"""Recovery-context consistency tests.

Covers the endowment-as-sole-replay-parameter rule, same-generation snapshot
conflicts over initial_balance, source interleaving across restarts, adopted
tip expiry, fingerprint/tip tamper pruning on recovery, save-failure restore
of the trust/sync state, and concurrent reads during mutations.

Run: python3 tests/recovery_context_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.models import Block, Transaction
from ledger.service import LedgerService
from ledger.store import (
    SNAPSHOT_PREFIX,
    LedgerStore,
    StateRecoveryError,
)

KEY_A = "a" * 64
KEY_B = "b" * 64
KEY_C = "c" * 64
FUTURE = 1_900_000_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(signed_tx(key, sender, to, amount))


def fork_doc(*blocks: Block) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


def read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class RecoveryContextCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def service(self, initial_balance: int = 1000) -> LedgerService:
        return LedgerService(
            LedgerStore(self.path, initial_balance=initial_balance),
            initial_balance=initial_balance,
        )

    def register(self, svc, source, key_hex=KEY_A, expires_at=FUTURE):
        return svc.register_trust_source(
            {"source": source, "public_key": key_hex, "expires_at": expires_at}
        )

    def block(self, amount=10, *, key=None, sender=None, recipient=None,
              height=1, prev=None, status="confirmed") -> Block:
        key = key or self.ka
        sender = sender or self.A
        recipient = recipient or self.B
        return Block.create(
            height,
            prev if prev is not None else self.svc.store.chain[0].block_hash,
            [tx_obj(key, sender, recipient, amount)],
            status,
        )

    def sync(self, svc, doc, *, source="node-1", request_id="req-1", expires_at=None):
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        return svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": doc,
            }
        )


class InitialBalanceRecoveryTests(RecoveryContextCase):
    def test_persisted_fork_replays_with_snapshot_endowment(self) -> None:
        # A candidate spending 900 is legal under the recorded endowment 1000
        # but would overspend under a 10-endowment restart.
        self.svc = self.service(1000)
        svc = self.svc
        genesis = svc.store.chain[0]
        b1 = self.block(900, key=self.ka, sender=self.A, recipient=self.B)
        self.assertEqual(
            svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), b1.to_dict()]}
            )[0],
            201,
        )
        tip = b1.block_hash

        # Restart with a deliberately different endowment: legality must be
        # decided solely by state.initial_balance, so the fork survives.
        reopened = LedgerStore(self.path, initial_balance=10)
        self.assertEqual(reopened.initial_balance, 1000)
        self.assertIn(tip, reopened.forks)
        svc2 = LedgerService(reopened, initial_balance=10)
        self.assertEqual(svc2.initial_balance, 1000)

    def test_fork_legal_under_small_endowment_is_not_retried_under_larger(self) -> None:
        # The inverse guard: a fork persisted under endowment 10 spending 9 is
        # legal; replay under a larger 1000 restart is also legal here, but the
        # recorded endowment is still 10 and balances after restart use it.
        self.svc = self.service(10)
        svc = self.svc
        status, body = svc.submit_transaction(
            signed_tx(self.ka, self.A, self.B, 9)
        )
        self.assertEqual(status, 202, body)
        mined = svc.mine_block()[1]
        svc.confirm_block(mined["height"])
        reopened = LedgerStore(self.path, initial_balance=1_000_000)
        self.assertEqual(reopened.initial_balance, 10)
        svc2 = LedgerService(reopened, initial_balance=1_000_000)
        _, acc = svc2.get_account(self.A)
        self.assertEqual(acc["balance"], 1)

    def test_new_submission_after_restart_uses_recorded_endowment(self) -> None:
        self.svc = self.service(1000)
        svc = self.svc
        genesis = svc.store.chain[0]
        b1 = self.block(900, key=self.ka, sender=self.A, recipient=self.B)
        self.assertEqual(
            svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), b1.to_dict()]}
            )[0],
            201,
        )
        # Restart claiming a 10 endowment: a further candidate spending 800 is
        # legal against the *recorded* 1000 endowment and must be accepted.
        svc2 = LedgerService(LedgerStore(self.path, initial_balance=10), 10)
        self.svc = svc2
        b2 = self.block(800, key=self.ka, sender=self.A, recipient=self.C)
        status, body = svc2.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), b2.to_dict()]}
        )
        self.assertEqual(status, 201, body)

    def test_balances_follow_recorded_endowment_on_restart(self) -> None:
        self.svc = self.service(1000)
        svc = self.svc
        status, _ = svc.submit_transaction(signed_tx(self.ka, self.A, self.B, 250))
        self.assertEqual(status, 202)
        mined = svc.mine_block()[1]
        svc.confirm_block(mined["height"])
        svc2 = LedgerService(LedgerStore(self.path, initial_balance=7), 7)
        _, acc_a = svc2.get_account(self.A)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_a["balance"], 750)
        self.assertEqual(acc_b["balance"], 1250)

    def test_same_generation_snapshots_conflict_on_initial_balance(self) -> None:
        self.svc = self.service(1000)
        svc = self.svc
        data = read_json(self.path)
        twin = json.loads(json.dumps(data))
        # Identical chain/state except the recorded endowment.
        twin["state"]["initial_balance"] = 2000
        generation = data["state"]["generation"]
        with open(
            os.path.join(self.tmp, f"{SNAPSHOT_PREFIX}twin.gen{generation}"),
            "w",
            encoding="utf-8",
        ) as fh:
            json.dump(twin, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.path, initial_balance=1000)
        self.assertIn("conflicting snapshots", ctx.exception.reason)

    def test_identical_endowment_twins_accepted(self) -> None:
        self.service(1000)
        data = read_json(self.path)
        with open(
            os.path.join(
                self.tmp, f"{SNAPSHOT_PREFIX}twin.gen{data['state']['generation']}"
            ),
            "w",
            encoding="utf-8",
        ) as fh:
            json.dump(data, fh)
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(reopened.initial_balance, 1000)


class SourceInterleavingRecoveryTests(RecoveryContextCase):
    def _two_source_state(self):
        self.svc = self.service(1000)
        svc = self.svc
        genesis = svc.store.chain[0]
        self.assertEqual(self.register(svc, "node-1", KEY_A)[0], 201)
        self.assertEqual(self.register(svc, "node-2", KEY_B)[0], 201)
        doc1 = fork_doc(genesis, self.block(10, recipient=self.B))
        doc2 = fork_doc(genesis, self.block(12, recipient=self.C))
        s1, b1 = self.sync(svc, doc1, source="node-1", request_id="r1")
        s2, b2 = self.sync(svc, doc2, source="node-2", request_id="r2")
        self.assertEqual(s1, 201, b1)
        self.assertEqual(s2, 201, b2)
        return svc, b1["tip_hash"], b2["tip_hash"]

    @staticmethod
    def _events(store):
        return [dict(e) for e in store.audit_events]

    def test_restart_keeps_both_active_sources(self) -> None:
        svc, tip1, tip2 = self._two_source_state()
        before = self._events(svc.store)
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertIn(("node-1", "r1"), reopened.syncs)
        self.assertIn(("node-2", "r2"), reopened.syncs)
        self.assertIn(tip1, reopened.forks)
        self.assertIn(tip2, reopened.forks)
        self.assertEqual([dict(e) for e in reopened.audit_events], before)

    def test_revoke_one_source_prunes_only_its_record(self) -> None:
        svc, tip1, tip2 = self._two_source_state()
        self.assertEqual(
            svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        before = self._events(svc.store)
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertNotIn(("node-1", "r1"), reopened.syncs)
        self.assertNotIn(tip1, reopened.forks)
        # The still-active node-2 keeps its record and candidate verbatim.
        self.assertIn(("node-2", "r2"), reopened.syncs)
        self.assertIn(tip2, reopened.forks)
        self.assertEqual([dict(e) for e in reopened.audit_events], before)
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(before) + 1)),
        )

    def test_registry_expiry_of_one_source_prunes_selectively(self) -> None:
        svc, tip1, tip2 = self._two_source_state()
        soon = int(time.time()) + 1
        self.assertEqual(
            svc.rotate_trust_source(
                "node-2",
                {"public_key": KEY_B, "expires_at": soon, "expected_version": 1},
            )[0],
            200,
        )
        before = self._events(svc.store)
        time.sleep(1.2)
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertIn(("node-1", "r1"), reopened.syncs)
        self.assertIn(tip1, reopened.forks)
        self.assertNotIn(("node-2", "r2"), reopened.syncs)
        self.assertNotIn(tip2, reopened.forks)
        self.assertEqual([dict(e) for e in reopened.audit_events], before)

    def test_rotation_keeps_record_and_fork(self) -> None:
        svc, tip1, _ = self._two_source_state()
        self.assertEqual(
            svc.rotate_trust_source(
                "node-1",
                {"public_key": KEY_C, "expires_at": FUTURE, "expected_version": 1},
            )[0],
            200,
        )
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertIn(("node-1", "r1"), reopened.syncs)
        self.assertIn(tip1, reopened.forks)

    def _tamper_and_reopen(self, mutate):
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        mutate(data)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return LedgerStore(self.path, initial_balance=1000)

    def test_tampered_fingerprint_prunes_record_and_fork(self) -> None:
        svc, _, _ = self._two_source_state()
        before = self._events(svc.store)
        reopened = self._tamper_and_reopen(
            lambda d: d["syncs"][0].__setitem__("fingerprint", "0" * 64)
        )
        # Exactly one pair survives; its record points at the surviving fork.
        self.assertEqual(len(reopened.syncs), 1)
        self.assertEqual(len(reopened.forks), 1)
        surviving_tip = next(iter(reopened.forks))
        self.assertEqual(
            reopened.syncs[next(iter(reopened.syncs))]["tip_hash"], surviving_tip
        )
        self.assertEqual([dict(e) for e in reopened.audit_events], before)

    def test_tampered_tip_hash_orphans_record(self) -> None:
        # A void tip_hash can no longer be correlated to a fork, so the record
        # itself is pruned while the canonical chain and audit history survive.
        svc, tip1, tip2 = self._two_source_state()
        before = self._events(svc.store)
        reopened = self._tamper_and_reopen(
            lambda d: d["syncs"][0].__setitem__("tip_hash", "f" * 64)
        )
        self.assertEqual(len(reopened.syncs), 1)
        self.assertNotIn("f" * 64, reopened.forks)
        self.assertEqual(svc.store.tip_hash(), reopened.tip_hash())
        self.assertEqual([dict(e) for e in reopened.audit_events], before)

    def test_tampered_past_expires_at_prunes_record(self) -> None:
        svc, _, _ = self._two_source_state()
        before = self._events(svc.store)
        reopened = self._tamper_and_reopen(
            lambda d: d["syncs"][0].__setitem__("expires_at", 1)
        )
        self.assertEqual(len(reopened.syncs), 1)
        self.assertEqual(len(reopened.forks), 1)
        self.assertEqual([dict(e) for e in reopened.audit_events], before)

    def test_tampered_candidate_blocks_prunes_fork_and_record(self) -> None:
        svc, tip1, tip2 = self._two_source_state()
        before = self._events(svc.store)
        canonical_tip = svc.store.tip_hash()

        def mutate(data):
            entry = next(f for f in data["forks"] if f[-1]["block_hash"] == tip1)
            entry[1]["block_hash"] = "e" * 64

        reopened = self._tamper_and_reopen(mutate)
        self.assertNotIn(("node-1", "r1"), reopened.syncs)
        self.assertNotIn(tip1, reopened.forks)
        self.assertIn(("node-2", "r2"), reopened.syncs)
        self.assertIn(tip2, reopened.forks)
        self.assertEqual(canonical_tip, reopened.tip_hash())
        self.assertEqual([dict(e) for e in reopened.audit_events], before)


class AdoptedTipExpiryTests(RecoveryContextCase):
    def _adopt_synced_tip(self):
        self.svc = self.service(1000)
        svc = self.svc
        genesis = svc.store.chain[0]
        # A strictly longer synced fork beats canonical genesis.
        f1 = Block.create(
            1, genesis.block_hash, [tx_obj(self.ka, self.A, self.C, 20)]
        )
        f2 = Block.create(
            2, f1.block_hash, [tx_obj(self.kc, self.C, self.A, 5)]
        )
        self.assertEqual(self.register(svc, "node-1", KEY_A)[0], 201)
        doc = fork_doc(genesis, f1, f2)
        status, body = self.sync(svc, doc, expires_at=int(time.time()) + 3600)
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        self.assertEqual(svc.adopt_fork(tip)[0], 200)
        self.assertEqual(svc.store.tip_hash(), tip)
        return svc, tip

    def test_adopted_tip_expiry_keeps_chain_and_all_three_events(self) -> None:
        svc, tip = self._adopt_synced_tip()
        svc.store.syncs[("node-1", "req-1")]["expires_at"] = int(time.time()) - 1
        # Trigger the lazy atomic sweep through a read endpoint.
        status, listing = svc.list_fork_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 0)
        # The canonical adopted chain is untouched...
        self.assertEqual(svc.store.tip_hash(), tip)
        self.assertNotIn(("node-1", "req-1"), svc.store.syncs)
        # ...and one of each lifecycle event remains, in write order.
        kinds = [e["kind"] for e in svc.store.audit_events]
        self.assertEqual(
            kinds,
            ["source_registered", "sync_received", "sync_adopted", "sync_expired"],
        )
        # The events are still individually queryable after the record is gone.
        _, page = svc.list_audit_events({"kind": "sync_expired"})
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["tip_hash"], tip)
        self.assertEqual(
            [e["event_id"] for e in svc.store.audit_events], [1, 2, 3, 4]
        )

    def test_adopted_tip_expiry_during_restart(self) -> None:
        svc, tip = self._adopt_synced_tip()
        before = [dict(e) for e in svc.store.audit_events]
        # Expiry happens while the process is "down": rewrite the deadline
        # directly without running the in-process sweep.
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["syncs"][0]["expires_at"] = int(time.time()) - 1
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(reopened.tip_hash(), tip)
        self.assertEqual(reopened.syncs, {})
        # No extra/duplicate events are synthesized during recovery; the
        # received+adopted history survives verbatim with dense event ids.
        self.assertEqual([dict(e) for e in reopened.audit_events], before)
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(before) + 1)),
        )
        svc2 = LedgerService(reopened, initial_balance=1000)
        self.assertEqual(svc2.list_fork_syncs({})[1]["total"], 0)


class SaveFailureRestoreTests(RecoveryContextCase):
    def _fail_save_once(self, store):
        original = store.save
        state = {"failed": False}

        def failing():
            if not state["failed"]:
                state["failed"] = True
                raise OSError("simulated persistence failure")
            return original()

        store.save = failing
        self.addCleanup(lambda: setattr(store, "save", original))

    def test_register_failure_restores_registry_and_events(self) -> None:
        svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        before = list(svc.store.audit_events)
        before_gen = svc.store.generation
        self._fail_save_once(svc.store)
        with self.assertRaises(OSError):
            svc.register_trust_source(
                {"source": "node-1", "public_key": KEY_A, "expires_at": FUTURE}
            )
        self.assertNotIn("node-1", svc.store.trust_sources)
        self.assertEqual(svc.store.audit_events, before)
        self.assertEqual(svc.store.generation, before_gen)
        # Retry persists exactly once.
        self.assertEqual(
            svc.register_trust_source(
                {"source": "node-1", "public_key": KEY_A, "expires_at": FUTURE}
            )[0],
            201,
        )
        kinds = [e["kind"] for e in svc.store.audit_events]
        self.assertEqual(kinds, ["source_registered"])

    def test_rotate_failure_restores_registry_and_events(self) -> None:
        svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.assertEqual(
            svc.register_trust_source(
                {"source": "node-1", "public_key": KEY_A, "expires_at": FUTURE}
            )[0],
            201,
        )
        before = [dict(e) for e in svc.store.audit_events]
        before_gen = svc.store.generation
        self._fail_save_once(svc.store)
        with self.assertRaises(OSError):
            svc.rotate_trust_source(
                "node-1",
                {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 1},
            )
        rec = svc.store.trust_sources["node-1"]
        self.assertEqual(rec["public_key"], KEY_A)
        self.assertEqual(rec["version"], 1)
        self.assertEqual(rec["status"], "active")
        self.assertEqual([dict(e) for e in svc.store.audit_events], before)
        self.assertEqual(svc.store.generation, before_gen)
        # Retry rotates exactly once.
        status, body = svc.rotate_trust_source(
            "node-1",
            {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 1},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["version"], 2)
        self.assertEqual(
            [e["kind"] for e in svc.store.audit_events].count("source_rotated"), 1
        )

    def test_expiry_sweep_failure_is_fully_restorable(self) -> None:
        self.svc = self.service(1000)
        svc = self.svc
        genesis = svc.store.chain[0]
        self.register(svc, "node-1", KEY_A)
        doc = fork_doc(genesis, self.block(3))
        self.assertEqual(
            self.sync(svc, doc, expires_at=int(time.time()) + 1)[0], 201
        )
        time.sleep(1.1)
        before_kinds = [e["kind"] for e in svc.store.audit_events]
        self.assertNotIn("sync_expired", before_kinds)
        self.assertEqual(len(svc.store.syncs), 1)

        # First sweep attempt fails mid-persist: record, fork and the would-be
        # events must all be restored; generation stays put.
        gen_before = svc.store.generation
        self._fail_save_once(svc.store)
        with self.assertRaises(OSError):
            svc.list_audit_events({})
        self.assertEqual(len(svc.store.syncs), 1)
        self.assertEqual(len(svc.store.forks), 1)
        self.assertEqual(svc.store.generation, gen_before)
        self.assertEqual(
            [e["kind"] for e in svc.store.audit_events], before_kinds
        )

        # A successful retry sweeps exactly once: one expiry event, no dupes.
        _, page = svc.list_audit_events({})
        kinds = [e["kind"] for e in svc.store.audit_events]
        self.assertEqual(kinds.count("sync_expired"), 1)
        self.assertEqual(svc.store.syncs, {})
        self.assertEqual(svc.store.forks, {})
        self.assertEqual(
            [e["event_id"] for e in svc.store.audit_events],
            list(range(1, len(kinds) + 1)),
        )


class ConcurrentReadConsistencyTests(RecoveryContextCase):
    def test_concurrent_reads_during_trust_and_sync_mutations(self) -> None:
        self.svc = self.service(1000)
        svc = self.svc
        genesis = svc.store.chain[0]
        self.register(svc, "node-1", KEY_A)
        errors: list[Exception] = []
        stop = threading.Event()

        def readers() -> None:
            try:
                while not stop.is_set():
                    for fn in (
                        lambda: svc.get_chain(),
                        lambda: svc.get_trust_document(),
                        lambda: svc.list_audit_events({}),
                        lambda: svc.list_fork_syncs({}),
                    ):
                        status, body = fn()
                        assert status == 200, (status, body)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=readers) for _ in range(4)]
        for t in threads:
            t.start()
        try:
            for i in range(6):
                doc = fork_doc(genesis, self.block(100 + i, recipient=self.C))
                status, body = svc.submit_fork_sync(
                    {
                        "source": "node-1",
                        "request_id": f"req-{i}",
                        "expires_at": int(time.time()) + 3600,
                        "candidate": doc,
                    }
                )
                assert status == 201, (status, body)
            status, _ = svc.rotate_trust_source(
                "node-1",
                {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 1},
            )
            assert status == 200
            status, _ = svc.revoke_trust_source("node-1", {"expected_version": 2})
            assert status == 200
        finally:
            stop.set()
            for t in threads:
                t.join(timeout=20)
        self.assertEqual(errors, [])

        # Final state is internally consistent: revoked source prunes every
        # record on restart, audit history remains dense and verbatim.
        before = [dict(e) for e in svc.store.audit_events]
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(reopened.syncs, {})
        self.assertEqual([dict(e) for e in reopened.audit_events], before)
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(before) + 1)),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

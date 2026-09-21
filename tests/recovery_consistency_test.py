"""Tests for snapshot-recovery context consistency.

These lock in the rules from the recovery-consistency task:

* ``state.initial_balance`` is the sole balance-replay parameter on snapshot
  recovery: the canonical chain is verified first, then persisted forks are
  re-validated against *that* recorded endowment. Restarting with a different
  ``--initial-balance`` neither changes a fork's legality nor the reported
  balances.
* Two same-generation snapshots with different ``initial_balance`` (or
  different authoritative sections) conflict and raise StateRecoveryError —
  endowment differences alone are enough.
* On restart every surviving sync record's candidate, tip summary, expiry,
  request fingerprint and source authorization are re-verified: unexpired,
  still-active records survive; expired, revoked, unauthorized, candidate-less
  or fingerprint-mismatched unadopted records are removed together with their
  fork, while an adopted tip never alters the canonical chain and only the
  sync_received/sync_adopted/sync_expired audit history is retained.
* ``event_id`` starts at 1 and is dense; audit events are preserved verbatim
  across such pruning.

Run: python3 tests/recovery_consistency_test.py
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
from ledger.store import SNAPSHOT_PREFIX, LedgerStore, StateRecoveryError

KEY_A = "a" * 64
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


def read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def fork_doc(genesis: Block, *blocks: Block) -> dict:
    chain = [genesis, *blocks]
    tip = chain[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(chain),
        "status": tip.status,
        "blocks": [b.to_dict() for b in chain],
    }


class RecordedEndowmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )

    def _confirmed_tx(self, amount: int = 10) -> None:
        self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, amount))
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])

    def test_restart_with_different_balance_keeps_recorded_endowment(self) -> None:
        self._confirmed_tx(10)
        # Restart with a wildly different launch endowment: the snapshot value
        # must govern reported balances, not the constructor argument.
        svc2 = LedgerService(
            LedgerStore(self.path, initial_balance=9_999_999),
            initial_balance=9_999_999,
        )
        self.assertEqual(svc2.store.initial_balance, 1000)
        self.assertEqual(svc2.initial_balance, 1000)
        _, acc_a = svc2.get_account(self.A)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_a["balance"], 990)
        self.assertEqual(acc_b["balance"], 1010)

    def test_fork_legality_independent_of_startup_balance(self) -> None:
        # A candidate spending 80 of a recorded endowment of 100 is valid.
        self._confirmed_tx(1)
        genesis = self.svc.store.chain[0]
        block = Block.create(1, genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 80)])
        # Build it in a separate store keyed at endowment 100 so it validates.
        fork_dir = tempfile.mkdtemp()
        fork_path = os.path.join(fork_dir, "f.json")
        fsvc = LedgerService(
            LedgerStore(fork_path, initial_balance=100), initial_balance=100
        )
        fgen = fsvc.store.chain[0]
        fblock = Block.create(1, fgen.block_hash, [tx_obj(self.ka, self.A, self.B, 80)])
        status, body = fsvc.submit_fork_candidate(
            {"blocks": [fgen.to_dict(), fblock.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]

        # Transplant the persisted snapshot (which records initial_balance 100)
        # to the store under test, then reopen with a far smaller endowment:
        # the fork must remain legal because the snapshot says 100.
        data = read_json(fork_path)
        write_json(self.path, data)
        reopened = LedgerStore(self.path, initial_balance=50)
        self.assertEqual(reopened.initial_balance, 100)
        self.assertIn(tip, reopened.forks)

    def test_fork_dropped_when_recorded_endowment_makes_it_overspend(self) -> None:
        genesis = self.svc.store.chain[0]
        block = Block.create(1, genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 80)])
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), block.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        # Lower the *recorded* endowment below the spent amount. The canonical
        # chain is still valid, but replaying the fork now overspends and the
        # candidate must be pruned rather than trusted.
        data = read_json(self.path)
        data["state"]["initial_balance"] = 50
        write_json(self.path, data)
        reopened = LedgerStore(self.path, initial_balance=50)
        self.assertNotIn(tip, reopened.forks)
        self.assertEqual(reopened.tip_hash(), genesis.block_hash)

    def test_same_generation_conflict_on_initial_balance_only(self) -> None:
        self._confirmed_tx(10)
        base = read_json(self.path)
        d1 = json.loads(json.dumps(base))
        d2 = json.loads(json.dumps(base))
        d1["state"]["generation"] = 77
        d2["state"]["generation"] = 77
        d1["state"]["initial_balance"] = 1000
        d2["state"]["initial_balance"] = 2000
        conflict_dir = tempfile.mkdtemp()
        main_path = os.path.join(conflict_dir, "state.json")
        write_json(main_path, d1)
        write_json(
            os.path.join(conflict_dir, f"{SNAPSHOT_PREFIX}twin.gen77"), d2
        )
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(main_path, initial_balance=1000)
        self.assertEqual(ctx.exception.path, conflict_dir)
        self.assertIn("conflicting snapshots", ctx.exception.reason)


class SyncRecoveryReverificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.assertRegister(
            self.svc.register_trust_source(
                {"source": "node-1", "public_key": KEY_A, "expires_at": FUTURE}
            )
        )

    @staticmethod
    def assertRegister(result) -> None:
        assert result[0] == 201, result

    def _block(self, amount: int = 5, *, recipient=None, height=1, prev=None,
               sender_key=None, sender=None, status="confirmed") -> Block:
        return Block.create(
            height,
            prev if prev is not None else self.genesis.block_hash,
            [tx_obj(sender_key or self.ka, sender or self.A, recipient or self.B, amount)],
            status,
        )

    def _sync(self, doc: dict, *, expires_at=None) -> tuple[int, dict]:
        return self.svc.submit_fork_sync(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600 if expires_at is None else expires_at,
                "candidate": doc,
            }
        )

    def test_unexpired_active_record_survives_restart(self) -> None:
        doc = fork_doc(self.genesis, self._block())
        status, body = self._sync(doc)
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertIn(("node-1", "req-1"), reopened.syncs)
        self.assertIn(tip, reopened.forks)

    def test_fingerprint_tamper_drops_record_and_fork_keeps_audit(self) -> None:
        doc = fork_doc(self.genesis, self._block())
        status, body = self._sync(doc)
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        before = [dict(e) for e in self.store.audit_events]

        data = read_json(self.path)
        self.assertEqual(len(data["syncs"]), 1)
        data["syncs"][0]["fingerprint"] = "0" * 64
        write_json(self.path, data)

        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        # Audit history is retained verbatim with a dense 1..N event_id.
        self.assertEqual([dict(e) for e in reopened.audit_events], before)
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(before) + 1)),
        )

    def test_record_whose_tip_resolves_nowhere_is_pruned(self) -> None:
        # If the persisted tip_hash no longer names either a stored fork or a
        # canonical block, the record references a candidate that no longer
        # exists and must be dropped (the record's own candidate is gone).
        doc = fork_doc(self.genesis, self._block())
        status, body = self._sync(doc)
        self.assertEqual(status, 201, body)
        data = read_json(self.path)
        data["syncs"][0]["tip_hash"] = "f" * 64
        write_json(self.path, data)
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn("f" * 64, reopened.forks)

    def test_adopted_tip_expiry_keeps_canonical_and_history_only(self) -> None:
        # Canonical confirmed block 1 (A->B 10).
        canon = self._block(amount=10)
        self.store.chain.append(canon)
        self.store.rebuild_derived()
        self.store.save()
        # A longer synced fork: A->C 20 then C->A 5.
        f1 = self._block(amount=20, recipient=self.C, height=1)
        f2 = self._block(
            amount=5, sender_key=self.kc, sender=self.C, recipient=self.A,
            height=2, prev=f1.block_hash,
        )
        doc = fork_doc(self.genesis, f1, f2)
        # Re-anchor the delivered genesis to the current canonical one.
        doc["blocks"][0] = self.store.chain[0].to_dict()
        status, body = self._sync(doc, expires_at=int(time.time()) + 1)
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)
        self.assertEqual(self.store.tip_hash(), tip)
        # Revoke the source and let the sync record expire while "down".
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        before = [dict(e) for e in self.store.audit_events]
        time.sleep(1.1)

        reopened = LedgerStore(self.path, initial_balance=1000)
        # The adopted canonical tip is untouched.
        self.assertEqual(reopened.tip_hash(), tip)
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        # The pre-downtime history survives verbatim; the record lapsed both
        # by deadline and by de-authorization while down, so exactly one
        # sync_expired event is back-filled, keeping event_id dense.
        events = [dict(e) for e in reopened.audit_events]
        self.assertEqual(events[: len(before)], before)
        tail = events[len(before) :]
        self.assertEqual(len(tail), 1)
        self.assertEqual(tail[0]["kind"], "sync_expired")
        self.assertEqual(tail[0]["event_id"], len(before) + 1)
        self.assertEqual(tail[0]["tip_hash"], tip)
        self.assertEqual(
            tail[0]["expires_at"],
            next(e["expires_at"] for e in before if e["kind"] == "sync_received"),
        )
        kinds = [e["kind"] for e in reopened.audit_events]
        self.assertEqual(
            kinds,
            [
                "source_registered",
                "sync_received",
                "sync_adopted",
                "source_revoked",
                "sync_expired",
            ],
        )
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(events) + 1)),
        )
        svc2 = LedgerService(reopened, initial_balance=1000)
        self.assertEqual(svc2.list_fork_syncs({})[1]["total"], 0)
        for kind in ("sync_received", "sync_adopted", "sync_expired"):
            _, page = svc2.list_audit_events({"kind": kind})
            self.assertEqual(page["total"], 1)
            self.assertEqual(page["items"][0]["tip_hash"], tip)

    def test_multiple_sources_backfill_one_event_each_on_restart(self) -> None:
        # Three sources deliver three distinct candidates while trusted. While
        # the process is down: s1's request deadline elapses, s2 is revoked,
        # s3 stays valid. On restart exactly one sync_expired per lapsed record
        # is back-filled (in (source, request_id) order), s3 survives, and a
        # second restart neither duplicates nor advances the generation.
        self.assertRegister(
            self.svc.register_trust_source(
                {"source": "s2", "public_key": "b" * 64, "expires_at": FUTURE}
            )
        )
        self.assertRegister(
            self.svc.register_trust_source(
                {"source": "s3", "public_key": "c" * 64, "expires_at": FUTURE}
            )
        )
        far_future = int(time.time()) + 10_000

        def deliver(source, request_id, amount, expires_at):
            status, body = self.svc.submit_fork_sync(
                {
                    "source": source,
                    "request_id": request_id,
                    "expires_at": expires_at,
                    "candidate": fork_doc(self.genesis, self._block(amount=amount)),
                }
            )
            assert status == 201, body
            return body["tip_hash"]

        t1 = deliver("node-1", "r1", 11, int(time.time()) + 1)
        t2 = deliver("s2", "r2", 12, far_future)
        t3 = deliver("s3", "r3", 13, far_future)
        self.assertEqual(
            self.svc.revoke_trust_source("s2", {"expected_version": 1})[0], 200
        )
        gen_before = self.store.generation
        time.sleep(1.1)  # node-1 deadline elapses while "down"

        reopened = LedgerStore(self.path, initial_balance=1000)
        # Only the still-valid s3 record and its candidate survive.
        self.assertNotIn(("node-1", "r1"), reopened.syncs)
        self.assertNotIn(("s2", "r2"), reopened.syncs)
        self.assertIn(("s3", "r3"), reopened.syncs)
        self.assertNotIn(t1, reopened.forks)
        self.assertNotIn(t2, reopened.forks)
        self.assertIn(t3, reopened.forks)
        # One back-filled expiry per lapsed record, sorted by (source, rid).
        tail = [e for e in reopened.audit_events if e["kind"] == "sync_expired"]
        self.assertEqual(
            [(e["source"], e["request_id"], e["tip_hash"]) for e in tail],
            [("node-1", "r1", t1), ("s2", "r2", t2)],
        )
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(reopened.audit_events) + 1)),
        )
        self.assertEqual(reopened.generation, gen_before + 1)
        # The back-fill is durable.
        disk = read_json(self.path)
        self.assertEqual(
            sum(1 for e in disk["audit_events"] if e["kind"] == "sync_expired"), 2
        )
        self.assertEqual(disk["state"]["generation"], reopened.generation)
        # A second restart neither duplicates nor re-saves.
        gen_after = reopened.generation
        reopened2 = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(
            sum(1 for e in reopened2.audit_events if e["kind"] == "sync_expired"), 2
        )
        self.assertEqual(reopened2.generation, gen_after)


class CorruptAuthoritativeSectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.svc.register_trust_source(
            {"source": "node-1", "public_key": KEY_A, "expires_at": FUTURE}
        )

    def _reopen_mutated(self, mutate) -> StateRecoveryError:
        data = read_json(self.path)
        mutate(data)
        out_dir = tempfile.mkdtemp()
        path = os.path.join(out_dir, "state.json")
        write_json(path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(path, initial_balance=1000)
        return ctx.exception

    def test_corrupt_trust_source_fails_recovery(self) -> None:
        err = self._reopen_mutated(
            lambda d: d["trust_sources"][0].__setitem__("public_key", "zz")
        )
        self.assertTrue(err.reason)

    def test_corrupt_allowlist_fails_recovery(self) -> None:
        data = read_json(self.path)
        data["allowlist"] = {"node-x": "not-an-int"}
        out_dir = tempfile.mkdtemp()
        path = os.path.join(out_dir, "state.json")
        write_json(path, data)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(path, initial_balance=1000)

    def test_corrupt_audit_event_id_fails_recovery(self) -> None:
        def mutate(data) -> None:
            # Two events but renumber to start at 2: not 1..N -> corruption.
            data["audit_events"][0]["event_id"] = 2

        err = self._reopen_mutated(mutate)
        self.assertIn("event_id", err.reason)

    def test_corrupt_audit_event_id_gap_fails_recovery(self) -> None:
        # Add a second event with a gapped id.
        data = read_json(self.path)
        first = dict(data["audit_events"][0])
        second = dict(first)
        second["event_id"] = 3  # gap: expected 2
        data["audit_events"].append(second)
        out_dir = tempfile.mkdtemp()
        path = os.path.join(out_dir, "state.json")
        write_json(path, data)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(path, initial_balance=1000)

    def test_corrupt_canonical_chain_fails_recovery(self) -> None:
        err = self._reopen_mutated(
            lambda d: d["chain"][0].__setitem__("block_hash", "9" * 64)
        )
        self.assertTrue(err.reason)


class ConcurrentRecoveryReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, 10))
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        self.expected_generation = self.svc.store.generation

    def test_concurrent_reopens_share_consistent_recovered_state(self) -> None:
        reopened: list[LedgerStore] = []
        gate = threading.Barrier(6)

        def open_store() -> None:
            gate.wait()
            reopened.append(LedgerStore(self.path, initial_balance=1000))

        threads = [threading.Thread(target=open_store) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(reopened), 6)
        for store in reopened:
            self.assertEqual(store.generation, self.expected_generation)
            self.assertEqual(store.initial_balance, 1000)
            self.assertEqual(store.tip().height, 1)
        # All readers observed the same canonical tip and no temp residue.
        tips = {store.tip_hash() for store in reopened}
        self.assertEqual(len(tips), 1)
        self.assertEqual(
            [n for n in os.listdir(self.tmp) if n.startswith(SNAPSHOT_PREFIX)], []
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for multi-block durability, snapshot recovery and crash consistency.

Covers:

* generation advancing on every successful atomic write and surviving restart;
* multi-block consistency after restart (next height, balances,
  confirmed_transactions, tx_index, Merkle proofs across several blocks);
* startup scanning of the main file plus sibling ``.ledger-*`` snapshots:
  promotion of a newer durable snapshot, fall-back past a corrupt main file,
  ignoring/cleaning a half-written temp, refusal to invent a new chain, and
  same-generation content conflicts;
* rejection of tampered height / prev_hash / block_hash / Merkle root /
  tx signature and of duplicate pending entries;
* serialized concurrent submit / mine / confirm / rollback: no overspend,
  no duplicate mempool entries, no lost transactions, every result durable.

Run: python3 tests/recovery_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.service import LedgerService
from ledger.store import SNAPSHOT_PREFIX, LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def snapshot_files(directory: str) -> list[str]:
    return sorted(n for n in os.listdir(directory) if n.startswith(SNAPSHOT_PREFIX))


def read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class GenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)

    def test_generation_advances_per_successful_write_and_persists(self) -> None:
        store = self.svc.store
        genesis_generation = store.generation
        self.assertGreaterEqual(genesis_generation, 1)
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        self.assertEqual(store.generation, genesis_generation + 1)
        block = self.svc.mine_block()[1]
        self.assertEqual(store.generation, genesis_generation + 2)
        self.svc.confirm_block(block["height"])
        self.assertEqual(store.generation, genesis_generation + 3)
        # Failed validation must not consume a generation: submitting an
        # invalid transaction persists nothing.
        before = store.generation
        self.assertEqual(
            self.svc.submit_transaction(make_tx(self.kb, self.A, self.B, 10))[0],
            400,
        )
        self.assertEqual(store.generation, before)
        # Reopened store reports the persisted generation.
        reopened = LedgerStore(self.path)
        self.assertEqual(reopened.generation, genesis_generation + 3)
        self.assertEqual(
            read_json(self.path)["state"]["generation"],
            genesis_generation + 3,
        )
        # No snapshot temp files are left next to the main file.
        self.assertEqual(snapshot_files(self.tmp), [])


class MultiBlockRestartConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.committed: list[str] = []  # tx_ids confirmed across blocks

    def _send_mine_confirm(self, amount: int) -> tuple[str, dict]:
        _, body = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, amount))
        tx_id = body["tx_id"]
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        self.committed.append(tx_id)
        return tx_id, block

    def test_multi_block_consistency_after_restart(self) -> None:
        blocks = [self._send_mine_confirm(10 + i)[1] for i in range(3)]
        # A fourth transaction is mined but left pending across the restart.
        _, pending_body = self.svc.submit_transaction(
            make_tx(self.ka, self.A, self.B, 7)
        )
        pending_tx = pending_body["tx_id"]
        pending_block = self.svc.mine_block()[1]

        svc2 = LedgerService(LedgerStore(self.path), initial_balance=1000)
        store2 = svc2.store

        # Next height and chain shape: genesis + 3 confirmed + 1 pending.
        self.assertEqual(store2.next_height(), 5)
        self.assertEqual(len(store2.chain), 5)
        statuses = [svc2.get_block_status(h)[1]["status"] for h in range(5)]
        self.assertEqual(
            statuses, ["confirmed", "confirmed", "confirmed", "confirmed", "pending"]
        )
        # Pending only ever sits at the tip.
        self.assertTrue(all(
            b.status != "pending" for b in store2.chain[:-1]
        ))

        # Block queries at every height preserve hashes and linkage.
        prev = svc2.get_block(0)[1]["block_hash"]
        for h, original in enumerate(blocks, start=1):
            _, summary = svc2.get_block(h)
            self.assertEqual(summary["block_hash"], original["block_hash"])
            self.assertEqual(summary["merkle_root"], original["merkle_root"])
            self.assertEqual(summary["prev_hash"], prev)
            prev = summary["block_hash"]
        _, genesis_summary = svc2.get_block(0)
        self.assertEqual(genesis_summary["prev_hash"], "0" * 64)
        _, pending_summary = svc2.get_block(4)
        self.assertEqual(pending_summary["prev_hash"], prev)
        self.assertEqual(pending_summary["status"], "pending")

        # tx_index covers exactly the confirmed transactions.
        self.assertEqual(set(store2.tx_index), set(self.committed))
        self.assertEqual(store2.tx_index[self.committed[0]], 1)
        self.assertEqual(store2.tx_index[self.committed[-1]], 3)
        self.assertNotIn(pending_tx, store2.tx_index)

        # Balances: 30+10? amounts were 10,11,12 -> 33 confirmed out,
        # 7 pending spend deducted, pending income ignored.
        _, acc_a = svc2.get_account(self.A)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_a["balance"], 1000 - (10 + 11 + 12) - 7)
        self.assertEqual(acc_b["balance"], 1000 + (10 + 11 + 12))
        self.assertEqual(acc_a["confirmed_transactions"], self.committed)
        self.assertEqual(acc_b["confirmed_transactions"], self.committed)

        # Merkle proofs verify across multiple confirmed blocks and stay
        # refused on the pending one.
        for tx_id in self.committed:
            height = store2.tx_index[tx_id]
            status, proof = svc2.get_proof(height, tx_id)
            self.assertEqual(status, 200)
            block = store2.block_at(height)
            self.assertTrue(
                crypto.verify_merkle_proof(
                    tx_id,
                    proof["siblings"],
                    proof["merkle_root"],
                    proof["block_hash"],
                    block.block_hash,
                )
            )
            # Proof is bound to the block hash: a foreign expected hash fails.
            self.assertFalse(
                crypto.verify_merkle_proof(
                    tx_id,
                    proof["siblings"],
                    proof["merkle_root"],
                    proof["block_hash"],
                    "0" * 64,
                )
            )
        self.assertEqual(svc2.get_proof(4, pending_tx)[0], 409)
        self.assertEqual(svc2.get_proof(99, pending_tx)[0], 404)

        # Confirm the surviving pending block after restart; a third reopen
        # then sees everything consistent and confirmed.
        self.assertEqual(svc2.confirm_block(4)[0], 200)
        svc3 = LedgerService(LedgerStore(self.path), initial_balance=1000)
        _, acc_a = svc3.get_account(self.A)
        _, acc_b = svc3.get_account(self.B)
        self.assertEqual(acc_a["balance"], 1000 - (10 + 11 + 12 + 7))
        self.assertEqual(acc_b["balance"], 1000 + (10 + 11 + 12 + 7))
        self.assertEqual(len(svc3.store.tx_index), 4)
        self.assertEqual(svc3.store.pending, {})


class SnapshotRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def _build_state(self, amount: int = 10) -> LedgerService:
        svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        _, body = svc.submit_transaction(make_tx(self.ka, self.A, self.B, amount))
        block = svc.mine_block()[1]
        svc.confirm_block(block["height"])
        return svc

    def test_newer_durable_snapshot_is_promoted(self) -> None:
        svc = self._build_state(10)
        tip_generation = svc.store.generation
        # Simulate a crash after the temp snapshot was fsynced but before (or
        # indistinguishable from) the rename: a newer valid snapshot sits next
        # to an older main file.
        newer = read_json(self.path)
        newer["state"]["generation"] = tip_generation + 1
        residual = os.path.join(
            self.tmp, f"{SNAPSHOT_PREFIX}crash.gen{tip_generation + 1}"
        )
        with open(residual, "w", encoding="utf-8") as fh:
            json.dump(newer, fh)

        recovered = LedgerStore(self.path)
        self.assertEqual(recovered.generation, tip_generation + 1)
        self.assertEqual(recovered.tip().height, 1)
        # The residual was promoted then cleaned; no candidates remain.
        self.assertEqual(snapshot_files(self.tmp), [])
        self.assertFalse(os.path.exists(residual))

    def test_garbage_temp_is_ignored_and_cleaned(self) -> None:
        svc = self._build_state(10)
        good_generation = svc.store.generation
        with open(os.path.join(self.tmp, f"{SNAPSHOT_PREFIX}half.gen99"), "w") as fh:
            fh.write('{"chain": [')  # truncated mid-write
        recovered = LedgerStore(self.path)
        self.assertEqual(recovered.generation, good_generation)
        self.assertEqual(snapshot_files(self.tmp), [])

    def test_corrupt_main_falls_back_to_older_valid_snapshot(self) -> None:
        # Advance the main file well past the genesis state.
        self._build_state(10)
        # Only now place an older valid genesis snapshot beside it (doing it
        # earlier would let the main-file-absent startup promote the temp).
        genesis_dir = tempfile.mkdtemp()
        genesis_path = os.path.join(genesis_dir, "g.json")
        LedgerStore(genesis_path)
        older = read_json(genesis_path)
        older["state"]["generation"] = 1
        with open(os.path.join(self.tmp, f"{SNAPSHOT_PREFIX}old.gen1"), "w") as fh:
            json.dump(older, fh)
        # Then the main file gets corrupted.
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")

        recovered = LedgerStore(self.path)
        self.assertEqual(recovered.generation, 1)
        self.assertEqual(recovered.tip().height, 0)
        self.assertEqual(recovered.tip().status, "confirmed")
        self.assertEqual(snapshot_files(self.tmp), [])

    def test_all_candidates_invalid_raises_and_does_not_create_chain(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{broken")
        with open(os.path.join(self.tmp, f"{SNAPSHOT_PREFIX}x"), "w") as fh:
            fh.write("also broken")
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.path)
        err = ctx.exception
        # Public, catchable, and carries the directory plus both paths/reasons.
        self.assertIsInstance(err, ValueError)
        self.assertEqual(err.path, self.tmp)
        self.assertTrue(err.reason)
        self.assertIn(os.path.basename(self.path), str(err))
        self.assertIn(f"{SNAPSHOT_PREFIX}x", str(err))
        # The corrupt main file must not be replaced by a silent new genesis.
        self.assertEqual(open(self.path).read(), "{broken")

    def test_same_generation_conflict_raises(self) -> None:
        svc1 = self._build_state(10)
        svc2 = self._build_state  # noqa: F841 (clarity only)
        first = read_json(self.path)
        # Build a genuinely different chain in a scratch directory.
        other_dir = tempfile.mkdtemp()
        other_path = os.path.join(other_dir, "o.json")
        other_svc = LedgerService(LedgerStore(other_path), initial_balance=1000)
        other_svc.submit_transaction(make_tx(self.ka, self.A, self.B, 123))
        blk = other_svc.mine_block()[1]
        other_svc.confirm_block(blk["height"])
        second = read_json(other_path)
        self.assertNotEqual(first["chain"], second["chain"])

        gen = 99
        first["state"]["generation"] = gen
        second["state"]["generation"] = gen
        conflict_dir = tempfile.mkdtemp()
        main_path = os.path.join(conflict_dir, "state.json")
        with open(main_path, "w", encoding="utf-8") as fh:
            json.dump(first, fh)
        with open(
            os.path.join(conflict_dir, f"{SNAPSHOT_PREFIX}twin.gen{gen}"), "w"
        ) as fh:
            json.dump(second, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(main_path)
        self.assertIn("conflicting snapshots", ctx.exception.reason)
        self.assertEqual(ctx.exception.path, conflict_dir)

    def test_identical_same_generation_twins_are_accepted(self) -> None:
        self._build_state(10)
        data = read_json(self.path)
        with open(
            os.path.join(
                self.tmp,
                f"{SNAPSHOT_PREFIX}twin.gen{data['state']['generation']}",
            ),
            "w",
        ) as fh:
            json.dump(data, fh)  # byte-identical content, same generation
        recovered = LedgerStore(self.path)
        self.assertEqual(recovered.generation, data["state"]["generation"])
        self.assertEqual(snapshot_files(self.tmp), [])

    def test_empty_directory_creates_unique_genesis_once(self) -> None:
        store = LedgerStore(self.path)
        self.assertEqual(store.tip().height, 0)
        self.assertEqual(store.tip().status, "confirmed")
        # A second startup loads the genesis rather than creating another.
        again = LedgerStore(self.path)
        self.assertEqual(len(again.chain), 1)
        self.assertEqual(
            again.tip().block_hash, store.tip().block_hash
        )


class TamperRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        blk = svc.mine_block()[1]
        svc.confirm_block(blk["height"])

    def _reload_with(self, mutate, label: str) -> None:
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        mutate(data)
        # Place the tampered content as the *only* candidate in a fresh
        # directory, so the scan cannot quietly prefer a valid sibling.
        out_dir = tempfile.mkdtemp()
        path = os.path.join(out_dir, "state.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(path)
        # With a single invalid candidate the failure is reported against the
        # directory; the offending file path is carried in the reason.
        self.assertTrue(ctx.exception.reason)
        self.assertIn(path, str(ctx.exception))

    def test_tampered_block_hash_rejected(self) -> None:
        self._reload_with(
            lambda d: d["chain"][1].__setitem__("block_hash", "a" * 64),
            "blockhash",
        )

    def test_tampered_merkle_root_rejected(self) -> None:
        self._reload_with(
            lambda d: d["chain"][1].__setitem__("merkle_root", "b" * 64),
            "merkle",
        )

    def test_tampered_signature_rejected(self) -> None:
        self._reload_with(
            lambda d: d["chain"][1]["transactions"][0].__setitem__(
                "signature", "00" * 64
            ),
            "signature",
        )

    def test_tampered_tx_id_rejected(self) -> None:
        def mutate(data) -> None:
            data["chain"][1]["transactions"][0]["tx_id"] = "c" * 64

        self._reload_with(mutate, "txid")

    def test_tampered_prev_hash_rejected(self) -> None:
        self._reload_with(
            lambda d: d["chain"][1].__setitem__("prev_hash", "d" * 64),
            "prevhash",
        )

    def test_duplicate_pending_in_mempool_rejected(self) -> None:
        def mutate(data) -> None:
            data["pending"] = [
                dict(data["chain"][1]["transactions"][0]),
                dict(data["chain"][1]["transactions"][0]),
            ]

        self._reload_with(mutate, "dup")

    def test_pending_overlapping_confirmed_tx_rejected(self) -> None:
        def mutate(data) -> None:
            data["pending"] = [dict(data["chain"][1]["transactions"][0])]

        self._reload_with(mutate, "overlap")

    def test_pending_block_below_tip_rejected(self) -> None:
        # Build two confirmed blocks, then retroactively mark block 1 pending.
        svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        svc.submit_transaction(make_tx(self.kb, self.B, self.A, 5))
        blk2 = svc.mine_block()[1]
        svc.confirm_block(blk2["height"])
        self.assertEqual(svc.store.tip().height, 2)

        def mutate(data) -> None:
            data["chain"][1]["status"] = "pending"

        self._reload_with(mutate, "pendingbelowtip")


class RollbackPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)

    def test_rollback_restores_deduped_and_restart_is_consistent(self) -> None:
        tx1 = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))[1]["tx_id"]
        tx2 = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 20))[1]["tx_id"]
        block = self.svc.mine_block()[1]
        self.assertEqual(self.svc.store.pending, {})
        self.assertEqual(
            self.svc.rollback_block(block["height"]),
            (200, {"height": block["height"], "status": "rolled_back"}),
        )
        self.assertEqual(set(self.svc.store.pending), {tx1, tx2})
        # Mining can resume only after the pending tip is gone, and the
        # re-mined block is byte-for-byte identical.
        again = self.svc.mine_block()[1]
        self.assertEqual(again["block_hash"], block["block_hash"])
        self.assertEqual(again["merkle_root"], block["merkle_root"])
        self.svc.confirm_block(again["height"])

        # Restart: transactions exist exactly once, balances and index agree.
        svc2 = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.assertEqual(svc2.store.pending, {})
        self.assertEqual(set(svc2.store.tx_index), {tx1, tx2})
        _, acc_a = svc2.get_account(self.A)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_a["balance"], 970)
        self.assertEqual(acc_b["balance"], 1030)
        all_ids = [
            tx.tx_id for b in svc2.store.chain for tx in b.transactions
        ]
        self.assertEqual(sorted(all_ids), sorted([tx1, tx2]))
        self.assertEqual(len(all_ids), len(set(all_ids)))


class ConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)

    @staticmethod
    def _assert_invariants(svc: LedgerService) -> None:
        with svc.store.lock:
            chain = svc.store.chain
            # Heights consecutive, at most the tip may be pending.
            for i, block in enumerate(chain):
                assert block.height == i
                if block.status == "pending":
                    assert i == len(chain) - 1
            # No tx id appears twice across blocks or mempool overlap.
            seen: set[str] = set()
            for block in chain:
                for tx in block.transactions:
                    assert tx.tx_id not in seen
                    seen.add(tx.tx_id)
            for tx_id in svc.store.pending:
                assert tx_id not in seen
            # Reported balances can never go negative.
            for account in svc.store.accounts:
                assert svc.reported_balance(account) >= 0

    def test_concurrent_submissions_never_overspend_or_duplicate(self) -> None:
        # 30 distinct transactions (amounts 1..30) against a 1000 balance.
        results: dict[int, tuple[int, str]] = {}
        errors: list[Exception] = []

        def worker(i: int) -> None:
            try:
                status, body = self.svc.submit_transaction(
                    make_tx(self.ka, self.A, self.B, i + 1)
                )
                results[i] = (status, body.get("tx_id", ""))
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

        accepted = {i: r for i, r in results.items() if r[0] == 202}
        rejected = {i: r for i, r in results.items() if r[0] != 202}
        for i in rejected:
            self.assertEqual(results[i][0], 400, results[i])
        # Serialization enforces the mempool-spend cap: accepted amounts fit
        # within 1000, and every rejected amount would breach the remaining cap.
        accepted_sum = sum(i + 1 for i in accepted)
        self.assertLessEqual(accepted_sum, 1000)
        for i in rejected:
            self.assertGreater(accepted_sum + i + 1, 1000)
        tx_ids = [r[1] for r in accepted.values()]
        self.assertEqual(len(tx_ids), len(set(tx_ids)))

        # Drain and confirm everything, then verify persistence.
        while self.svc.store.pending:
            block = self.svc.mine_block()[1]
            self.svc.confirm_block(block["height"])
        self._assert_invariants(self.svc)
        svc2 = LedgerService(LedgerStore(self.path), initial_balance=1000)
        on_disk = {tx.tx_id for b in svc2.store.chain for tx in b.transactions}
        self.assertEqual(on_disk, set(tx_ids))
        self.assertEqual(svc2.store.pending, {})
        _, acc_a = svc2.get_account(self.A)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_a["balance"], 1000 - accepted_sum)
        self.assertEqual(acc_b["balance"], 1000 + accepted_sum)

    def test_concurrent_mine_confirm_rollback_is_serialized(self) -> None:
        # Seed the mempool with plenty of transactions from the funded sender.
        txs = []
        for i in range(20):
            _, body = self.svc.submit_transaction(
                make_tx(self.ka, self.A, self.B, i + 1)
            )
            txs.append(body["tx_id"])

        stop = threading.Event()
        errors: list[Exception] = []

        def loop(kind: str) -> None:
            try:
                for _ in range(200):
                    if stop.is_set():
                        return
                    if kind == "mine":
                        self.svc.mine_block()
                    elif kind == "confirm":
                        h = self.svc.store.tip().height
                        if h > 0:
                            self.svc.confirm_block(h)
                    else:
                        h = self.svc.store.tip().height
                        if h > 0:
                            self.svc.rollback_block(h)
                    self._assert_invariants(self.svc)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [
            threading.Thread(target=loop, args=("mine",)),
            threading.Thread(target=loop, args=("confirm",)),
            threading.Thread(target=loop, args=("rollback",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        stop.set()
        self.assertEqual(errors, [])

        # Settle the chain: roll back any pending tip, then mine+confirm all
        # remaining mempool transactions.
        if self.svc.store.tip_is_pending():
            self.svc.rollback_block(self.svc.store.tip().height)
        while self.svc.store.pending:
            block = self.svc.mine_block()[1]
            self.svc.confirm_block(block["height"])
        self._assert_invariants(self.svc)

        # Every seeded transaction is persisted exactly once; nothing lost.
        svc2 = LedgerService(LedgerStore(self.path), initial_balance=1000)
        on_disk = [tx.tx_id for b in svc2.store.chain for tx in b.transactions]
        self.assertEqual(sorted(on_disk), sorted(txs))
        self.assertEqual(len(on_disk), len(set(on_disk)))
        self.assertFalse(svc2.store.tip_is_pending())
        total = sum(range(1, 21))
        _, acc_a = svc2.get_account(self.A)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_a["balance"], 1000 - total)
        self.assertEqual(acc_b["balance"], 1000 + total)

    def test_concurrent_store_openings_agree(self) -> None:
        # Several threads opening the same state file must all recover the
        # same generation and leave no temp residue.
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        expected_generation = self.svc.store.generation
        opened: list[LedgerStore] = []
        gate = threading.Barrier(6)

        def open_store() -> None:
            gate.wait()
            opened.append(LedgerStore(self.path))

        threads = [threading.Thread(target=open_store) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(opened), 6)
        self.assertTrue(all(s.generation == expected_generation for s in opened))
        self.assertEqual(snapshot_files(self.tmp), [])


class InterruptedWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)

    def test_failed_write_keeps_previous_state_intact(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        before_generation = self.svc.store.generation
        on_disk_before = read_json(self.path)

        # Force the next persistence to die mid-write (after the temp file is
        # created but before/during its contents are finalized).
        import ledger.store as store_module

        original_dump = store_module.json.dump

        def failing_dump(obj, fh, **kwargs):
            fh.write('{"chain": [')  # partial content
            fh.flush()
            raise OSError("simulated interrupted write")

        store_module.json.dump = failing_dump
        try:
            with self.assertRaises(OSError):
                self.svc.mine_block()
        finally:
            store_module.json.dump = original_dump

        # No generation was consumed in memory, and no half-written temp
        # snapshot is left behind to confuse the next startup.
        self.assertEqual(self.svc.store.generation, before_generation)
        self.assertEqual(snapshot_files(self.tmp), [])
        # The main file is exactly the last successfully persisted state.
        self.assertEqual(read_json(self.path), on_disk_before)

        # A fresh store reopens that last-good state without complaint...
        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.assertEqual(reopened.store.generation, before_generation)
        self.assertEqual(reopened.store.tip().height, 0)
        # ...and normal operation resumes: the mempool tx is still there.
        self.assertEqual(len(reopened.store.pending), 1)
        block = reopened.mine_block()[1]
        self.assertEqual(block["status"], "pending")
        reopened.confirm_block(block["height"])
        self.assertEqual(reopened.store.tip().status, "confirmed")
        self.assertEqual(snapshot_files(self.tmp), [])

    def test_partial_temp_snapshot_is_discarded_on_restart(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        good_generation = self.svc.store.generation
        # A crash leaves a complete main file plus a truncated temp snapshot
        # (never atomically renamed). Startup must ignore the residue.
        residual = os.path.join(self.tmp, f"{SNAPSHOT_PREFIX}partial.gen999")
        with open(residual, "w", encoding="utf-8") as fh:
            fh.write('{"state": {"generation": 999}, "chain": [')
        reopened = LedgerStore(self.path)
        self.assertEqual(reopened.generation, good_generation)
        self.assertEqual(len(reopened.pending), 1)
        self.assertFalse(os.path.exists(residual))
        self.assertEqual(snapshot_files(self.tmp), [])


class SaveFailureRollbackTests(unittest.TestCase):
    """A failed persistence must never leave an un-persisted result visible."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)

    def _fail_save_once(self) -> None:
        original = self.svc.store.save
        calls = {"n": 0}

        def fail_then_restore():
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("disk full")
            return original()

        self.svc.store.save = fail_then_restore  # type: ignore[assignment]

    def test_submit_failure_rolls_back(self) -> None:
        self.assertEqual(len(self.svc.store.pending), 0)
        self._fail_save_once()
        with self.assertRaises(OSError):
            self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        self.assertEqual(self.svc.store.pending, {})
        # Disk recovers: the same transaction can be submitted normally.
        status, body = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        self.assertEqual(status, 202)
        self.assertIn(body["tx_id"], self.svc.store.pending)

    def test_mine_failure_rolls_back(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        tx_ids = set(self.svc.store.pending)
        chain_len = len(self.svc.store.chain)
        self._fail_save_once()
        with self.assertRaises(OSError):
            self.svc.mine_block()
        self.assertEqual(len(self.svc.store.chain), chain_len)
        self.assertEqual(set(self.svc.store.pending), tx_ids)
        self.assertFalse(self.svc.store.tip_is_pending())

    def test_confirm_failure_rolls_back(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        height = self.svc.mine_block()[1]["height"]
        self.assertTrue(self.svc.store.tip_is_pending())
        self._fail_save_once()
        with self.assertRaises(OSError):
            self.svc.confirm_block(height)
        self.assertEqual(self.svc.store.tip().status, "pending")
        # Confirm still works once persistence succeeds.
        self.assertEqual(self.svc.confirm_block(height)[0], 200)
        self.assertEqual(self.svc.store.tip().status, "confirmed")

    def test_rollback_failure_rolls_back(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        height = self.svc.mine_block()[1]["height"]
        self.assertEqual(self.svc.store.pending, {})
        self.assertEqual(len(self.svc.store.chain), 2)
        self._fail_save_once()
        with self.assertRaises(OSError):
            self.svc.rollback_block(height)
        # Block still present as pending tip, mempool still empty.
        self.assertEqual(len(self.svc.store.chain), 2)
        self.assertEqual(self.svc.store.tip().status, "pending")
        self.assertEqual(self.svc.store.pending, {})
        # Rollback still works once persistence succeeds.
        self.assertEqual(self.svc.rollback_block(height)[0], 200)
        self.assertEqual(len(self.svc.store.chain), 1)
        self.assertEqual(len(self.svc.store.pending), 1)


if __name__ == "__main__":
    unittest.main()

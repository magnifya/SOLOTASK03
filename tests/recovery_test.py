"""Crash recovery and concurrency tests for generation-based snapshots.

Covers the recovery contract:

* every successful atomic write bumps the embedded generation;
* startup scans the main file plus same-directory ``.ledger-*`` candidates;
* a newer complete leftover snapshot is promoted over an older/corrupt main;
* corrupt JSON, bad linkage/hashes/Merkle roots/tx ids/signatures and
  duplicate pending/on-chain transactions invalidate a candidate;
* same-generation content conflicts and "no valid candidate" raise
  StateRecoveryError carrying the path and reason — never a silent reset;
* concurrent submit/mine/confirm/rollback never overspend, duplicate a
  transaction, lose a transaction or answer from unpersisted state.

Run: python3 tests/recovery_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


class RecoveryTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.state_path), initial_balance=1000)

    def reopen(self) -> LedgerService:
        return LedgerService(LedgerStore(self.state_path), initial_balance=1000)

    def submit(self, key, sender, to, amount) -> tuple[int, dict]:
        return self.svc.submit_transaction(make_tx(key, sender, to, amount))

    def submit_ok(self, key, sender, to, amount) -> str:
        status, body = self.submit(key, sender, to, amount)
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine_ok(self) -> dict:
        status, body = self.svc.mine_block()
        self.assertEqual(status, 201, body)
        return body

    def confirm_ok(self, height: int) -> None:
        status, body = self.svc.confirm_block(height)
        self.assertEqual(status, 200, body)

    def snapshot_names(self) -> list[str]:
        return sorted(n for n in os.listdir(self.tmp) if n.startswith(".ledger-"))

    def load_raw(self) -> dict:
        with open(self.state_path, encoding="utf-8") as fh:
            import json

            return json.load(fh)


class GenerationTests(RecoveryTestBase):
    def test_every_successful_write_bumps_generation(self) -> None:
        store = self.svc.store
        self.assertEqual(store.generation, self.load_raw()["state"]["generation"])
        genesis_generation = store.generation
        self.assertGreaterEqual(genesis_generation, 1)

        self.submit_ok(self.ka, self.A, self.B, 10)
        self.assertEqual(store.generation, genesis_generation + 1)
        self.assertEqual(
            self.load_raw()["state"]["generation"], genesis_generation + 1
        )

        block = self.mine_ok()
        self.assertEqual(store.generation, genesis_generation + 2)
        self.confirm_ok(block["height"])
        self.assertEqual(store.generation, genesis_generation + 3)

        # Rollback persists too.
        self.submit_ok(self.ka, self.A, self.B, 5)
        block2 = self.mine_ok()
        self.assertEqual(store.generation, genesis_generation + 5)
        status, _ = self.svc.rollback_block(block2["height"])
        self.assertEqual(status, 200)
        self.assertEqual(store.generation, genesis_generation + 6)

    def test_failed_write_does_not_consume_generation_or_touch_main(self) -> None:
        self.submit_ok(self.ka, self.A, self.B, 10)
        before = self.svc.store.generation
        raw_before = self.load_raw()

        import ledger.store as store_module

        original_replace = store_module.os.replace

        def boom(src, dst):
            raise OSError("simulated crash during replace")

        store_module.os.replace = boom
        try:
            with self.assertRaises(OSError):
                self.svc.mine_block()
        finally:
            store_module.os.replace = original_replace

        # Generation not consumed, temp debris removed, main file unchanged.
        self.assertEqual(self.svc.store.generation, before)
        self.assertEqual(self.load_raw(), raw_before)
        self.assertEqual(self.snapshot_names(), [])

    def test_multi_block_consistency_after_restart(self) -> None:
        # Three confirmed blocks.
        tx_ids = []
        for amount in (10, 20, 30):
            tx_ids.append(self.submit_ok(self.ka, self.A, self.B, amount))
            block = self.mine_ok()
            self.confirm_ok(block["height"])

        # Fourth block stays pending, mempool holds one more tx.
        pending_tx = self.submit_ok(self.kb, self.B, self.A, 7)
        pending_block = self.mine_ok()
        mempool_tx = self.submit_ok(self.ka, self.A, self.B, 1)

        svc2 = self.reopen()
        store2 = svc2.store

        # next height / chain shape
        self.assertEqual(store2.next_height(), pending_block["height"] + 1)
        self.assertEqual(len(store2.chain), pending_block["height"] + 1)
        self.assertTrue(store2.tip_is_pending())
        status, tip = svc2.get_block(pending_block["height"])
        self.assertEqual(status, 200)
        self.assertEqual(tip["status"], "pending")

        # tx_index: confirmed only
        self.assertEqual(
            store2.tx_index,
            {tx_id: height for height, tx_id in enumerate(tx_ids, start=1)},
        )
        self.assertNotIn(pending_tx, store2.tx_index)

        # balances: A sent 60 confirmed (+ pending tip spends nothing of A),
        # B received 60 confirmed, spends 7 in the pending tip.
        _, acc_a = svc2.get_account(self.A)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_a["balance"], 1000 - 60)
        self.assertEqual(acc_b["balance"], 1000 + 60 - 7)
        self.assertEqual(acc_a["confirmed_transactions"], tx_ids)
        self.assertEqual(acc_b["confirmed_transactions"], tx_ids)

        # mempool survived
        self.assertIn(mempool_tx, store2.pending)

        # proofs available for every confirmed block and tx
        for height, tx_id in enumerate(tx_ids, start=1):
            status, proof = svc2.get_proof(height, tx_id)
            self.assertEqual(status, 200, proof)
            self.assertEqual(proof["index"], 0)
            self.assertTrue(
                crypto.verify_merkle_proof(
                    tx_id,
                    proof["siblings"],
                    proof["merkle_root"],
                    proof["block_hash"],
                    proof["block_hash"],
                )
            )
        # pending block still refuses proofs and mining
        self.assertEqual(svc2.get_proof(pending_block["height"], pending_tx)[0], 409)
        self.assertEqual(svc2.mine_block()[0], 409)

        # confirm after restart, then another restart: everything converges
        svc2.confirm_block(pending_block["height"])
        svc3 = self.reopen()
        self.assertFalse(svc3.store.tip_is_pending())
        self.assertEqual(svc3.store.tx_index[pending_tx], pending_block["height"])
        _, acc_a3 = svc3.get_account(self.A)
        _, acc_b3 = svc3.get_account(self.B)
        # B's 7-coin spend is now confirmed (A receives it too).
        self.assertEqual(acc_b3["balance"], 1000 + 60 - 7)
        self.assertEqual(acc_a3["balance"], 1000 - 60 + 7)

        # The surviving mempool tx can now be mined; mining was blocked while
        # the tip was pending and must work exactly once after confirmation.
        status, block5 = svc3.mine_block()
        self.assertEqual(status, 201, block5)
        status, summary = svc3.get_block(block5["height"])
        self.assertEqual(status, 200)
        self.assertEqual(summary["transaction_ids"], [mempool_tx])
        self.assertEqual(svc3.mine_block()[0], 409)


class SnapshotRecoveryTests(RecoveryTestBase):
    """Leftover ``.ledger-*`` snapshots drive startup recovery."""

    def _write_raw(self, path: str, data: dict) -> None:
        import json

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

    def test_genesis_only_when_nothing_exists(self) -> None:
        tmp2 = tempfile.mkdtemp()
        path = os.path.join(tmp2, "fresh.json")
        store = LedgerStore(path)
        self.assertEqual(store.generation, 1)
        self.assertEqual(store.next_height(), 1)
        # Reopening must not create a second genesis.
        self.assertEqual(LedgerStore(path).next_height(), 1)
        self.assertEqual(
            [n for n in os.listdir(tmp2) if n.startswith(".ledger-")], []
        )

    def test_main_missing_but_snapshot_present_is_recovered(self) -> None:
        self.submit_ok(self.ka, self.A, self.B, 10)
        block = self.mine_ok()
        self.confirm_ok(block["height"])
        data = self.load_raw()
        os.unlink(self.state_path)
        snap = os.path.join(self.tmp, ".ledger-salvage")
        self._write_raw(snap, data)

        store = LedgerStore(self.state_path)
        self.assertEqual(store.next_height(), block["height"] + 1)
        self.assertTrue(os.path.exists(self.state_path))
        self.assertFalse(os.path.exists(snap))  # promoted, not copied

    def test_newer_snapshot_beats_older_main_and_cleans_debris(self) -> None:
        # Main at generation 2 (one submitted tx).
        tx1 = self.submit_ok(self.ka, self.A, self.B, 10)
        older = self.load_raw()
        # Advance the real store; snapshot the newer state.
        block = self.mine_ok()
        self.confirm_ok(block["height"])
        tx2 = self.submit_ok(self.kb, self.B, self.A, 3)
        newer = self.load_raw()
        # A valid but old leftover snapshot, must be judged stale.
        old_leftover = os.path.join(self.tmp, ".ledger-old")
        self._write_raw(old_leftover, older)
        # The recoverable newer snapshot (crash before it was promoted).
        new_snapshot = os.path.join(self.tmp, ".ledger-new")
        self._write_raw(new_snapshot, newer)
        # Main file rolled back to the older generation.
        self._write_raw(self.state_path, older)

        store = LedgerStore(self.state_path)
        self.assertEqual(store.generation, newer["state"]["generation"])
        self.assertEqual(store.next_height(), block["height"] + 1)
        self.assertIn(tx1, store.tx_index)
        self.assertIn(tx2, store.pending)
        # Winner promoted, every judged-older candidate removed.
        self.assertFalse(os.path.exists(new_snapshot))
        self.assertFalse(os.path.exists(old_leftover))

    def test_newer_main_beats_older_snapshot(self) -> None:
        self.submit_ok(self.ka, self.A, self.B, 10)
        older = self.load_raw()
        block = self.mine_ok()
        self.confirm_ok(block["height"])
        stale = os.path.join(self.tmp, ".ledger-stale")
        self._write_raw(stale, older)

        store = LedgerStore(self.state_path)
        self.assertEqual(store.next_height(), block["height"] + 1)
        self.assertFalse(os.path.exists(stale))

    def test_corrupt_main_falls_back_to_valid_older_snapshot(self) -> None:
        self.submit_ok(self.ka, self.A, self.B, 10)
        good = self.load_raw()
        snap = os.path.join(self.tmp, ".ledger-good")
        self._write_raw(snap, good)
        with open(self.state_path, "w", encoding="utf-8") as fh:
            fh.write("{not json")

        store = LedgerStore(self.state_path)
        self.assertEqual(store.generation, good["state"]["generation"])
        self.assertFalse(os.path.exists(snap))

    def test_torn_temp_debris_is_ignored_and_cleaned(self) -> None:
        self.submit_ok(self.ka, self.A, self.B, 10)
        good_gen = self.load_raw()["state"]["generation"]
        debris = os.path.join(self.tmp, ".ledger-torn")
        with open(debris, "w", encoding="utf-8") as fh:
            fh.write('{"state": {"generation": 999, "chain": [')  # torn JSON

        store = LedgerStore(self.state_path)
        self.assertEqual(store.generation, good_gen)
        self.assertFalse(os.path.exists(debris))


class CorruptionRejectionTests(RecoveryTestBase):
    """Each structural/cryptographic defect invalidates its candidate."""

    def _one_confirmed_tx_state(self) -> dict:
        self.submit_ok(self.ka, self.A, self.B, 10)
        block = self.mine_ok()
        self.confirm_ok(block["height"])
        return self.load_raw()

    def _reopen_expect_recovery_error(self, needle: str) -> None:
        with self.assertRaises(StateRecoveryError) as caught:
            LedgerStore(self.state_path)
        err = caught.exception
        self.assertEqual(os.path.abspath(err.path), os.path.abspath(self.state_path))
        self.assertIn(needle, err.reason)

    def test_truncated_json(self) -> None:
        self._one_confirmed_tx_state()
        with open(self.state_path, "rb+") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.truncate(size // 2)
        self._reopen_expect_recovery_error("JSON")

    def test_bad_prev_hash(self) -> None:
        data = self._one_confirmed_tx_state()
        data["chain"][1]["prev_hash"] = "f" * 64
        self._write(data)
        self._reopen_expect_recovery_error("prev_hash")

    def test_bad_block_hash(self) -> None:
        data = self._one_confirmed_tx_state()
        data["chain"][1]["block_hash"] = "e" * 64
        self._write(data)
        self._reopen_expect_recovery_error("block hash mismatch")

    def test_bad_merkle_root(self) -> None:
        data = self._one_confirmed_tx_state()
        data["chain"][1]["merkle_root"] = "a" * 64
        self._write(data)
        self._reopen_expect_recovery_error("merkle root mismatch")

    def test_bad_tx_signature(self) -> None:
        data = self._one_confirmed_tx_state()
        sig = data["chain"][1]["transactions"][0]["signature"]
        flipped = "0" if sig[0] != "0" else "1"
        data["chain"][1]["transactions"][0]["signature"] = flipped + sig[1:]
        self._write(data)
        self._reopen_expect_recovery_error("signature")

    def test_tx_id_mismatch(self) -> None:
        data = self._one_confirmed_tx_state()
        data["chain"][1]["transactions"][0]["amount"] = 999
        self._write(data)
        self._reopen_expect_recovery_error("tx_id")

    def test_pending_block_not_at_tip(self) -> None:
        # Two confirmed blocks, then retroactively mark the first one pending.
        data = self._one_confirmed_tx_state()
        self.submit_ok(self.kb, self.B, self.A, 2)
        block2 = self.mine_ok()
        self.confirm_ok(block2["height"])
        data = self.load_raw()
        data["chain"][1]["status"] = "pending"
        self._write(data)
        self._reopen_expect_recovery_error("chain tip")

    def test_duplicate_pending_entry(self) -> None:
        self.submit_ok(self.ka, self.A, self.B, 10)
        data = self.load_raw()
        data["pending"].append(data["pending"][0])
        self._write(data)
        self._reopen_expect_recovery_error("duplicate pending")

    def test_pending_overlaps_confirmed_transaction(self) -> None:
        data = self._one_confirmed_tx_state()
        data["pending"].append(data["chain"][1]["transactions"][0])
        self._write(data)
        self._reopen_expect_recovery_error("already exists in a block")

    def test_no_valid_candidate_lists_every_reason(self) -> None:
        with open(self.state_path, "w", encoding="utf-8") as fh:
            fh.write("nonsense")
        debris = os.path.join(self.tmp, ".ledger-bad")
        with open(debris, "w", encoding="utf-8") as fh:
            fh.write("also nonsense")
        with self.assertRaises(StateRecoveryError) as caught:
            LedgerStore(self.state_path)
        self.assertIn("no valid recovery candidate", caught.exception.reason)
        self.assertEqual(
            os.path.abspath(caught.exception.path), os.path.abspath(self.state_path)
        )

    def _write(self, data: dict) -> None:
        import json

        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)


    def test_duplicate_tx_across_blocks(self) -> None:
        data = self._one_confirmed_tx_state()
        self.submit_ok(self.kb, self.B, self.A, 2)
        block2 = self.mine_ok()
        self.confirm_ok(block2["height"])
        data = self.load_raw()
        # Copy the height-1 transaction into the height-2 block too.
        data["chain"][2]["transactions"].append(data["chain"][1]["transactions"][0])
        self._write(data)
        self._reopen_expect_recovery_error("appears in multiple blocks")


class SameGenerationConflictTests(RecoveryTestBase):
    def test_same_generation_identical_snapshot_is_not_a_conflict(self) -> None:
        import json

        self.submit_ok(self.ka, self.A, self.B, 10)
        data = self.load_raw()
        snapshot = os.path.join(self.tmp, ".ledger-twin")
        with open(snapshot, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        store = LedgerStore(self.state_path)
        self.assertEqual(store.generation, data["state"]["generation"])
        # Main file wins the identical-content tie; the snapshot is cleaned up.
        self.assertTrue(os.path.exists(self.state_path))
        self.assertFalse(os.path.exists(snapshot))

    def test_same_generation_conflicting_snapshots_raise(self) -> None:
        import json

        # Main: gen 2 with tx1 pending.
        tx1 = self.submit_ok(self.ka, self.A, self.B, 10)
        main_data = self.load_raw()

        tmp2 = tempfile.mkdtemp()
        path2 = os.path.join(tmp2, "other.json")
        svc2 = LedgerService(LedgerStore(path2), initial_balance=1000)
        svc2.submit_transaction(make_tx(self.kb, self.B, self.A, 3))
        with open(path2, encoding="utf-8") as fh:
            other_data = json.load(fh)
        self.assertEqual(
            main_data["state"]["generation"], other_data["state"]["generation"]
        )

        snapshot = os.path.join(self.tmp, ".ledger-conflict")
        with open(snapshot, "w", encoding="utf-8") as fh:
            json.dump(other_data, fh)

        with self.assertRaises(StateRecoveryError) as caught:
            LedgerStore(self.state_path)
        self.assertEqual(os.path.abspath(caught.exception.path), os.path.abspath(snapshot))
        self.assertIn("generation", caught.exception.reason)
        # Nothing is promoted while the conflict is unresolved.
        self.assertTrue(os.path.exists(snapshot))
        with open(self.state_path, encoding="utf-8") as fh:
            still_main = json.load(fh)
        self.assertEqual(still_main["pending"][0]["tx_id"], tx1)


class ConcurrencyTests(RecoveryTestBase):
    """Concurrent submit/mine/confirm/rollback must serialize safely."""

    @staticmethod
    def _recipient(tag: int) -> str:
        return f"{tag:064x}"

    def test_concurrent_submissions_all_persisted_once(self) -> None:
        import threading

        n = 50
        accepted: list[str] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            payload = make_tx(self.ka, self.A, self._recipient(1000 + i), 1)
            status, body = self.svc.submit_transaction(payload)
            self.assertEqual(status, 202, body)
            with lock:
                accepted.append(body["tx_id"])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(accepted), n)
        self.assertEqual(len(set(accepted)), n)

        # Restart: nothing lost, nothing duplicated, every tx still in mempool.
        store2 = LedgerStore(self.state_path)
        self.assertEqual(set(store2.pending), set(accepted))
        # A has never appeared in a confirmed block, so it is not queryable.
        svc2 = LedgerService(store2, initial_balance=1000)
        self.assertEqual(svc2.get_account(self.A)[0], 404)

    def test_concurrent_submissions_never_overspend(self) -> None:
        import threading

        n_threads, amount = 200, 10  # only 100 of these can fit the balance
        outcomes: list[int] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            payload = make_tx(self.ka, self.A, self._recipient(2000 + i), amount)
            status, _ = self.svc.submit_transaction(payload)
            with lock:
                outcomes.append(status)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        accepted = [code for code in outcomes if code == 202]
        rejected = [code for code in outcomes if code == 400]
        self.assertEqual(len(accepted) * amount, 1000)
        self.assertEqual(len(accepted) + len(rejected), n_threads)

        # The committed mempool spend matches exactly the accepted count.
        committed = sum(tx.amount for tx in self.svc.store.pending.values())
        self.assertEqual(committed, 1000)

    def test_concurrent_mine_confirm_rollback_chaos(self) -> None:
        import random
        import threading

        random.seed(4242)
        # 40 pre-chaos transactions plus 40 submitted during the chaos; all
        # unique, all must eventually exist exactly once and confirm.
        initial = [
            self.submit_ok(self.ka, self.A, self._recipient(i), 1) for i in range(40)
        ]
        extra: list[str] = []
        extra_lock = threading.Lock()

        def chaos_worker() -> None:
            for _ in range(150):
                with self.svc.store.lock:
                    height = self.svc.store.next_height() - 1
                choice = random.randrange(3)
                if choice == 0:
                    self.svc.mine_block()
                elif choice == 1:
                    self.svc.confirm_block(height)
                else:
                    self.svc.rollback_block(height)

        def submit_worker() -> None:
            for i in range(40, 80):
                status, body = self.svc.submit_transaction(
                    make_tx(self.ka, self.A, self._recipient(i), 1)
                )
                # Balance is ample (1000 vs 80 spend); every tx must land.
                assert status == 202, body
                with extra_lock:
                    extra.append(body["tx_id"])

        workers = [threading.Thread(target=chaos_worker) for _ in range(6)]
        workers.append(threading.Thread(target=submit_worker))
        for t in workers:
            t.start()
        for t in workers:
            t.join()

        expected = set(initial) | set(extra)
        self.assertEqual(len(expected), 80)

        # Invariant immediately after the chaos: every accepted tx appears in
        # exactly one place: a confirmed block, the pending tip, or mempool.
        store = self.svc.store
        locations: dict[str, int] = {}

        def note(tx_id: str, where: str) -> None:
            self.assertNotIn(tx_id, locations, f"{tx_id} duplicated: {where}")
            locations[tx_id] = where

        with store.lock:
            for block in store.chain:
                for tx in block.transactions:
                    note(tx.tx_id, f"block {block.height}")
            for tx_id in store.pending:
                note(tx_id, "mempool")
        self.assertEqual(set(locations), expected)

        # Settle single-threaded, then restart: everything confirmed once.
        for _ in range(500):
            with store.lock:
                if store.tip_is_pending():
                    self.svc.confirm_block(store.tip().height)
                elif store.pending:
                    self.svc.mine_block()
                else:
                    break
        self.assertFalse(self.svc.store.tip_is_pending())
        self.assertEqual(self.svc.store.pending, {})

        store2 = LedgerStore(self.state_path)
        self.assertEqual(set(store2.tx_index), expected)
        self.assertEqual(len(store2.tx_index), 80)
        svc2 = LedgerService(store2, initial_balance=1000)
        _, acc_a = svc2.get_account(self.A)
        self.assertEqual(acc_a["balance"], 1000 - 80)
        self.assertEqual(len(acc_a["confirmed_transactions"]), 80)
        # All 80 recipients queryable with a single confirmed credit each.
        for tx_id in expected:
            height = store2.tx_index[tx_id]
            self.assertEqual(svc2.get_block_status(height)[1]["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()

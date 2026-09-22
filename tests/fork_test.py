"""Tests for candidate fork submission, chain comparison and adoption.

Covers POST /v1/forks/candidates validation (canonical genesis connection,
height/prev_hash linkage, block hash, Merkle root, Ed25519 signatures,
unique ascending tx_ids, replay no-overspend, pending-tip rule, length
including genesis), 201/400/409 status codes, GET /v1/chain ordering
(tip_hash ascending candidates, longest / smallest-tip-hash winner,
adoptable non-canonical winner), POST adoption (404/409/200), atomic chain
swap with generation bump and index rebuild, old-chain confirmed txs
returning to the mempool de-duplicated while pending txs never enter it,
and restart behaviour (invalid candidates dropped, canonical invalidity
still raising StateRecoveryError).

Run: python3 tests/fork_test.py
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.models import Block, Transaction, compute_block_hash
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def tx_dict(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(tx_dict(key, sender, to, amount))


class ForkServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()

    def fork_payload(self, blocks: list) -> dict:
        return {"blocks": [b.to_dict() if hasattr(b, "to_dict") else b for b in blocks]}

    def submit(self, blocks: list[Block]):
        return self.svc.submit_fork_candidate(self.fork_payload(blocks))

    def fork_chain(self, key, sender, to, amount, *, height=1, prev=None,
                   status="confirmed", extra_after=0):
        """Build a genesis-anchored fork list with one transaction per block."""
        prev = prev if prev is not None else self.genesis.block_hash
        blocks = []
        block = Block.create(height, prev, [tx_obj(key, sender, to, amount)], status)
        blocks.append(block)
        for _ in range(extra_after):
            block = Block.create(
                block.height + 1,
                block.block_hash,
                [tx_obj(key, sender, to, 1)],
                status,
            )
            blocks.append(block)
        return blocks

    # -- submission validation ---------------------------------------------

    def test_genesis_only_chain(self):
        status, body = self.submit([self.genesis])
        # A fork identical to canonical (just genesis) conflicts 409.
        self.assertEqual(status, 409, body)

    def test_valid_candidate_returns_s(self):
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        status, body = self.submit([self.genesis, block])
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "tip_hash": block.block_hash,
                "height": 1,
                "length": 2,  # includes genesis
                "status": "confirmed",
            },
        )

    def test_pending_tip_candidate(self):
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)],
            status="pending",
        )
        status, body = self.submit([self.genesis, block])
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], "pending")

    def test_non_list_blocks_is_400(self):
        for bad in ({}, {"blocks": "x"}, {"blocks": []}, {"blocks": [1]}, "x"):
            status, body = self.svc.submit_fork_candidate(bad)
            self.assertEqual(status, 400, bad)

    def test_must_start_with_canonical_genesis(self):
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        # Missing genesis.
        self.assertEqual(self.submit([block])[0], 400)
        # Foreign genesis (different hash, still height 0 empty).
        foreign = Block.create(0, "1" * 64, [], status="confirmed")
        self.assertEqual(self.submit([foreign, block])[0], 400)

    def test_height_and_prev_linkage_checked(self):
        block1 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        block2 = Block.create(3, block1.block_hash, [tx_obj(self.kb, self.B, self.A, 1)])
        self.assertEqual(self.submit([self.genesis, block1, block2])[0], 400)
        block2b = Block.create(2, "f" * 64, [tx_obj(self.kb, self.B, self.A, 1)])
        self.assertEqual(self.submit([self.genesis, block1, block2b])[0], 400)

    def test_block_hash_and_merkle_checked(self):
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        tampered_hash = block.to_dict()
        tampered_hash["block_hash"] = "f" * 64
        self.assertEqual(self.submit([self.genesis, tampered_hash])[0], 400)
        tampered_merkle = block.to_dict()
        tampered_merkle["merkle_root"] = "a" * 64
        self.assertEqual(self.submit([self.genesis, tampered_merkle])[0], 400)

    def test_signature_checked(self):
        bad_tx = Transaction(self.A, self.B, 10, "00" * 64)
        block = Block.create(1, self.genesis.block_hash, [bad_tx])
        self.assertEqual(self.submit([self.genesis, block])[0], 400)

    def test_disguised_height_and_amount_types_are_400(self):
        # Strings, floats and booleans must never be coerced into legal chain
        # integers: the raw JSON value is judged first, so every disguise is a
        # 400 and must not persist a fork or advance the generation.
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        good = [self.genesis.to_dict(), block.to_dict()]
        generation_before = self.store.generation

        def mutated(mutator) -> dict:
            doc = {"blocks": copy.deepcopy(good)}
            mutator(doc["blocks"])
            return doc

        bad_documents = (
            # height disguises
            mutated(lambda bl: bl[1].update(height="1")),
            mutated(lambda bl: bl[1].update(height=1.0)),
            mutated(lambda bl: bl[1].update(height=True)),
            # amount disguises
            mutated(lambda bl: bl[1]["transactions"][0].update(amount="10")),
            mutated(lambda bl: bl[1]["transactions"][0].update(amount=10.0)),
            mutated(lambda bl: bl[1]["transactions"][0].update(amount=True)),
        )
        for doc in bad_documents:
            status, body = self.svc.submit_fork_candidate(doc)
            self.assertEqual(status, 400, body)
            self.assertEqual(self.store.forks, {})
            self.assertEqual(self.store.generation, generation_before)
        # The un-coerced integer document still validates.
        self.assertEqual(self.svc.submit_fork_candidate({"blocks": good})[0], 201)

    def test_tx_id_unique_and_ascending(self):
        t1 = tx_obj(self.ka, self.A, self.B, 10)
        t2 = tx_obj(self.ka, self.A, self.C, 5)
        # Same transaction twice inside a block: unique tx_id violation.
        dup_merkle = crypto.merkle_root([t1.tx_id, t1.tx_id])
        dup_block = {
            "height": 1,
            "prev_hash": self.genesis.block_hash,
            "merkle_root": dup_merkle,
            "block_hash": compute_block_hash(1, self.genesis.block_hash, dup_merkle),
            "status": "confirmed",
            "transactions": [t1.to_dict(), t1.to_dict()],
        }
        self.assertEqual(self.submit([self.genesis, dup_block])[0], 400)
        # Duplicate across blocks.
        b1 = Block.create(1, self.genesis.block_hash, [t1])
        b2 = Block.create(2, b1.block_hash, [t1])
        self.assertEqual(self.submit([self.genesis, b1, b2])[0], 400)
        # Unsorted within a block: stored tx order disagrees with the
        # ascending order the recorded Merkle root was built from.
        lo, hi = sorted((t1, t2), key=lambda t: t.tx_id)
        self.assertNotEqual(lo.tx_id, hi.tx_id)
        unsorted_merkle = crypto.merkle_root([lo.tx_id, hi.tx_id])
        unsorted = {
            "height": 1,
            "prev_hash": self.genesis.block_hash,
            "merkle_root": unsorted_merkle,
            "block_hash": compute_block_hash(
                1, self.genesis.block_hash, unsorted_merkle
            ),
            "status": "confirmed",
            "transactions": [hi.to_dict(), lo.to_dict()],
        }
        self.assertEqual(self.submit([self.genesis, unsorted])[0], 400)

    def test_replay_overspend_rejected(self):
        # Two spends of 600 each from A (endowment 1000): second block fails.
        t1 = tx_obj(self.ka, self.A, self.B, 600)
        t2 = tx_obj(self.ka, self.A, self.C, 600)
        b1 = Block.create(1, self.genesis.block_hash, [t1])
        b2 = Block.create(2, b1.block_hash, [t2])
        self.assertEqual(self.submit([self.genesis, b1, b2])[0], 400)
        # Confirmed income does fund later spend, though: B receives 600 then
        # B can spend 600 onward.
        t3 = tx_obj(self.kb, self.B, self.C, 600)
        b3 = Block.create(2, b1.block_hash, [t3])
        self.assertEqual(self.submit([self.genesis, b1, b3])[0], 201)

    def test_pending_non_tip_rejected(self):
        t1 = tx_obj(self.ka, self.A, self.B, 10)
        t2 = tx_obj(self.kb, self.B, self.A, 1)
        b1 = Block.create(1, self.genesis.block_hash, [t1], status="pending")
        b2 = Block.create(2, b1.block_hash, [t2], status="confirmed")
        self.assertEqual(self.submit([self.genesis, b1, b2])[0], 400)

    def test_duplicate_candidate_is_409(self):
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        self.assertEqual(self.submit([self.genesis, block])[0], 201)
        self.assertEqual(self.submit([self.genesis, block])[0], 409)

    def test_prefix_of_extended_canonical_is_409(self):
        # Extend canonical to height 2; a submission equal to the canonical
        # height-1 prefix (and genesis alone) is a duplicate, not a candidate.
        c1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        c2 = Block.create(2, c1.block_hash, [tx_obj(self.kb, self.B, self.A, 1)])
        self.store.chain.extend([c1, c2])
        self.store.rebuild_derived()
        self.store.save()
        self.assertEqual(self.submit([self.store.chain[0], c1])[0], 409)
        self.assertEqual(self.submit([self.store.chain[0]])[0], 409)

    # -- chain comparison ---------------------------------------------------

    def test_chain_listing_sorted_and_adoptable(self):
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        c1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.C, 10)])
        tip1 = self.submit([self.genesis, b1])[1]["tip_hash"]
        tip2 = self.submit([self.genesis, c1])[1]["tip_hash"]
        status, chain = self.svc.get_chain()
        self.assertEqual(status, 200)
        self.assertEqual(chain["canonical"]["length"], 1)
        self.assertEqual([c["tip_hash"] for c in chain["candidates"]], sorted([tip1, tip2]))
        winner = min(tip1, tip2)
        self.assertEqual(chain["adoptable"], [{
            "tip_hash": winner, "height": 1, "length": 2, "status": "confirmed",
        }])

    def test_longest_chain_wins_regardless_of_tip_hash(self):
        # One-block candidate with a tiny tip hash.
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        # Two-block candidate: it must win even if its tip hash is larger.
        c1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.C, 10)])
        c2 = Block.create(2, c1.block_hash, [tx_obj(self.kc, self.C, self.A, 1)])
        short_tip = self.submit([self.genesis, b1])[1]["tip_hash"]
        long_tip = self.submit([self.genesis, c1, c2])[1]["tip_hash"]
        chain = self.svc.get_chain()[1]
        # The two-block chain wins purely on length, regardless of tip hashes.
        self.assertEqual(chain["adoptable"][0]["tip_hash"], long_tip)
        self.assertEqual(chain["adoptable"][0]["length"], 3)
        # The shorter candidate cannot be adopted while a longer winner exists.
        self.assertEqual(self.svc.adopt_fork(short_tip)[0], 409)
        self.assertEqual(self.svc.adopt_fork(long_tip)[0], 200)

    def test_adopt_unknown_and_malformed_tip_404(self):
        self.assertEqual(self.svc.adopt_fork("f" * 64)[0], 404)
        self.assertEqual(self.svc.adopt_fork("not-hex")[0], 404)

    # -- adoption effects ---------------------------------------------------

    def test_adoption_swaps_chain_and_reconciles_mempool(self):
        # Canonical: block 1 with A->B 10, confirmed.
        canon_tx = tx_obj(self.ka, self.A, self.B, 10)
        c1 = Block.create(1, self.genesis.block_hash, [canon_tx])
        self.store.chain.append(c1)
        self.store.rebuild_derived()
        self.store.save()
        gen = self.store.chain[0]
        # Fork: confirmed block 1 A->C 20, then pending tip C->A 5.
        f1tx = tx_obj(self.ka, self.A, self.C, 20)
        f1 = Block.create(1, gen.block_hash, [f1tx], status="confirmed")
        f2tx = tx_obj(self.kc, self.C, self.A, 5)
        f2 = Block.create(2, f1.block_hash, [f2tx], status="pending")
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [gen.to_dict(), f1.to_dict(), f2.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        generation_before = self.store.generation
        status, adopted = self.svc.adopt_fork(tip)
        self.assertEqual(status, 200, adopted)
        self.assertEqual(self.store.tip_hash(), tip)
        self.assertEqual(self.store.tip().status, "pending")
        # Generation advanced by the single atomic adopt write.
        self.assertEqual(self.store.generation, generation_before + 1)
        # Indexes rebuilt: f1tx confirmed, canon_tx gone from chain/index.
        self.assertEqual(self.store.tx_index.get(f1tx.tx_id), 1)
        self.assertNotIn(canon_tx.tx_id, self.store.tx_index)
        # Old-chain-only confirmed tx back in mempool de-duplicated;
        # pending-tip tx of the adopted fork never enters the pool.
        self.assertIn(canon_tx.tx_id, self.store.pending)
        self.assertNotIn(f2tx.tx_id, self.store.pending)
        # Adopted tip removed from candidates.
        self.assertNotIn(tip, self.store.forks)
        # Account view reflects the new chain.
        status, acct = self.svc.get_account(self.B)
        self.assertEqual(status, 404)
        status, acct_c = self.svc.get_account(self.C)
        self.assertEqual(status, 200)
        # +20 confirmed received, minus the 5 C spends in the pending tip.
        self.assertEqual(acct_c["balance"], 1000 + 20 - 5)

    def test_mempool_restore_is_deduplicated(self):
        canon_tx = tx_obj(self.ka, self.A, self.B, 10)
        c1 = Block.create(1, self.genesis.block_hash, [canon_tx])
        self.store.chain.append(c1)
        self.store.rebuild_derived()
        self.store.save()
        gen = self.store.chain[0]
        # The same tx is also already queued in the mempool.
        self.store.pending[canon_tx.tx_id] = canon_tx
        # A strictly longer fork so it is the winner regardless of tip hashes.
        f1 = Block.create(1, gen.block_hash, [tx_obj(self.ka, self.A, self.C, 10)])
        f2 = Block.create(2, f1.block_hash, [tx_obj(self.kc, self.C, self.A, 1)])
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [gen.to_dict(), f1.to_dict(), f2.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(self.svc.adopt_fork(body["tip_hash"])[0], 200)
        self.assertEqual(list(self.store.pending), [canon_tx.tx_id])

    # -- restart ------------------------------------------------------------

    def test_restart_persists_and_revalidates_forks(self):
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        tip = self.submit([self.genesis, b1])[1]["tip_hash"]
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn(tip, reopened.forks)
        self.assertEqual(reopened.forks[tip][-1].block_hash, tip)

    def test_restart_drops_invalid_candidate_keeps_canonical(self):
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        valid_tip = self.submit([self.genesis, b1])[1]["tip_hash"]
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        # Replace the candidate set with one bogus entry; recovery drops it
        # but must still recover the canonical chain.
        doc["forks"] = [[{"height": 0, "bogus": True}]]
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(reopened.forks, {})
        self.assertEqual(reopened.tip_hash(), self.genesis.block_hash)
        # The genuinely valid candidate alone round-trips fine.
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["forks"] = [[self.genesis.to_dict(), b1.to_dict()]]
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        reopened2 = LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn(valid_tip, reopened2.forks)

    def test_restart_canonical_invalid_raises_state_recovery_error(self):
        # Extend the *canonical* chain with a confirmed block, then tamper it.
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        self.store.chain.append(b1)
        self.store.rebuild_derived()
        self.store.save()
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(len(doc["chain"]), 2)
        doc["chain"][1]["block_hash"] = "f" * 64
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_restart_disguised_canonical_types_raise_recovery_error(self):
        # A string/float/boolean height or amount on the canonical chain must
        # never be coerced into a loadable chain: recovery fails loudly with a
        # StateRecoveryError carrying path and reason.
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        self.store.chain.append(b1)
        self.store.rebuild_derived()
        self.store.save()
        tamperings = (
            lambda d: d["chain"][1].__setitem__("height", "1"),
            lambda d: d["chain"][1].__setitem__("height", 1.0),
            lambda d: d["chain"][1].__setitem__("height", True),
            lambda d: d["chain"][1]["transactions"][0].__setitem__("amount", "10"),
            lambda d: d["chain"][1]["transactions"][0].__setitem__("amount", 10.0),
            lambda d: d["chain"][1]["transactions"][0].__setitem__("amount", True),
        )
        for tamper in tamperings:
            with open(self.state_path, encoding="utf-8") as fh:
                doc = json.load(fh)
            tamper(doc)
            with open(self.state_path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            with self.assertRaises(StateRecoveryError) as ctx:
                LedgerStore(self.state_path, initial_balance=1000)
            self.assertTrue(ctx.exception.path)
            self.assertTrue(ctx.exception.reason)
            # Re-write a clean snapshot for the next iteration.
            self.store.save()

    def test_restart_disguised_pending_type_raises_recovery_error(self):
        # The pending (mempool) set is authoritative state too: a disguised
        # amount there must raise rather than be coerced.
        status, body = self.svc.submit_transaction(
            tx_dict(self.ka, self.A, self.B, 10)
        )
        self.assertEqual(status, 202, body)
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["pending"][0]["amount"] = "10"
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("pending", ctx.exception.reason)

    def test_restart_drops_candidate_with_disguised_types(self):
        # Type-disguised values confined to a persisted *candidate* follow the
        # normal cache rule: that candidate is dropped and the valid canonical
        # chain is recovered untouched.
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        tip = self.submit([self.genesis, b1])[1]["tip_hash"]
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["forks"][0][1]["transactions"][0]["amount"] = True
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(reopened.forks, {})
        self.assertEqual(reopened.tip_hash(), self.genesis.block_hash)

    def test_same_generation_conflicting_snapshots_raise(self):
        b1 = Block.create(1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)])
        self.submit([self.genesis, b1])
        with open(self.state_path, encoding="utf-8") as fh:
            first = json.load(fh)

        # A second, self-consistent chain with different content.
        other_dir = tempfile.mkdtemp()
        other_path = os.path.join(other_dir, "o.json")
        other = LedgerService(
            LedgerStore(other_path, initial_balance=1000), initial_balance=1000
        )
        other.submit_transaction(tx_dict(self.ka, self.A, self.B, 123))
        mined = other.mine_block()[1]
        other.confirm_block(mined["height"])
        with open(other_path, encoding="utf-8") as fh:
            second = json.load(fh)
        self.assertNotEqual(first["chain"], second["chain"])

        gen = 99
        first["state"]["generation"] = gen
        second["state"]["generation"] = gen
        conflict_dir = tempfile.mkdtemp()
        main_path = os.path.join(conflict_dir, "state.json")
        with open(main_path, "w", encoding="utf-8") as fh:
            json.dump(first, fh)
        with open(
            os.path.join(conflict_dir, ".ledger-twin.gen%d" % gen), "w", encoding="utf-8"
        ) as fh:
            json.dump(second, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(main_path, initial_balance=1000)
        self.assertIn("conflicting snapshots", ctx.exception.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)

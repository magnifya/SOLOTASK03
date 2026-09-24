"""Tests for batch account-state Merkle proofs.

Covers crypto.verify_account_proof_bundle (exact key sets/order, types,
uniqueness and ascending account order, index/path consistency, leaf
recomputation, root and anchor binding, odd self-pairing, phantom slot,
never raising), the service batch lookup
POST /v1/accounts/proofs[?height=H] (strict 400 body/query validation, 404
semantics, fixed response key order, historical prefix replay, no state
mutation), the HTTP route wire format and the CLI
``state-proofs ACC... [--height H]`` subcommand, plus result stability across
restart, fork adoption, rollback and concurrent reads.

Run: python3 tests/account_proof_bundle_test.py
"""
from __future__ import annotations

import copy
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import STATUS_CONFIRMED, Block
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def h(s: str) -> str:
    return crypto.sha256_hex(s.encode())


def make_bundle(
    accounts: list[str],
    balances: list[int],
    tx_lists: list[list[str]],
    indices: list[int],
    height: int,
    block_hash: str,
) -> dict:
    """Build a well-formed batch account-state bundle for the given leaf rows.

    All accounts are included as leaves (ascending); ``indices`` selects which
    rows get proof entries.
    """
    order = sorted(range(len(accounts)), key=lambda i: accounts[i])
    accounts = [accounts[i] for i in order]
    balances = [balances[i] for i in order]
    tx_lists = [tx_lists[i] for i in order]
    leaves = [
        crypto.account_state_leaf(account, balance, txs)
        for account, balance, txs in zip(accounts, balances, tx_lists)
    ]
    root = crypto.account_state_root(leaves)
    proofs = []
    for index in sorted(indices):
        proofs.append({
            "account": accounts[index],
            "balance": balances[index],
            "confirmed_transactions": tx_lists[index],
            "index": index,
            "siblings": crypto.merkle_proof(leaves, index),
        })
    return {
        "height": height,
        "block_hash": block_hash,
        "state_root": root,
        "proofs": proofs,
    }


class VerifyAccountBundleCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.block_hash = h("block")
        self.height = 6

    def build(self, n: int, indices: list[int]) -> tuple[dict, str]:
        accounts = [f"acct{i:03d}" for i in range(n)]
        txs = [[f"{i:064d}"] for i in range(n)]
        balances = [100 * i for i in range(n)]
        bundle = make_bundle(
            accounts, balances, txs, indices, self.height, self.block_hash
        )
        return bundle, bundle["state_root"]

    def test_all_tree_shapes_full_and_subset_bundles(self) -> None:
        for n in range(1, 13):
            subsets = [list(range(n)), [0], [n - 1],
                       [i for i in range(n) if i % 2 == 0]]
            for indices in subsets:
                bundle, root = self.build(n, indices)
                self.assertTrue(
                    crypto.verify_account_proof_bundle(
                        bundle, root, self.height, self.block_hash
                    ),
                    (n, indices),
                )
                for proof in bundle["proofs"]:
                    self.assertEqual(
                        list(proof.keys()),
                        ["account", "balance", "confirmed_transactions",
                         "index", "siblings"],
                    )
                    for sibling in proof["siblings"]:
                        self.assertEqual(list(sibling.keys()), ["direction", "hash"])
                        self.assertIn(sibling["direction"], ("left", "right"))
                        self.assertTrue(crypto.is_hex64(sibling["hash"]))

    def test_empty_transaction_list_is_valid(self) -> None:
        bundle = make_bundle(
            ["a", "b"], [5, 7], [[], []], [0, 1], self.height, self.block_hash
        )
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                bundle, bundle["state_root"], self.height, self.block_hash
            )
        )

    def test_response_key_order_is_significant(self) -> None:
        good, root = self.build(4, [1, 2])

        reordered = {key: good[key] for key in (
            "height", "state_root", "block_hash", "proofs"
        )}
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                reordered, root, self.height, self.block_hash
            )
        )
        missing = dict(good)
        del missing["proofs"]
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                missing, root, self.height, self.block_hash
            )
        )
        extra = dict(good)
        extra["extra"] = 1
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                extra, root, self.height, self.block_hash
            )
        )

        # Proof entry key order / key set.
        bad = copy.deepcopy(good)
        p = bad["proofs"][0]
        bad["proofs"][0] = {
            "balance": p["balance"],
            "account": p["account"],
            "confirmed_transactions": p["confirmed_transactions"],
            "index": p["index"],
            "siblings": p["siblings"],
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, self.height, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"][0].pop("index")
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, self.height, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"][0]["unexpected"] = 1
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, self.height, self.block_hash)
        )

        # Sibling entry key order / key set.
        bad = copy.deepcopy(good)
        item = bad["proofs"][0]["siblings"][0]
        bad["proofs"][0]["siblings"][0] = {
            "hash": item["hash"], "direction": item["direction"]
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, self.height, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"][0]["siblings"][0]["side"] = "left"
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, self.height, self.block_hash)
        )

    def test_wrong_types_return_false(self) -> None:
        good, root = self.build(4, [0, 3])

        def rejects(mutated, **anchors) -> None:
            kw = dict(
                expected_root=root,
                expected_height=self.height,
                expected_block_hash=self.block_hash,
            )
            kw.update(anchors)
            self.assertFalse(
                crypto.verify_account_proof_bundle(mutated, **kw)
            )

        for bad_height in ("6", 6.0, True, -1, None):
            mutated = copy.deepcopy(good)
            mutated["height"] = bad_height
            rejects(mutated)
        for bad_hash in ("A" * 64, "z" * 64, root[:63], 123, None):
            mutated = copy.deepcopy(good)
            mutated["block_hash"] = bad_hash
            rejects(mutated)
            mutated = copy.deepcopy(good)
            mutated["state_root"] = bad_hash
            rejects(mutated)
        # Bad expected anchors.
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, "abc", self.height, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, "6", self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, True, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, self.height, 7)
        )
        # Anchor value mismatches.
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, h("other"), self.height, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, self.height + 1, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, self.height, h("other"))
        )

        # proofs defects.
        mutated = copy.deepcopy(good)
        mutated["proofs"] = []
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"] = tuple(good["proofs"])
        rejects(mutated)

        p0 = good["proofs"][0]
        for field, bad in (
            ("account", ""),
            ("account", 7),
            ("account", None),
            ("balance", -1),
            ("balance", True),
            ("balance", "1"),
            ("balance", None),
            ("confirmed_transactions", "x"),
            ("confirmed_transactions", ("x",)),
            ("confirmed_transactions", ["nothex"]),
            ("confirmed_transactions", [123]),
            ("index", "0"),
            ("index", True),
            ("index", -1),
            ("siblings", None),
            ("siblings", "x"),
        ):
            mutated = copy.deepcopy(good)
            mutated["proofs"][0][field] = bad
            rejects(mutated)

    def test_uniqueness_and_order(self) -> None:
        good, root = self.build(5, [0, 2, 4])

        def rejects(mutated) -> None:
            self.assertFalse(
                crypto.verify_account_proof_bundle(
                    mutated, root, self.height, self.block_hash
                )
            )

        mutated = copy.deepcopy(good)
        mutated["proofs"].append(copy.deepcopy(mutated["proofs"][0]))
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"].reverse()
        rejects(mutated)

    def test_leaf_tampering_breaks_root(self) -> None:
        good, root = self.build(4, [1])

        def rejects(mutated) -> None:
            self.assertFalse(
                crypto.verify_account_proof_bundle(
                    mutated, root, self.height, self.block_hash
                )
            )

        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["balance"] += 1
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["account"] = "other"
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["confirmed_transactions"] = []
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["confirmed_transactions"] = ["9" * 64]
        rejects(mutated)
        # state_root cannot be retargeted to a tampered tree.
        mutated = copy.deepcopy(good)
        mutated["state_root"] = h("other")
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, h("other"), self.height, self.block_hash
            )
        )

    def test_path_index_and_phantom_slot(self) -> None:
        # Three accounts: rightmost leaf self-pairs with a right sibling.
        good, root = self.build(3, [2])
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                good, root, self.height, self.block_hash
            )
        )
        self.assertEqual(
            good["proofs"][0]["siblings"][0]["direction"], "right"
        )
        self.assertEqual(
            good["proofs"][0]["siblings"][0]["hash"],
            crypto.account_state_leaf("acct002", 200, ["0000000000000000000000000000000000000000000000000000000000000002"]),
        )

        def rejects(mutated) -> None:
            self.assertFalse(
                crypto.verify_account_proof_bundle(
                    mutated, root, self.height, self.block_hash
                )
            )

        # Phantom slot: a self-sibling on the left never verifies.
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["siblings"][0]["direction"] = "left"
        rejects(mutated)
        # Flipped direction / tampered hash / illegal direction.
        four, root4 = self.build(4, [0, 1, 2, 3])
        mutated = copy.deepcopy(four)
        first = mutated["proofs"][0]["siblings"][0]
        first["direction"] = "left" if first["direction"] == "right" else "right"
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        mutated = copy.deepcopy(four)
        mutated["proofs"][1]["siblings"][0]["hash"] = h("tampered")
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        mutated = copy.deepcopy(four)
        mutated["proofs"][2]["siblings"][0]["direction"] = "up"
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        # Sibling entry not a dict / hash malformed.
        mutated = copy.deepcopy(four)
        mutated["proofs"][0]["siblings"][0] = "nope"
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        mutated = copy.deepcopy(four)
        mutated["proofs"][0]["siblings"][0]["hash"] = "Z" * 64
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        # Excessive depth.
        mutated = copy.deepcopy(four)
        mutated["proofs"][0]["siblings"] = [
            {"direction": "left", "hash": "b" * 64}
        ] * (crypto.MAX_MERKLE_DEPTH + 1)
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        # Index incompatible with the supplied path depth (4 leaves need depth
        # 2; dropping all siblings addresses only slot 0).
        mutated = copy.deepcopy(four)
        mutated["proofs"][3]["siblings"] = []
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        mutated = copy.deepcopy(four)
        mutated["proofs"][0]["index"] = 1
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root4, self.height, self.block_hash
            )
        )
        # A single-leaf tree (depth 0) can only be index 0.
        single, root1 = self.build(1, [0])
        mutated = copy.deepcopy(single)
        mutated["proofs"][0]["index"] = 1
        self.assertFalse(
            crypto.verify_account_proof_bundle(
                mutated, root1, self.height, self.block_hash
            )
        )
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                single, root1, self.height, self.block_hash
            )
        )

    def test_junk_inputs_never_raise(self) -> None:
        for junk in (None, 42, "string", [], [1], {"height": 1}, object()):
            self.assertFalse(
                crypto.verify_account_proof_bundle(
                    junk, "a" * 64, 0, "b" * 64
                )
            )


class AccountProofsServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.endowment = 100_000
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=self.endowment,
        )

    def send(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine_and_confirm(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        status, confirmed = self.svc.confirm_block(block["height"])
        self.assertEqual(status, 200, confirmed)
        return block

    def fingerprint(self) -> tuple:
        store = self.svc.store
        return (
            store.generation,
            len(store.chain),
            sorted(store.pending),
            len(store.audit_events),
        )

    def test_success_shape_full_subset_and_reorder(self) -> None:
        t1 = self.send(self.ka, self.A, self.B, 100)
        t2 = self.send(self.kc, self.C, self.A, 40)
        block = self.mine_and_confirm()

        rows = self.svc.store.account_state_rows(
            self.svc.store.chain, self.svc.initial_balance
        )
        names = [name for name, _b, _t in rows]
        self.assertEqual(names, sorted([self.A, self.B, self.C]))
        leaves = [
            crypto.account_state_leaf(a, b, t) for a, b, t in rows
        ]
        root = crypto.account_state_root(leaves)

        # Full batch, requested out of order.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.C, self.A, self.B]}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body.keys()),
                         ["height", "block_hash", "state_root", "proofs"])
        self.assertEqual(body["height"], block["height"])
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(body["state_root"], root)
        self.assertEqual(
            [p["account"] for p in body["proofs"]], names
        )
        for index, proof in enumerate(body["proofs"]):
            self.assertEqual(
                list(proof.keys()),
                ["account", "balance", "confirmed_transactions",
                 "index", "siblings"],
            )
            account, balance, txs = rows[index]
            self.assertEqual(proof["account"], account)
            self.assertEqual(proof["balance"], balance)
            self.assertEqual(proof["confirmed_transactions"], txs)
            self.assertEqual(proof["index"], index)
            self.assertEqual(proof["siblings"], crypto.merkle_proof(leaves, index))
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                body, root, block["height"], block["block_hash"]
            )
        )

        # Subset: only those proofs, still ascending.
        requested = [self.C, self.A]
        status, subset = self.svc.get_account_proofs({"accounts": requested})
        self.assertEqual(status, 200, subset)
        self.assertEqual(
            [p["account"] for p in subset["proofs"]], sorted(requested)
        )
        self.assertEqual(
            [p["index"] for p in subset["proofs"]],
            [names.index(a) for a in sorted(requested)],
        )
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                subset, root, block["height"], block["block_hash"]
            )
        )

        # One single proof is exactly the state-proof content minus anchors.
        status, single = self.svc.get_account_proofs({"accounts": [self.B]})
        self.assertEqual(status, 200, single)
        status, legacy = self.svc.get_account_proof(self.B)
        self.assertEqual(status, 200)
        self.assertEqual(single["proofs"][0], {
            "account": legacy["account"],
            "balance": legacy["balance"],
            "confirmed_transactions": legacy["confirmed_transactions"],
            "index": legacy["index"],
            "siblings": legacy["siblings"],
        })
        self.assertEqual(single["height"], legacy["height"])
        self.assertEqual(single["block_hash"], legacy["block_hash"])
        self.assertEqual(single["state_root"], legacy["state_root"])

    def test_balances_and_transaction_order(self) -> None:
        t1 = self.send(self.ka, self.A, self.B, 100)
        t2 = self.send(self.kc, self.C, self.A, 40)
        self.mine_and_confirm()
        t3 = self.send(self.kb, self.B, self.A, 5)
        self.mine_and_confirm()
        _, body = self.svc.get_account_proofs({"accounts": [self.A, self.B]})
        by_account = {p["account"]: p for p in body["proofs"]}
        self.assertEqual(
            by_account[self.A]["balance"], self.endowment - 100 + 40 + 5
        )
        self.assertEqual(
            by_account[self.A]["confirmed_transactions"],
            sorted([t1, t2]) + [t3],
        )
        self.assertEqual(
            by_account[self.B]["confirmed_transactions"], [t1, t3]
        )

    def test_malformed_bodies_are_400_and_state_untouched(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        valid = "some-account"
        bad_bodies = [
            None,
            [],
            "nope",
            42,
            {},
            {"accounts": []},
            {"accounts": [valid, valid]},   # duplicate
            {"accounts": [valid], "x": 1},  # extra key
            {"proofs": [valid]},            # missing key
            {"accounts": valid},            # wrong type
            {"accounts": {valid}},          # wrong container type
            {"accounts": [valid, ""]},      # empty string
            {"accounts": [""]},             # only empty string
            {"accounts": [7]},              # non-string
            {"accounts": [None]},
        ]
        for body in bad_bodies:
            before = self.fingerprint()
            status, error = self.svc.get_account_proofs(body)
            self.assertEqual(status, 400, (body, error))
            self.assertEqual(set(error), {"error"})
            self.assertEqual(self.fingerprint(), before)

    def test_unknown_account_is_404(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        status, body = self.svc.get_account_proofs({"accounts": ["nobody"]})
        self.assertEqual(status, 404, body)
        # One missing account in an otherwise valid batch fails the whole call.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A, "nobody"]}
        )
        self.assertEqual(status, 404, body)

    def test_pending_tip_default_anchor_is_404(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        _, block = self.svc.mine_block()  # pending tip
        self.assertEqual(
            self.svc.get_account_proofs({"accounts": [self.A]})[0], 404
        )
        # A pending explicit anchor is 404 as well; the confirmed genesis stays.
        self.assertEqual(
            self.svc.get_account_proofs(
                {"accounts": [self.A]}, {"height": str(block["height"])}
            )[0],
            404,
        )
        # After confirmation the default anchor works.
        self.svc.confirm_block(block["height"])
        status, _ = self.svc.get_account_proofs({"accounts": [self.A, self.B]})
        self.assertEqual(status, 200)

    def test_height_query_validation(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        # Unknown parameter / malformed height: 400.
        self.assertEqual(
            self.svc.get_account_proofs({"accounts": [self.A]}, {"foo": "1"})[0],
            400,
        )
        for bad in ("01", "00", "-1", "1.0", "abc", " 1", ""):
            status, body = self.svc.get_account_proofs(
                {"accounts": [self.A]}, {"height": bad}
            )
            self.assertEqual(status, 400, (bad, body))
        # Unknown canonical height: 404.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A]}, {"height": "99"}
        )
        self.assertEqual(status, 404, body)
        # Pending anchor height: 404.
        self.send(self.kb, self.B, self.A, 2)
        _, pending = self.svc.mine_block()
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A]}, {"height": str(pending["height"])}
        )
        self.assertEqual(status, 404, body)

    def test_historical_prefix_replay(self) -> None:
        t1 = self.send(self.ka, self.A, self.B, 100)
        t2 = self.send(self.kc, self.C, self.A, 40)
        blk1 = self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 5)
        blk2 = self.mine_and_confirm()

        for height, blk in ((1, blk1), (2, blk2)):
            prefix = self.svc.store.chain[: height + 1]
            rows = self.svc.store.account_state_rows(prefix, self.svc.initial_balance)
            leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
            root = crypto.account_state_root(leaves)
            names = [name for name, _b, _t in rows]
            # Every other account, requested shuffled.
            requested = list(reversed(names))
            status, body = self.svc.get_account_proofs(
                {"accounts": requested}, {"height": str(height)}
            )
            self.assertEqual(status, 200, (height, body))
            self.assertEqual(body["height"], height)
            self.assertEqual(body["block_hash"], blk["block_hash"])
            self.assertEqual(body["state_root"], root)
            self.assertEqual(
                [p["account"] for p in body["proofs"]], names
            )
            self.assertTrue(
                crypto.verify_account_proof_bundle(
                    body, root, height, blk["block_hash"]
                ),
                height,
            )

        # The account absent at genesis history makes the batch 404.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A]}, {"height": "0"}
        )
        self.assertEqual(status, 404, body)
        # The height-1 state of A lacks the block-2 receive.
        _, body = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B, self.C]}, {"height": "1"}
        )
        by_account = {p["account"]: p for p in body["proofs"]}
        self.assertEqual(
            by_account[self.A]["confirmed_transactions"], sorted([t1, t2])
        )
        self.assertEqual(
            by_account[self.A]["balance"], self.endowment - 100 + 40
        )

        # Default anchor equals explicit latest height.
        _, default_body = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B, self.C]}
        )
        _, explicit = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B, self.C]}, {"height": "2"}
        )
        self.assertEqual(default_body, explicit)
        self.assertEqual(default_body["block_hash"], blk2["block_hash"])

    def test_historical_reads_do_not_mutate_state(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 3)
        self.mine_and_confirm()
        before_accounts = json.dumps(self.svc.store.accounts, sort_keys=True)
        before_index = json.dumps(self.svc.store.tx_index, sort_keys=True)
        for h in range(3):
            self.svc.get_account_proofs(
                {"accounts": [self.A, self.B, "missing"]},
                {"height": str(h)},
            )
        self.assertEqual(
            json.dumps(self.svc.store.accounts, sort_keys=True), before_accounts
        )
        self.assertEqual(
            json.dumps(self.svc.store.tx_index, sort_keys=True), before_index
        )

    def test_restart_recomputes_identical_batches(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 7)
        self.send(self.kc, self.C, self.A, 3)
        self.mine_and_confirm()
        snapshot = {}
        for h in range(3):
            prefix = self.svc.store.chain[: h + 1]
            rows = self.svc.store.account_state_rows(prefix, self.svc.initial_balance)
            names = [name for name, _b, _t in rows]
            status, snap = self.svc.get_account_proofs(
                {"accounts": names}, {"height": str(h)}
            )
            self.assertEqual(status, 200 if names else 400)
            if names:
                snapshot[h] = snap
        reopened = LedgerService(
            LedgerStore(self.svc.store.path), initial_balance=self.endowment
        )
        for h in range(3):
            prefix = self.svc.store.chain[: h + 1]
            rows = self.svc.store.account_state_rows(prefix, self.svc.initial_balance)
            names = [name for name, _b, _t in rows]
            status, body = reopened.get_account_proofs(
                {"accounts": names}, {"height": str(h)}
            )
            if h in snapshot:
                self.assertEqual(status, 200)
                self.assertEqual(body, snapshot[h])
            else:
                self.assertEqual(status, 400)

    def test_rollback_returns_identical_result(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        blk1 = self.mine_and_confirm()
        _, at_one = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B]}, {"height": "1"}
        )
        self.send(self.kb, self.B, self.A, 9)
        _, pending = self.svc.mine_block()
        self.assertEqual(self.svc.rollback_block(pending["height"])[0], 200)
        _, after = self.svc.get_account_proofs({"accounts": [self.A, self.B]})
        self.assertEqual(after, at_one)
        self.assertEqual(after["block_hash"], blk1["block_hash"])

    def test_fork_adoption_rebases_batches(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()

        kx, X = keypair()
        ky, Y = keypair()
        genesis = self.svc.store.chain[0]

        fb1 = Block.create(1, genesis.block_hash,
                           [_fork_tx_model(kx, X, Y, 11)], STATUS_CONFIRMED)
        fb2 = Block.create(2, fb1.block_hash,
                           [_fork_tx_model(ky, Y, X, 4)], STATUS_CONFIRMED)
        payload = {"blocks": [b.to_dict() for b in (genesis, fb1, fb2)]}
        self.assertEqual(
            self.svc.submit_fork_candidate(payload)[0], 201
        )
        self.assertEqual(self.svc.adopt_fork(fb2.block_hash)[0], 200)

        # Old-chain accounts are gone from the adopted history.
        self.assertEqual(
            self.svc.get_account_proofs(
                {"accounts": [self.A]}, {"height": "1"}
            )[0],
            404,
        )
        prefix = self.svc.store.chain[:2]
        rows = self.svc.store.account_state_rows(prefix, self.svc.initial_balance)
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        root = crypto.account_state_root(leaves)
        status, body = self.svc.get_account_proofs(
            {"accounts": [X, Y]}, {"height": "1"}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["block_hash"], fb1.block_hash)
        self.assertTrue(
            crypto.verify_account_proof_bundle(body, root, 1, fb1.block_hash)
        )

    def test_concurrent_reads_are_consistent(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.send(self.kc, self.C, self.A, 2)
        self.mine_and_confirm()
        _, frozen = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B, self.C]}, {"height": "1"}
        )
        errors: list[Exception] = []

        def reader() -> None:
            try:
                for _ in range(200):
                    status, body = self.svc.get_account_proofs(
                        {"accounts": [self.C, self.A, self.B]},
                        {"height": "1"},
                    )
                    if status != 200 or body != frozen:
                        errors.append(AssertionError((status, body)))
                    elif not crypto.verify_account_proof_bundle(
                        body,
                        frozen["state_root"],
                        frozen["height"],
                        frozen["block_hash"],
                    ):
                        errors.append(AssertionError("bundle does not verify"))
            except Exception as exc:  # pragma: no cover - test-only failure path
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        self.send(self.kb, self.B, self.A, 9)
        self.mine_and_confirm()
        self.send(self.kc, self.C, self.A, 1)
        _, pending = self.svc.mine_block()
        self.svc.rollback_block(pending["height"])
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


def _fork_tx_model(key, sender, to, amount):
    from ledger.models import Transaction

    msg = crypto.canonical_message(sender, to, amount)
    return Transaction(sender, to, amount, key.sign(msg).hex())


class AccountProofsHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=100_000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method: str, path: str, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def post_raw(self, path: str, raw: bytes):
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_endpoint_end_to_end(self) -> None:
        p1 = make_tx(self.ka, self.A, self.B, 10)
        p2 = make_tx(self.kb, self.B, self.A, 4)
        self.assertEqual(self.request("POST", "/v1/transactions", p1)[0], 202)
        self.assertEqual(self.request("POST", "/v1/transactions", p2)[0], 202)
        self.assertEqual(self.request("POST", "/v1/blocks", {})[0], 201)
        _, block = self.request("GET", "/v1/blocks/1")
        self.assertEqual(self.request("POST", "/v1/blocks/1/confirm", {})[0], 200)

        # Requested shuffled; response sorts proofs and fixes the wire order.
        req = urllib.request.Request(
            f"{self.base}/v1/accounts/proofs",
            data=json.dumps({"accounts": [self.B, self.A]}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            status = resp.status
        body = json.loads(raw)
        self.assertEqual(status, 200)
        self.assertTrue(raw.startswith('{"height"'))
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "state_root", "proofs"],
        )
        for earlier, later in (
            ("height", "block_hash"),
            ("block_hash", "state_root"),
            ("state_root", "proofs"),
        ):
            self.assertLess(raw.index(f'"{earlier}"'), raw.index(f'"{later}"'))
        self.assertEqual(body["height"], 1)
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(
            [p["account"] for p in body["proofs"]], sorted([self.A, self.B])
        )
        for proof in body["proofs"]:
            self.assertEqual(
                list(proof.keys()),
                ["account", "balance", "confirmed_transactions",
                 "index", "siblings"],
            )
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                body, body["state_root"], 1, block["block_hash"]
            )
        )

        # 400 cases.
        self.assertEqual(self.post_raw("/v1/accounts/proofs", b"{not json")[0], 400)
        self.assertEqual(self.post_raw("/v1/accounts/proofs", b"")[0], 400)
        for payload in (
            [], {}, {"accounts": []}, {"accounts": [self.A, self.A]},
            {"accounts": [""]}, {"accounts": [self.A], "more": 1},
            {"proofs": [self.A]}, {"accounts": 5},
        ):
            self.assertEqual(
                self.request("POST", "/v1/accounts/proofs", payload)[0], 400,
                payload,
            )
        # Query validation.
        self.assertEqual(
            self.request(
                "POST", "/v1/accounts/proofs?height=01",
                {"accounts": [self.A]},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/accounts/proofs?height=x",
                {"accounts": [self.A]},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/accounts/proofs?height=1&height=1",
                {"accounts": [self.A]},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/accounts/proofs?height=1&foo=1&foo=2",
                {"accounts": [self.A]},
            )[0],
            400,
        )
        # 404 cases.
        self.assertEqual(
            self.request(
                "POST", "/v1/accounts/proofs", {"accounts": ["nobody"]}
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/accounts/proofs?height=99",
                {"accounts": [self.A]},
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/accounts/proofs?height=0",
                {"accounts": [self.A]},
            )[0],
            404,
        )

    def test_pending_tip_is_404_over_http(self) -> None:
        k, X = keypair()
        _, Y = keypair()
        self.assertEqual(
            self.request("POST", "/v1/transactions", make_tx(k, X, Y, 3))[0], 202
        )
        _, block = self.request("POST", "/v1/blocks", {})
        status, body = self.request(
            "POST", "/v1/accounts/proofs", {"accounts": [X, Y]}
        )
        self.assertEqual(status, 404, body)
        self.assertEqual(self.request("POST", "/v1/blocks/2/confirm", {})[0], 200)
        # Genesis historical request for X still 404s.
        self.assertEqual(
            self.request(
                "POST", f"/v1/accounts/proofs?height={block['height'] - 1}",
                {"accounts": [X]},
            )[0],
            404,
        )


class AccountProofsCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=100_000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 12))
        cls.service.submit_transaction(make_tx(cls.kb, cls.B, cls.A, 5))
        _, cls.blk = cls.service.mine_block()
        cls.service.confirm_block(cls.blk["height"])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, dict, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw), raw

    def test_state_proofs_cli(self) -> None:
        rc, body, raw = self.run_cli("state-proofs", self.B, self.A)
        self.assertEqual(rc, 0, raw)
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "state_root", "proofs"],
        )
        for earlier, later in (
            ("height", "block_hash"),
            ("block_hash", "state_root"),
            ("state_root", "proofs"),
        ):
            self.assertLess(raw.index(f'"{earlier}"'), raw.index(f'"{later}"'))
        self.assertEqual(body["height"], self.blk["height"])
        self.assertEqual(body["block_hash"], self.blk["block_hash"])
        self.assertEqual(
            [p["account"] for p in body["proofs"]], sorted([self.A, self.B])
        )
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                body, body["state_root"],
                self.blk["height"], self.blk["block_hash"],
            )
        )

        # --height forwards verbatim.
        rc, body, raw = self.run_cli(
            "state-proofs", self.A, self.B, "--height", "1"
        )
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["height"], 1)
        # Genesis history: accounts absent -> 404, exit 1.
        rc, error, _ = self.run_cli(
            "state-proofs", self.A, "--height", "0"
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", error)
        # Malformed height -> 400, exit 1.
        rc, error, _ = self.run_cli(
            "state-proofs", self.A, "--height", "01"
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", error)
        # Unknown height -> 404, exit 1.
        rc, error, _ = self.run_cli(
            "state-proofs", self.A, "--height", "99"
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", error)
        # Unknown account -> 404, exit 1.
        rc, error, _ = self.run_cli("state-proofs", "nobody")
        self.assertEqual(rc, 1)
        self.assertIn("error", error)

    def test_state_proof_singleton_unchanged(self) -> None:
        # The existing state-proof subcommand keeps its shape and behavior.
        rc, body, raw = self.run_cli("state-proof", self.B)
        self.assertEqual(rc, 0, raw)
        self.assertTrue(
            crypto.verify_account_proof(
                body, body["state_root"],
                body["height"], body["block_hash"],
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

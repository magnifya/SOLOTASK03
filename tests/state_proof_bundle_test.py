"""Tests for batch account-state Merkle proofs.

Covers crypto.verify_account_proof_bundle (exact key order/sets, types,
account uniqueness/ordering, index/path consistency, the odd self-pair slot,
root and anchor binding, never raising), the service batch lookup
(strict 400 body validation, 404 anchor/account semantics, response key
ordering and historical prefix replay), the POST /v1/accounts/proofs HTTP
route and the CLI ``state-proofs ACC... [--height H]`` subcommand, plus
restart / rollback / fork-adoption / concurrency consistency.

The single-account GET proof endpoint is unchanged and stays covered by
state_proof_test.py / history_state_test.py.

Run: python3 tests/state_proof_bundle_test.py
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


def rows_for(n: int) -> list[tuple[str, int, list[str]]]:
    return [
        (f"acct{i:03d}", 100 * i, [f"{i:064d}"]) for i in range(n)
    ]


def build_bundle(
    rows: list[tuple[str, int, list[str]]],
    indices: list[int],
    height: int = 7,
    block_hash: str = "a" * 64,
) -> tuple[dict, str]:
    """Build a well-formed batch account-state bundle for the given rows."""
    leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
    root = crypto.account_state_root(leaves)
    proofs = []
    for i in indices:
        account, balance, txs = rows[i]
        proofs.append({
            "account": account,
            "balance": balance,
            "confirmed_transactions": txs,
            "index": i,
            "siblings": crypto.merkle_proof(leaves, i),
        })
    bundle = {
        "height": height,
        "block_hash": block_hash,
        "state_root": root,
        "proofs": proofs,
    }
    return bundle, root


class VerifyAccountBundleCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.block_hash = "a" * 64

    def test_all_tree_shapes_full_and_subset_bundles(self) -> None:
        for n in range(1, 13):
            rows = rows_for(n)
            subsets = [
                list(range(n)),
                [0],
                [n - 1],
                [i for i in range(n) if i % 2 == 0],
            ]
            for indices in subsets:
                bundle, root = build_bundle(rows, indices)
                self.assertTrue(
                    crypto.verify_account_proof_bundle(
                        bundle, root, 7, self.block_hash
                    ),
                    (n, indices),
                )

    def test_single_leaf_tree_has_empty_path(self) -> None:
        rows = rows_for(1)
        bundle, root = build_bundle(rows, [0])
        self.assertEqual(bundle["proofs"][0]["siblings"], [])
        self.assertTrue(
            crypto.verify_account_proof_bundle(bundle, root, 7, self.block_hash)
        )
        # Index 0 is the only legal slot of a depth-0 path.
        bad = copy.deepcopy(bundle)
        bad["proofs"][0]["index"] = 1
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )

    def test_odd_self_paired_node(self) -> None:
        # Three accounts: the rightmost leaf pairs with itself (a "right"
        # sibling equal to its own hash); the genuine bundle must verify.
        rows = rows_for(3)
        bundle, root = build_bundle(rows, [2])
        self.assertEqual(
            bundle["proofs"][0]["siblings"][0],
            {
                "direction": "right",
                "hash": crypto.account_state_leaf("acct002", 200, [f"{2:064d}"]),
            },
        )
        self.assertTrue(
            crypto.verify_account_proof_bundle(bundle, root, 7, self.block_hash)
        )

    def test_response_key_order_is_significant(self) -> None:
        rows = rows_for(4)
        good, root = build_bundle(rows, [1, 2])

        # Top level reordered / missing / extra.
        reordered = {key: good[key] for key in (
            "height", "state_root", "block_hash", "proofs"
        )}
        self.assertFalse(
            crypto.verify_account_proof_bundle(reordered, root, 7, self.block_hash)
        )
        missing = dict(good)
        del missing["proofs"]
        self.assertFalse(
            crypto.verify_account_proof_bundle(missing, root, 7, self.block_hash)
        )
        extra = dict(good)
        extra["extra"] = 1
        self.assertFalse(
            crypto.verify_account_proof_bundle(extra, root, 7, self.block_hash)
        )

        # Proof entry key order / key set.
        p = good["proofs"][0]
        bad = copy.deepcopy(good)
        bad["proofs"][0] = {
            "index": p["index"],
            "account": p["account"],
            "balance": p["balance"],
            "confirmed_transactions": p["confirmed_transactions"],
            "siblings": p["siblings"],
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"][0] = {
            "account": p["account"],
            "balance": p["balance"],
            "confirmed_transactions": p["confirmed_transactions"],
            "index": p["index"],
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"][0]["leaf"] = "x"
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )

        # Sibling entry key order / key set.
        bad = copy.deepcopy(good)
        first = bad["proofs"][0]["siblings"][0]
        bad["proofs"][0]["siblings"][0] = {
            "hash": first["hash"],
            "direction": first["direction"],
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"][0]["siblings"][0]["extra"] = 1
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )

    def test_proof_ordering_and_duplicates(self) -> None:
        rows = rows_for(4)
        good, root = build_bundle(rows, [1, 2])
        # Proofs reordered (accounts no longer ascending): rejected.
        bad = copy.deepcopy(good)
        bad["proofs"] = list(reversed(bad["proofs"]))
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        # A duplicated proof entry: rejected.
        bad = copy.deepcopy(good)
        bad["proofs"].append(copy.deepcopy(good["proofs"][0]))
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        # An empty proof list: rejected.
        bad = dict(good)
        bad["proofs"] = []
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )

    def test_indices_must_strictly_increase_with_accounts(self) -> None:
        # Two leaves where both supplied paths genuinely hash to the root,
        # but the accounts ascend while the indices descend.
        leaf_x = crypto.account_state_leaf("x", 1, [])
        leaf_y = crypto.account_state_leaf("y", 2, [])
        root = crypto.account_state_root([leaf_x, leaf_y])
        bundle = {
            "height": 7,
            "block_hash": self.block_hash,
            "state_root": root,
            "proofs": [
                {"account": "x", "balance": 1, "confirmed_transactions": [],
                 "index": 1,
                 "siblings": [{"direction": "left", "hash": leaf_y}]},
                {"account": "y", "balance": 2, "confirmed_transactions": [],
                 "index": 0,
                 "siblings": [{"direction": "right", "hash": leaf_x}]},
            ],
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bundle, root, 7, self.block_hash)
        )

    def test_paths_must_share_one_depth(self) -> None:
        rows = rows_for(4)
        good, root = build_bundle(rows, [0, 1])
        bad = copy.deepcopy(good)
        bad["proofs"][1]["siblings"] = bad["proofs"][1]["siblings"][:1]
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )

    def test_leaf_tampering_returns_false(self) -> None:
        rows = rows_for(4)
        good, root = build_bundle(rows, [1, 2])
        p = good["proofs"][0]
        for field, value in (
            ("balance", p["balance"] + 1),
            ("account", p["account"] + "x"),
            ("confirmed_transactions", ["9" * 64]),
            ("confirmed_transactions", []),
        ):
            bad = copy.deepcopy(good)
            bad["proofs"][0][field] = value
            self.assertFalse(
                crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash),
                field,
            )

    def test_illegal_direction_hash_index_and_depth(self) -> None:
        rows = rows_for(4)
        good, root = build_bundle(rows, [1])
        first = good["proofs"][0]["siblings"][0]

        bad = copy.deepcopy(good)
        bad["proofs"][0]["siblings"][0] = {
            "direction": "up", "hash": first["hash"]
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"][0]["siblings"][0] = {
            "direction": first["direction"], "hash": "Z" * 64
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        # Direction flipped relative to the index.
        bad = copy.deepcopy(good)
        flipped = "left" if first["direction"] == "right" else "right"
        bad["proofs"][0]["siblings"][0] = {
            "direction": flipped, "hash": first["hash"]
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        # Index out of the slots addressed by the path depth.
        bad = copy.deepcopy(good)
        bad["proofs"][0]["index"] = 4
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        # Excessive depth.
        bad = copy.deepcopy(good)
        bad["proofs"][0]["siblings"] = [
            {"direction": "left", "hash": "b" * 64}
        ] * (crypto.MAX_MERKLE_DEPTH + 1)
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        # Non-list siblings / non-dict proof.
        bad = copy.deepcopy(good)
        bad["proofs"][0]["siblings"] = None
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["proofs"] = ["nope"]
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )

    def test_phantom_self_pair_slot_rejected(self) -> None:
        # A two-leaf tree: the right leaf's genuine left sibling is the other
        # leaf; replacing it with its own hash addresses the phantom slot.
        leaf_0 = crypto.account_state_leaf("a", 0, [])
        leaf_1 = crypto.account_state_leaf("b", 1, [])
        root = crypto.account_state_root([leaf_0, leaf_1])
        bundle = {
            "height": 7,
            "block_hash": self.block_hash,
            "state_root": root,
            "proofs": [{
                "account": "b",
                "balance": 1,
                "confirmed_transactions": [],
                "index": 1,
                "siblings": [{"direction": "left", "hash": leaf_1}],
            }],
        }
        self.assertFalse(
            crypto.verify_account_proof_bundle(bundle, root, 7, self.block_hash)
        )

    def test_root_and_anchor_mismatches_return_false(self) -> None:
        rows = rows_for(4)
        good, root = build_bundle(rows, [1])
        self.assertTrue(
            crypto.verify_account_proof_bundle(good, root, 7, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, "0" * 64, 7, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, 8, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, 7, "0" * 64)
        )
        # A bundle state_root disagreeing with the recomputed root is rejected
        # even when the caller passes that same wrong value as expected_root.
        bad = copy.deepcopy(good)
        bad["state_root"] = "f" * 64
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, "f" * 64, 7, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["height"] = 8
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )
        bad = copy.deepcopy(good)
        bad["block_hash"] = "f" * 64
        self.assertFalse(
            crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash)
        )

    def test_type_violations_return_false(self) -> None:
        rows = rows_for(2)
        good, root = build_bundle(rows, [0, 1])
        # Top-level field types.
        for field, value in (
            ("height", True),
            ("height", -1),
            ("height", "7"),
            ("block_hash", "z" * 64),
            ("state_root", 123),
            ("proofs", None),
        ):
            bad = dict(good)
            bad[field] = value
            self.assertFalse(
                crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash),
                field,
            )
        # Proof field types.
        p = good["proofs"][0]
        for field, value in (
            ("account", ""),
            ("account", 7),
            ("balance", -1),
            ("balance", True),
            ("confirmed_transactions", "x"),
            ("confirmed_transactions", ["nothex"]),
            ("index", -1),
            ("index", True),
        ):
            bad = copy.deepcopy(good)
            bad["proofs"][0][field] = value
            self.assertFalse(
                crypto.verify_account_proof_bundle(bad, root, 7, self.block_hash),
                field,
            )
        # Expected anchor types.
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, 5, 7, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, "7", self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, True, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, -1, self.block_hash)
        )
        self.assertFalse(
            crypto.verify_account_proof_bundle(good, root, 7, 7)
        )

    def test_garbage_inputs_never_raise(self) -> None:
        for garbage in (None, 5, [], "proof", {"x": 1}, {"proofs": []}):
            self.assertFalse(
                crypto.verify_account_proof_bundle(
                    garbage, "0" * 64, 0, "0" * 64
                )
            )
            self.assertFalse(
                crypto.verify_account_proof_bundle(
                    garbage, garbage, garbage, garbage
                )
            )


class AccountProofsServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "service.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.endowment = 100_000
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=self.endowment
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

    def expected_rows(self, height: int) -> list[tuple[str, int, list[str]]]:
        prefix = self.svc.store.chain[: height + 1]
        return self.svc.store.account_state_rows(prefix, self.svc.initial_balance)

    def test_success_shape_ordering_and_content(self) -> None:
        t1 = self.send(self.ka, self.A, self.B, 100)
        t2 = self.send(self.kc, self.C, self.A, 40)
        block = self.mine_and_confirm()

        # Request order is deliberately not account order.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.C, self.A, self.B]}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            tuple(body), ("height", "block_hash", "state_root", "proofs")
        )
        self.assertEqual(body["height"], block["height"])
        self.assertEqual(body["block_hash"], block["block_hash"])
        accounts = [p["account"] for p in body["proofs"]]
        self.assertEqual(accounts, sorted([self.A, self.B, self.C]))

        rows = self.expected_rows(1)
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        root = crypto.account_state_root(leaves)
        self.assertEqual(body["state_root"], root)
        by_account = {p["account"]: p for p in body["proofs"]}
        for index, (account, balance, txs) in enumerate(rows):
            proof = by_account[account]
            self.assertEqual(
                tuple(proof),
                ("account", "balance", "confirmed_transactions", "index",
                 "siblings"),
            )
            self.assertEqual(proof["index"], index)
            self.assertEqual(proof["balance"], balance)
            self.assertEqual(proof["confirmed_transactions"], txs)
            for sibling in proof["siblings"]:
                self.assertEqual(set(sibling), {"direction", "hash"})
                self.assertIn(sibling["direction"], ("left", "right"))
                self.assertTrue(crypto.is_hex64(sibling["hash"]))
        # A's T keeps on-chain (ascending tx_id) order.
        self.assertEqual(by_account[self.A]["confirmed_transactions"], sorted([t1, t2]))
        # The whole bundle verifies offline.
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                body, root, block["height"], block["block_hash"]
            )
        )

    def test_subset_and_single_account(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.send(self.kc, self.C, self.A, 5)
        block = self.mine_and_confirm()
        status, body = self.svc.get_account_proofs({"accounts": [self.C]})
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body["proofs"]), 1)
        self.assertEqual(body["proofs"][0]["account"], self.C)
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                body, body["state_root"], block["height"], block["block_hash"]
            )
        )

    def test_body_validation_400(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        bad_bodies = [
            None,
            5,
            [],
            "x",
            {},
            {"accounts": [self.A], "extra": 1},
            {"account": [self.A]},
            {"accounts": None},
            {"accounts": "x"},
            {"accounts": []},
            {"accounts": [self.A, 7]},
            {"accounts": [self.A, ""]},
            {"accounts": [""]},
            {"accounts": [self.A, self.A]},
        ]
        for payload in bad_bodies:
            status, body = self.svc.get_account_proofs(payload)
            self.assertEqual(status, 400, payload)
            self.assertEqual(set(body), {"error"})

    def test_query_validation_400(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        for bad in ("01", "-1", "1.0", "abc", " 1", ""):
            status, body = self.svc.get_account_proofs(
                {"accounts": [self.A]}, {"height": bad}
            )
            self.assertEqual(status, 400, (bad, body))
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A]}, {"foo": "1"}
        )
        self.assertEqual(status, 400, body)
        # Unknown parameter rejected even with a valid height alongside it.
        status, _ = self.svc.get_account_proofs(
            {"accounts": [self.A]}, {"height": "1", "foo": "1"}
        )
        self.assertEqual(status, 400)

    def test_404_semantics(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        # Unknown account.
        status, body = self.svc.get_account_proofs({"accounts": ["d" * 64]})
        self.assertEqual(status, 404, body)
        # One missing account in an otherwise valid batch: 404 for all.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A, "d" * 64]}
        )
        self.assertEqual(status, 404, body)
        # Unknown anchor height.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A]}, {"height": "99"}
        )
        self.assertEqual(status, 404, body)
        # Accounts absent at genesis history.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B]}, {"height": "0"}
        )
        self.assertEqual(status, 404, body)

    def test_pending_tip_anchors_nothing(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 2)
        _, pending = self.svc.mine_block()
        # Default view 404 while the tip is pending.
        self.assertEqual(
            self.svc.get_account_proofs({"accounts": [self.A]})[0], 404
        )
        # The pending height itself is 404.
        self.assertEqual(
            self.svc.get_account_proofs(
                {"accounts": [self.A]}, {"height": str(pending["height"])}
            )[0],
            404,
        )
        # The last confirmed prefix remains served.
        status, body = self.svc.get_account_proofs(
            {"accounts": [self.A]}, {"height": "1"}
        )
        self.assertEqual(status, 200, body)

    def test_historical_prefix_replay(self) -> None:
        t1 = self.send(self.ka, self.A, self.B, 100)
        self.send(self.kc, self.C, self.A, 40)
        blk1 = self.mine_and_confirm()
        t3 = self.send(self.kb, self.B, self.A, 5)
        blk2 = self.mine_and_confirm()

        for height, blk in ((1, blk1), (2, blk2)):
            rows = self.expected_rows(height)
            accounts = [account for account, _b, _t in rows]
            status, body = self.svc.get_account_proofs(
                {"accounts": list(reversed(accounts))},
                {"height": str(height)},
            )
            self.assertEqual(status, 200, (height, body))
            self.assertEqual(body["height"], height)
            self.assertEqual(body["block_hash"], blk["block_hash"])
            leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
            root = crypto.account_state_root(leaves)
            self.assertEqual(body["state_root"], root)
            self.assertEqual(
                [p["account"] for p in body["proofs"]], accounts
            )
            self.assertTrue(
                crypto.verify_account_proof_bundle(
                    body, root, height, blk["block_hash"]
                )
            )
            # A historical anchor must not verify against another height.
            if height > 1:
                self.assertFalse(
                    crypto.verify_account_proof_bundle(
                        body, root, height - 1, blk["block_hash"]
                    )
                )

        # Default (no height) equals the explicit latest height.
        _, default = self.svc.get_account_proofs({"accounts": [self.A, self.B]})
        _, explicit = self.svc.get_account_proofs(
            {"accounts": [self.B, self.A]}, {"height": "2"}
        )
        self.assertEqual(default, explicit)
        # B at height 2 carries its block-1 receipt (t1) then the block-2
        # receipt (t3), keeping on-chain order across blocks.
        by_account = {p["account"]: p for p in explicit["proofs"]}
        self.assertEqual(by_account[self.B]["confirmed_transactions"], [t1, t3])

    def test_reads_do_not_mutate_state(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        before_accounts = json.dumps(self.svc.store.accounts, sort_keys=True)
        before_index = json.dumps(self.svc.store.tx_index, sort_keys=True)
        for h in (None, "0", "1"):
            params = None if h is None else {"height": h}
            self.svc.get_account_proofs({"accounts": [self.A, "missing"]}, params)
            self.svc.get_account_proofs({"accounts": [self.A, self.B]}, params)
        self.assertEqual(
            json.dumps(self.svc.store.accounts, sort_keys=True), before_accounts
        )
        self.assertEqual(
            json.dumps(self.svc.store.tx_index, sort_keys=True), before_index
        )

    def test_rollback_keeps_historical_bundle_identical(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        blk1 = self.mine_and_confirm()
        _, frozen = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B]}, {"height": "1"}
        )
        self.send(self.kb, self.B, self.A, 9)
        _, pending = self.svc.mine_block()
        _, during = self.svc.get_account_proofs(
            {"accounts": [self.A, self.B]}, {"height": "1"}
        )
        self.assertEqual(during, frozen)
        self.assertEqual(self.svc.rollback_block(pending["height"])[0], 200)
        _, after = self.svc.get_account_proofs(
            {"accounts": [self.B, self.A]}, {"height": "1"}
        )
        self.assertEqual(after, frozen)
        self.assertEqual(after["block_hash"], blk1["block_hash"])

    def test_restart_recomputes_identical_bundles(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 7)
        self.send(self.kc, self.C, self.A, 3)
        self.mine_and_confirm()
        snapshot = {}
        for h in (None, "0", "1", "2"):
            params = None if h is None else {"height": h}
            status, body = self.svc.get_account_proofs(
                {"accounts": [self.A, self.B, self.C]}, params
            )
            snapshot[h] = (status, body)
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=self.endowment
        )
        for h in (None, "0", "1", "2"):
            params = None if h is None else {"height": h}
            status, body = reopened.get_account_proofs(
                {"accounts": [self.C, self.B, self.A]}, params
            )
            self.assertEqual((status, body), snapshot[h], h)

    def test_fork_adoption_rebases_batches(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()

        kx, X = keypair()
        ky, Y = keypair()
        genesis = self.svc.store.chain[0]

        def fork_tx(key, s, t, amt):
            from ledger.models import Transaction
            msg = crypto.canonical_message(s, t, amt)
            return Transaction(s, t, amt, key.sign(msg).hex())

        fb1 = Block.create(
            1, genesis.block_hash, [fork_tx(kx, X, Y, 11)], STATUS_CONFIRMED
        )
        fb2 = Block.create(
            2, fb1.block_hash, [fork_tx(ky, Y, X, 7)], STATUS_CONFIRMED
        )
        fb3 = Block.create(
            3, fb2.block_hash, [fork_tx(self.kc, self.C, X, 1)], STATUS_CONFIRMED
        )
        payload = {"blocks": [b.to_dict() for b in (genesis, fb1, fb2, fb3)]}
        self.assertEqual(
            self.svc.submit_fork_candidate(payload)[0], 201
        )
        self.assertEqual(self.svc.adopt_fork(fb3.block_hash)[0], 200)

        # Old-chain accounts vanish from the adopted history.
        self.assertEqual(
            self.svc.get_account_proofs(
                {"accounts": [self.A]}, {"height": "1"}
            )[0],
            404,
        )
        status, body = self.svc.get_account_proofs(
            {"accounts": [X, Y]}, {"height": "1"}
        )
        self.assertEqual(status, 200, body)
        rows = self.svc.store.account_state_rows(
            self.svc.store.chain[:2], self.svc.initial_balance
        )
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        root = crypto.account_state_root(leaves)
        self.assertEqual(body["state_root"], root)
        self.assertTrue(
            crypto.verify_account_proof_bundle(body, root, 1, fb1.block_hash)
        )
        # The adopted history survives restart.
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=self.endowment
        )
        status, again = reopened.get_account_proofs(
            {"accounts": [Y, X]}, {"height": "1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(again, body)

    def test_concurrent_batches_are_consistent(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        blk1 = self.mine_and_confirm()
        rows = self.expected_rows(1)
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        root = crypto.account_state_root(leaves)
        accounts = [a for a, _b, _t in rows]
        errors: list[Exception] = []

        def reader() -> None:
            try:
                for _ in range(200):
                    status, body = self.svc.get_account_proofs(
                        {"accounts": list(reversed(accounts))},
                        {"height": "1"},
                    )
                    if status != 200:
                        errors.append(AssertionError(status))
                    elif not crypto.verify_account_proof_bundle(
                        body, root, 1, blk1["block_hash"]
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
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 77))
        _, cls.blk = cls.service.mine_block()
        cls.service.confirm_block(cls.blk["height"])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def post(self, path: str, raw: bytes | str | None, ctype: bool = True):
        if raw is None:
            data = None
        else:
            data = raw if isinstance(raw, bytes) else json.dumps(raw).encode()
        headers = {"Content-Type": "application/json"} if ctype and data is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_success_route_and_wire_key_order(self) -> None:
        status, raw = self.post(
            "/v1/accounts/proofs", {"accounts": [self.B, self.A]}
        )
        self.assertEqual(status, 200, raw)
        body = json.loads(raw)
        self.assertEqual(body["height"], self.blk["height"])
        self.assertEqual(body["block_hash"], self.blk["block_hash"])
        self.assertEqual(
            [p["account"] for p in body["proofs"]], sorted([self.A, self.B])
        )
        # Wire-level fixed key order.
        self.assertTrue(
            raw.startswith('{"height":'), raw[:60]
        )
        top_positions = [raw.index(f'"{key}"') for key in (
            "height", "block_hash", "state_root", "proofs"
        )]
        self.assertEqual(top_positions, sorted(top_positions))
        proof_entry = raw[raw.index("proofs"):]
        sub_positions = [proof_entry.index(f'"{key}"') for key in (
            "account", "balance", "confirmed_transactions", "index", "siblings"
        )]
        self.assertEqual(sub_positions, sorted(sub_positions))

    def test_height_query(self) -> None:
        # Explicit historical height.
        status, raw = self.post(
            f"/v1/accounts/proofs?height={self.blk['height']}",
            {"accounts": [self.B]},
        )
        self.assertEqual(status, 200, raw)
        self.assertEqual(json.loads(raw)["height"], self.blk["height"])
        # Malformed / unknown / repeated / unknown-name parameters: 400.
        self.assertEqual(self.post("/v1/accounts/proofs?height=01",
                                   {"accounts": [self.B]})[0], 400)
        self.assertEqual(self.post("/v1/accounts/proofs?height=x",
                                   {"accounts": [self.B]})[0], 400)
        self.assertEqual(self.post("/v1/accounts/proofs?height=1&height=1",
                                   {"accounts": [self.B]})[0], 400)
        self.assertEqual(self.post("/v1/accounts/proofs?foo=1",
                                   {"accounts": [self.B]})[0], 400)
        # Well-formed but unknown height: 404.
        self.assertEqual(self.post("/v1/accounts/proofs?height=99",
                                   {"accounts": [self.B]})[0], 404)

    def test_body_errors(self) -> None:
        for payload in (
            b"{not json",
            json.dumps({}).encode(),
            json.dumps({"accounts": []}).encode(),
            json.dumps({"accounts": [self.A, self.A]}).encode(),
            json.dumps({"accounts": [""]}).encode(),
            json.dumps({"accounts": [1, 2]}).encode(),
            json.dumps({"accounts": [self.A], "x": 1}).encode(),
            b"[]",
            b"null",
        ):
            status, raw = self.post("/v1/accounts/proofs", payload)
            self.assertEqual(status, 400, payload)
            self.assertEqual(set(json.loads(raw)), {"error"})
        # Unknown account: 404.
        status, _ = self.post("/v1/accounts/proofs", {"accounts": ["e" * 64]})
        self.assertEqual(status, 404)


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
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 9))
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
        self.assertEqual(raw.count("\n"), 1)
        return rc, json.loads(raw), raw

    def test_state_proofs_cli(self) -> None:
        rc, body, raw = self.run_cli("state-proofs", self.B, self.A)
        self.assertEqual(rc, 0, raw)
        self.assertEqual(
            tuple(body), ("height", "block_hash", "state_root", "proofs")
        )
        self.assertEqual(
            [p["account"] for p in body["proofs"]], sorted([self.A, self.B])
        )
        self.assertTrue(
            crypto.verify_account_proof_bundle(
                body,
                body["state_root"],
                self.blk["height"],
                self.blk["block_hash"],
            )
        )

    def test_state_proofs_cli_height_and_errors(self) -> None:
        rc, body, raw = self.run_cli(
            "state-proofs", self.B, "--height", str(self.blk["height"])
        )
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["height"], self.blk["height"])
        # Unknown account: non-2xx, single error line, exit 1.
        rc, err, _ = self.run_cli("state-proofs", "f" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("error", err)
        # Malformed height: exit 1.
        rc, err, _ = self.run_cli("state-proofs", self.B, "--height", "01")
        self.assertEqual(rc, 1)
        self.assertIn("error", err)
        # Unknown height: exit 1.
        rc, err, _ = self.run_cli("state-proofs", self.B, "--height", "99")
        self.assertEqual(rc, 1)
        self.assertIn("error", err)
        # Duplicate account: 400 forwarded, exit 1.
        rc, err, _ = self.run_cli("state-proofs", self.B, self.B)
        self.assertEqual(rc, 1)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()

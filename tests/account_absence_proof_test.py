"""Tests for account-absence (non-membership) proofs.

Covers GET /v1/accounts/{account}/absence-proof and the offline
ledger.crypto.verify_account_absence_proof(document, account, expected_state):

* service semantics: empty tree (both neighbors null, empty root), interior
  targets (strict bracketing at adjacent indices), boundary targets (single
  neighbor at index 0 / account_count - 1), 409 for a present target;
* strict ``height`` query handling (malformed/unknown/repeated 400),
  unknown/non-canonical/pending anchors and a pending default tip (404);
* read-only behavior (ledger, generation, indexes and audit events
  unchanged), absence not implying a zero balance, historical confirmed
  prefixes, restart/fork canonical views and concurrent-read consistency;
* neighbor accounts use the raw ascending Python string order (no case
  folding or Unicode normalization);
* offline verification: valid shapes for every tree size/position, strict
  top-level/state/neighbor/sibling key sets, bool-as-number rejection,
  tampering, anchor mixing, non-adjacent neighbors, out-of-range indices and
  odd-node phantom slots all return False without raising, independent of
  dict key order;
* HTTP status codes, wire key order (account, state, lower, upper; state
  keys state_root, height, block_hash, account_count) and unchanged
  behavior of the existing account/proof/attested-proof endpoints.

Run: python3 tests/account_absence_proof_test.py
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
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
    return {"from": sender, "to": to, "amount": amount,
            "signature": key.sign(msg).hex()}


def _neighbor_doc(rows, leaves, root, height, block_hash, index):
    name, balance, transactions = rows[index]
    return {
        "account": name,
        "balance": balance,
        "confirmed_transactions": transactions,
        "index": index,
        "state_root": root,
        "height": height,
        "block_hash": block_hash,
        "siblings": crypto.merkle_proof(leaves, index),
    }


def build_absence_doc(names, target, height=1, block_hash="a" * 64):
    """Build a valid absence document from synthetic accounts ``names``.

    Each account gets balance ``n`` and an empty confirmed-transaction list;
    the tree is anchored at ``(height, block_hash)``.
    """
    ordered = sorted(names)
    rows = [(name, idx + 1, []) for idx, name in enumerate(ordered)]
    leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
    root = crypto.account_state_root(leaves)
    pos = next(i for i, name in enumerate(ordered) if name > target) if any(
        n > target for n in ordered
    ) else len(ordered)
    state = {
        "state_root": root,
        "height": height,
        "block_hash": block_hash,
        "account_count": len(ordered),
    }
    lower = _neighbor_doc(rows, leaves, root, height, block_hash, pos - 1) if pos > 0 else None
    upper = _neighbor_doc(rows, leaves, root, height, block_hash, pos) if pos < len(ordered) else None
    return {"account": target, "state": state, "lower": lower, "upper": upper}


class AbsenceProofCryptoTests(unittest.TestCase):
    def test_valid_shapes_all_sizes_and_positions(self) -> None:
        names = [f"{i:064x}" for i in range(1, 14)]
        for n in range(0, 13):
            subset = names[:n]
            targets = ["0" * 64, "f" * 64]
            if n >= 2:
                targets.append(subset[0] + "m")
            for target in targets:
                if n == 0:
                    doc = {
                        "account": target,
                        "state": {
                            "state_root": crypto.EMPTY_MERKLE_ROOT,
                            "height": 0,
                            "block_hash": "a" * 64,
                            "account_count": 0,
                        },
                        "lower": None,
                        "upper": None,
                    }
                else:
                    doc = build_absence_doc(subset, target)
                self.assertTrue(
                    crypto.verify_account_absence_proof(
                        doc, target, copy.deepcopy(doc["state"])
                    ),
                    (n, target),
                )

    def test_key_order_does_not_matter(self) -> None:
        doc = build_absence_doc(["1" * 64, "3" * 64], "2" + "0" * 63)
        shuffled = {k: doc[k] for k in ("upper", "account", "lower", "state")}
        shuffled["state"] = {
            k: doc["state"][k]
            for k in ("account_count", "block_hash", "state_root", "height")
        }
        self.assertTrue(
            crypto.verify_account_absence_proof(shuffled, doc["account"], doc["state"])
        )

    def test_malformed_top_level_inputs(self) -> None:
        doc = build_absence_doc(["1" * 64, "3" * 64], "2" + "0" * 63)
        state = doc["state"]
        for bad in (None, 5, [], "x", object()):
            self.assertFalse(
                crypto.verify_account_absence_proof(bad, doc["account"], state)
            )
        # Missing / extra top-level keys.
        for key in ("account", "state", "lower", "upper"):
            d = {k: v for k, v in doc.items() if k != key}
            self.assertFalse(
                crypto.verify_account_absence_proof(d, doc["account"], state), key
            )
        extra = dict(doc)
        extra["nope"] = None
        self.assertFalse(
            crypto.verify_account_absence_proof(extra, doc["account"], state)
        )
        # Bad pinned account: non-string, empty, or mismatch.
        for bad_account in (None, "", 7, True, b"x"):
            self.assertFalse(
                crypto.verify_account_absence_proof(doc, bad_account, state)
            )
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, doc["account"] + "x", state)
        )
        # document account must equal the pinned target; claiming a neighbor
        # as the target fails the strict bracketing.
        d = dict(doc)
        d["account"] = doc["upper"]["account"]
        self.assertFalse(
            crypto.verify_account_absence_proof(d, d["account"], state)
        )

    def test_malformed_state_anchor(self) -> None:
        doc = build_absence_doc(["1" * 64, "3" * 64], "2" + "0" * 63)
        state = doc["state"]
        for bad_state in (None, 7, [], "x", {"a": 1}):
            self.assertFalse(
                crypto.verify_account_absence_proof(doc, doc["account"], bad_state)
            )
        # expected_state missing/extra keys.
        partial = {k: v for k, v in state.items() if k != "block_hash"}
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, doc["account"], partial)
        )
        with_extra = dict(state)
        with_extra["x"] = 1
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, doc["account"], with_extra)
        )
        # Any mismatch between document state and the pinned state.
        for key, value in (
            ("state_root", "f" * 64),
            ("height", state["height"] + 1),
            ("block_hash", "0" * 64),
            ("account_count", state["account_count"] + 1),
        ):
            d = copy.deepcopy(doc)
            d["state"][key] = value
            self.assertFalse(
                crypto.verify_account_absence_proof(d, doc["account"], state), key
            )
        # Wrong types inside the state document.
        for key, value in (
            ("state_root", 3),
            ("state_root", "Z" * 64),
            ("height", "1"),
            ("height", -1),
            ("height", True),
            ("block_hash", 7),
            ("account_count", "2"),
            ("account_count", -1),
            ("account_count", True),
        ):
            d = copy.deepcopy(doc)
            d["state"][key] = value
            self.assertFalse(
                crypto.verify_account_absence_proof(d, doc["account"], d["state"]),
                (key, value),
            )
        # Document state itself missing/extra keys.
        d = copy.deepcopy(doc)
        d["state"].pop("account_count")
        self.assertFalse(
            crypto.verify_account_absence_proof(d, doc["account"], d["state"])
        )
        d = copy.deepcopy(doc)
        d["state"]["extra"] = 1
        self.assertFalse(
            crypto.verify_account_absence_proof(d, doc["account"], d["state"])
        )

    def test_empty_tree_rules(self) -> None:
        state = {
            "state_root": crypto.EMPTY_MERKLE_ROOT,
            "height": 0,
            "block_hash": "a" * 64,
            "account_count": 0,
        }
        good = {"account": "x", "state": state, "lower": None, "upper": None}
        self.assertTrue(
            crypto.verify_account_absence_proof(good, "x", state)
        )
        # A non-null neighbor in an empty tree is impossible.
        fake_neighbor = _neighbor_doc(
            [("y", 1, [])],
            [crypto.account_state_leaf("y", 1, [])],
            crypto.account_state_root(
                [crypto.account_state_leaf("y", 1, [])]
            ),
            0, "a" * 64, 0,
        )
        d = copy.deepcopy(good)
        d["lower"] = fake_neighbor
        self.assertFalse(crypto.verify_account_absence_proof(d, "x", state))
        # A non-empty root with account_count 0 is inconsistent.
        d = copy.deepcopy(good)
        d["state"] = dict(state, state_root="f" * 64)
        self.assertFalse(
            crypto.verify_account_absence_proof(d, "x", d["state"])
        )

    def test_neighbor_proof_integrity(self) -> None:
        doc = build_absence_doc(["1" * 64, "3" * 64, "5" * 64], "4" + "0" * 63)
        state = doc["state"]
        target = doc["account"]
        # Neighbor must be a dict with the full inclusion-proof key set.
        d = copy.deepcopy(doc)
        d["lower"] = ["not", "a", "dict"]
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        d = copy.deepcopy(doc)
        d["upper"] = 7
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        d = copy.deepcopy(doc)
        d["lower"].pop("siblings")
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        d = copy.deepcopy(doc)
        d["upper"]["extra"] = 1
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        # Sibling entries also need an exact key set.
        d = copy.deepcopy(doc)
        d["lower"]["siblings"][0]["extra"] = 1
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        # Leaf / path / anchor tampering on either neighbor.
        for side in ("lower", "upper"):
            for mutate in (
                lambda p: p.update(balance=p["balance"] + 1),
                lambda p: p.update(account=p["account"] + "z"),
                lambda p: p.update(height=99),
                lambda p: p.update(state_root="f" * 64),
            ):
                d = copy.deepcopy(doc)
                mutate(d[side])
                self.assertFalse(
                    crypto.verify_account_absence_proof(d, target, state), side
                )
            d = copy.deepcopy(doc)
            d[side]["confirmed_transactions"] = ["9" * 64]
            self.assertFalse(crypto.verify_account_absence_proof(d, target, state))

    def test_bracketing_and_adjacency(self) -> None:
        names = [f"{i:064x}" for i in range(1, 8)]
        # Interior target between index 2 and 3.
        target = names[2] + "m"
        doc = build_absence_doc(names, target)
        state = doc["state"]
        self.assertTrue(crypto.verify_account_absence_proof(doc, target, state))
        self.assertEqual(doc["lower"]["index"], 2)
        self.assertEqual(doc["upper"]["index"], 3)
        # Non-adjacent neighbors: index 1 with index 3.
        far = _neighbor_doc_from(names, 1, state)
        d = copy.deepcopy(doc)
        d["lower"] = far
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        # Boundary: before-first requires the index-0 neighbor only.
        pre = build_absence_doc(names, "0" * 64)
        self.assertIsNone(pre["lower"])
        self.assertEqual(pre["upper"]["index"], 0)
        self.assertTrue(
            crypto.verify_account_absence_proof(pre, "0" * 64, pre["state"])
        )
        d = copy.deepcopy(pre)
        d["upper"] = _neighbor_doc_from(names, 1, pre["state"])
        self.assertFalse(
            crypto.verify_account_absence_proof(d, "0" * 64, pre["state"])
        )
        # Boundary: after-last requires the index count-1 neighbor only.
        post = build_absence_doc(names, "f" * 64)
        self.assertIsNone(post["upper"])
        self.assertEqual(post["lower"]["index"], len(names) - 1)
        self.assertTrue(
            crypto.verify_account_absence_proof(post, "f" * 64, post["state"])
        )
        d = copy.deepcopy(post)
        d["lower"] = _neighbor_doc_from(names, len(names) - 2, post["state"])
        self.assertFalse(
            crypto.verify_account_absence_proof(d, "f" * 64, post["state"])
        )
        # Both null on a non-empty tree is never a valid absence proof.
        d = copy.deepcopy(doc)
        d["lower"], d["upper"] = None, None
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        # Equal (non-strict) bracketing is rejected.
        d = copy.deepcopy(doc)
        d["account"] = d["lower"]["account"]
        self.assertFalse(
            crypto.verify_account_absence_proof(
                d, d["lower"]["account"], state
            )
        )
        d = copy.deepcopy(doc)
        d["account"] = d["upper"]["account"]
        self.assertFalse(
            crypto.verify_account_absence_proof(
                d, d["upper"]["account"], state
            )
        )


def _neighbor_doc_from(names, index, state):
    ordered = sorted(names)
    rows = [(name, i + 1, []) for i, name in enumerate(ordered)]
    leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
    return _neighbor_doc(
        rows, leaves, state["state_root"], state["height"],
        state["block_hash"], index,
    )


class AbsenceProofIndexSafetyTests(unittest.TestCase):
    def test_out_of_range_and_phantom_indices(self) -> None:
        names = [f"{i:064x}" for i in range(1, 6)]
        target = names[1] + "m"
        doc = build_absence_doc(names, target)
        state = doc["state"]
        for bad_index in (-1, state["account_count"], 100):
            d = copy.deepcopy(doc)
            d["upper"]["index"] = bad_index
            self.assertFalse(
                crypto.verify_account_absence_proof(d, target, state), bad_index
            )
        # Booleans are not accepted as numeric indices.
        d = copy.deepcopy(doc)
        d["lower"]["index"] = True
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))
        # A phantom odd-copy slot cannot be turned into a real neighbor: an
        # index >= account_count is always rejected even with a self-paired
        # sibling path.
        d = copy.deepcopy(doc)
        d["upper"]["index"] = 5
        self.assertFalse(crypto.verify_account_absence_proof(d, target, state))

class AbsenceProofServiceTests(unittest.TestCase):
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
        status, body = self.svc.submit_transaction(
            make_tx(key, sender, to, amount)
        )
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine_pending(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        return block

    def confirm(self, height) -> dict:
        status, block = self.svc.confirm_block(height)
        self.assertEqual(status, 200, block)
        return block

    def mine_confirm(self) -> dict:
        block = self.mine_pending()
        self.confirm(block["height"])
        return block

    def verify(self, doc, account, state=None) -> bool:
        return crypto.verify_account_absence_proof(
            doc, account, state if state is not None else doc["state"]
        )

    def test_empty_tree_at_genesis(self) -> None:
        status, doc = self.svc.get_account_absence_proof(self.A)
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["account", "state", "lower", "upper"])
        self.assertEqual(doc["account"], self.A)
        self.assertIsNone(doc["lower"])
        self.assertIsNone(doc["upper"])
        self.assertEqual(
            list(doc["state"]),
            ["state_root", "height", "block_hash", "account_count"],
        )
        self.assertEqual(doc["state"]["account_count"], 0)
        self.assertEqual(doc["state"]["state_root"], crypto.EMPTY_MERKLE_ROOT)
        self.assertEqual(doc["state"]["height"], 0)
        self.assertEqual(
            doc["state"]["block_hash"], self.svc.store.chain[0].block_hash
        )
        self.assertTrue(self.verify(doc, self.A))

    def test_interior_bracketing_and_boundaries(self) -> None:
        # Block 1: A->B and C->A land together; accounts sorted A,B,C.
        self.send(self.ka, self.A, self.B, 100)
        self.send(self.kc, self.C, self.A, 40)
        block = self.mine_confirm()
        ordered = sorted((self.A, self.B, self.C))

        status, rootdoc = self.svc.get_state_root()
        self.assertEqual(status, 200)

        # Target strictly between the first two accounts.
        target = ordered[0] + "m"
        self.assertLess(ordered[0], target)
        self.assertLess(target, ordered[1])
        status, doc = self.svc.get_account_absence_proof(target)
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["state"], rootdoc)
        self.assertEqual(doc["lower"]["account"], ordered[0])
        self.assertEqual(doc["upper"]["account"], ordered[1])
        self.assertEqual(doc["lower"]["index"], 0)
        self.assertEqual(doc["upper"]["index"], 1)
        self.assertTrue(self.verify(doc, target))
        # Neighbor proofs are ordinary inclusion proofs under the same anchor.
        self.assertTrue(
            crypto.verify_account_proof(
                doc["lower"], rootdoc["state_root"],
                rootdoc["height"], rootdoc["block_hash"],
            )
        )
        self.assertTrue(
            crypto.verify_account_proof(
                doc["upper"], rootdoc["state_root"],
                rootdoc["height"], rootdoc["block_hash"],
            )
        )
        self.assertEqual(doc["state"]["block_hash"], block["block_hash"])

        # Before the first account: only upper at index 0.
        status, pre = self.svc.get_account_absence_proof("0" * 64)
        self.assertEqual(status, 200, pre)
        self.assertIsNone(pre["lower"])
        self.assertEqual(pre["upper"]["index"], 0)
        self.assertEqual(pre["upper"]["account"], ordered[0])
        self.assertTrue(self.verify(pre, "0" * 64))

        # After the last account: only lower at account_count - 1.
        status, post = self.svc.get_account_absence_proof("f" * 64)
        self.assertEqual(status, 200, post)
        self.assertIsNone(post["upper"])
        self.assertEqual(post["lower"]["index"], 2)
        self.assertEqual(post["lower"]["account"], ordered[2])
        self.assertTrue(self.verify(post, "f" * 64))

    def test_existing_account_conflicts(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_confirm()
        for account in (self.A, self.B):
            status, body = self.svc.get_account_absence_proof(account)
            self.assertEqual(status, 409, body)
            self.assertEqual(body, {"error": "account already exists"})
        # A stranger never in a confirmed block is still absent (its zero-ish
        # balance does not make it an account).
        kd, D = keypair()
        status, doc = self.svc.get_account_absence_proof(D)
        self.assertEqual(status, 200, doc)
        self.assertTrue(self.verify(doc, D))

    def test_pending_tip_anchors_nothing(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_pending()
        status, body = self.svc.get_account_absence_proof("0" * 64)
        self.assertEqual(status, 404, body)
        self.assertEqual(body, {"error": "chain tip is pending confirmation"})
        # Existing target does not get 409 while the anchor is unavailable.
        self.assertEqual(self.svc.get_account_absence_proof(self.A)[0], 404)
        self.confirm(1)
        self.assertEqual(self.svc.get_account_absence_proof(self.A)[0], 409)

    def test_query_parameter_rules(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_confirm()
        for bad in ("01", "-1", "1.0", "abc", " 0", "0 ", ""):
            status, body = self.svc.get_account_absence_proof(
                "0" * 64, {"height": bad}
            )
            self.assertEqual(status, 400, (bad, body))
        self.assertEqual(
            self.svc.get_account_absence_proof(
                "0" * 64, {"height": "0", "extra": "1"}
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.get_account_absence_proof(
                "0" * 64, {"only": "1"}
            )[0],
            400,
        )
        # Non-string height types are malformed too.
        self.assertEqual(
            self.svc.get_account_absence_proof("0" * 64, {"height": 0})[0], 400
        )
        # Unknown / future anchor heights are 404.
        self.assertEqual(
            self.svc.get_account_absence_proof("0" * 64, {"height": "99"})[0],
            404,
        )

    def test_historical_prefix_absence(self) -> None:
        # Block 1 creates A and B; block 2 adds C.
        self.send(self.ka, self.A, self.B, 100)
        blk1 = self.mine_confirm()
        self.send(self.kc, self.C, self.A, 5)
        blk2 = self.mine_confirm()

        # At height 0 the tree is empty for every target.
        status, genesis = self.svc.get_account_absence_proof(
            self.C, {"height": "0"}
        )
        self.assertEqual(status, 200, genesis)
        self.assertIsNone(genesis["lower"])
        self.assertIsNone(genesis["upper"])
        self.assertEqual(genesis["state"]["state_root"], crypto.EMPTY_MERKLE_ROOT)
        self.assertTrue(self.verify(genesis, self.C))

        # At height 1 C is absent and its neighbors bracket it inside the
        # two-account set (possibly only one side on a boundary).
        status, old = self.svc.get_account_absence_proof(self.C, {"height": "1"})
        self.assertEqual(status, 200, old)
        self.assertEqual(old["state"]["height"], 1)
        self.assertEqual(old["state"]["block_hash"], blk1["block_hash"])
        self.assertEqual(old["state"]["account_count"], 2)
        ordered = sorted((self.A, self.B))
        before = [n for n in ordered if n < self.C]
        after = [n for n in ordered if n > self.C]
        self.assertEqual(
            old["lower"]["account"] if old["lower"] else None,
            before[-1] if before else None,
        )
        self.assertEqual(
            old["upper"]["account"] if old["upper"] else None,
            after[0] if after else None,
        )
        if old["lower"] and old["upper"]:
            self.assertEqual(old["lower"]["index"] + 1, old["upper"]["index"])
        self.assertTrue(self.verify(old, self.C))
        # Pending income at the tip never enters the historical view.

        # At height 2 C is present -> 409 even though it was absent at height 1.
        self.assertEqual(
            self.svc.get_account_absence_proof(self.C, {"height": "2"})[0], 409
        )
        # A historical document does not verify against the tip anchor.
        _, tip = self.svc.get_state_root()
        self.assertNotEqual(old["state"]["state_root"], tip["state_root"])
        self.assertFalse(self.verify(old, self.C, tip))
        # A pending block 3 anchors no default view, but already-confirmed
        # historical prefixes still answer from their immutable state.
        self.send(self.kb, self.B, self.A, 1)
        self.mine_pending()
        self.assertEqual(self.svc.get_account_absence_proof(self.C)[0], 404)
        status, under_pending = self.svc.get_account_absence_proof(
            self.C, {"height": "1"}
        )
        self.assertEqual(status, 200, under_pending)
        self.assertEqual(under_pending, old)
        self.assertEqual(
            self.svc.get_account_absence_proof(self.C, {"height": "2"})[0], 409
        )
        # Rolling the pending block back leaves the historical view identical.
        self.svc.rollback_block(3)
        status, old2 = self.svc.get_account_absence_proof(self.C, {"height": "1"})
        self.assertEqual(status, 200)
        self.assertEqual(old2, old)

    def test_read_only_does_not_touch_generation_or_events(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.send(self.kc, self.C, self.A, 40)
        self.mine_confirm()
        ordered = sorted((self.A, self.B, self.C))
        target = ordered[0] + "m"

        generation_before = self.svc.store.generation
        chain_len = len(self.svc.store.chain)
        events_before = len(self.svc.store.audit_events)
        accounts_before = self.svc.store.account_state_rows(
            self.svc.store.chain, self.endowment
        )
        for _ in range(5):
            status, _ = self.svc.get_account_absence_proof(target)
            self.assertEqual(status, 200)
            self.assertEqual(
                self.svc.get_account_absence_proof("0" * 64, {"height": "0"})[0],
                200,
            )
            self.assertEqual(self.svc.get_account_absence_proof(self.A)[0], 409)
        self.assertEqual(self.svc.store.generation, generation_before)
        self.assertEqual(len(self.svc.store.chain), chain_len)
        self.assertEqual(len(self.svc.store.audit_events), events_before)
        self.assertEqual(
            self.svc.store.account_state_rows(
                self.svc.store.chain, self.endowment
            ),
            accounts_before,
        )

    def test_stable_across_restart(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.send(self.kc, self.C, self.A, 40)
        self.mine_confirm()
        ordered = sorted((self.A, self.B, self.C))
        target = ordered[1] + "m"
        status, before = self.svc.get_account_absence_proof(target)
        self.assertEqual(status, 200)

        reopened = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=self.endowment,
        )
        status, after = reopened.get_account_absence_proof(target)
        self.assertEqual(status, 200)
        self.assertEqual(after, before)
        self.assertTrue(self.verify(after, target))

    def test_fork_adopts_canonical_view(self) -> None:
        from ledger.models import Transaction

        self.send(self.ka, self.A, self.B, 100)
        self.mine_confirm()

        # A strictly longer competing fork from the shared genesis uses only
        # fresh accounts, so the old canonical accounts are absent after
        # adoption.
        kx, X = keypair()
        ky, Y = keypair()
        kz, Z = keypair()
        genesis = self.svc.store.chain[0]

        def fork_tx(key, sender, to, amount) -> Transaction:
            msg = crypto.canonical_message(sender, to, amount)
            return Transaction(sender, to, amount, key.sign(msg).hex())

        fb1 = Block.create(
            1, genesis.block_hash, [fork_tx(kx, X, Y, 11)], STATUS_CONFIRMED
        )
        fb2 = Block.create(
            2, fb1.block_hash, [fork_tx(ky, Y, Z, 7)], STATUS_CONFIRMED
        )
        fb3 = Block.create(
            3, fb2.block_hash, [fork_tx(kz, Z, X, 1)], STATUS_CONFIRMED
        )
        payload = {"blocks": [b.to_dict() for b in (genesis, fb1, fb2, fb3)]}
        status, body = self.svc.submit_fork_candidate(payload)
        self.assertEqual(status, 201, body)
        status, adopted = self.svc.adopt_fork(fb3.block_hash)
        self.assertEqual(status, 200, adopted)

        # A and B are absent from the adopted canonical confirmed set; the
        # post-query view is the fork tip with exactly X, Y, Z.
        fork_names = {X, Y, Z}
        status, doc = self.svc.get_account_absence_proof(self.A)
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["state"]["account_count"], 3)
        self.assertEqual(doc["state"]["block_hash"], fb3.block_hash)
        neighbors = {
            side["account"] for side in (doc["lower"], doc["upper"]) if side
        }
        self.assertTrue(neighbors)
        self.assertTrue(neighbors <= fork_names)
        for side in (doc["lower"], doc["upper"]):
            if side is not None:
                self.assertIn(side["account"], fork_names)
                self.assertTrue(
                    crypto.verify_account_proof(
                        side, doc["state"]["state_root"],
                        doc["state"]["height"], doc["state"]["block_hash"],
                    )
                )
        self.assertTrue(self.verify(doc, self.A))
        self.assertEqual(self.svc.get_account_absence_proof(self.B)[0], 200)
        # The fresh fork accounts are present -> 409, not an absence proof.
        for present in (X, Y, Z):
            self.assertEqual(
                self.svc.get_account_absence_proof(present)[0], 409
            )

    def test_concurrent_reads_stay_within_one_view(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_confirm()
        _, frozen = self.svc.get_state_root()
        ordered = sorted((self.A, self.B))
        target = ordered[0] + "m"
        errors: list[Exception] = []

        def reader() -> None:
            try:
                for _ in range(150):
                    status, body = self.svc.get_account_absence_proof(
                        target, {"height": "1"}
                    )
                    if status != 200:
                        errors.append(AssertionError(("status", status)))
                        continue
                    if body["state"] != frozen:
                        errors.append(AssertionError("mixed anchors"))
                    if not self.verify(body, target, frozen):
                        errors.append(AssertionError("does not verify"))
            except Exception as exc:  # pragma: no cover - test failure path
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        self.send(self.kc, self.C, self.A, 5)
        self.mine_confirm()
        self.send(self.kb, self.B, self.A, 1)
        _, pending = self.svc.mine_block()
        self.svc.rollback_block(pending["height"])
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

    def test_target_ordering_is_raw_string_order(self) -> None:
        # Generate three accounts with first nibbles split so that an
        # uppercase "F..." target sorts strictly between the first two under
        # raw code-point order ("F" == 70: after decimal digits, before "a").
        # All three still enter one confirmed block.
        while True:
            key_lo, lo = keypair()
            key_mid, mid = keypair()
            key_hi, hi = keypair()
            if (
                lo[0] in "0123456789"
                and mid[0] in "abcde"
                and mid[0] < hi[0]
            ):
                break
        for key, sender, to in (
            (key_lo, lo, mid),
            (key_mid, mid, hi),
            (key_hi, hi, lo),
        ):
            status, _ = self.svc.submit_transaction(make_tx(key, sender, to, 1))
            self.assertEqual(status, 202)
        self.mine_confirm()
        names = sorted((lo, mid, hi))
        self.assertEqual(names, [lo, mid, hi])

        # No case folding: uppercase "F..." is a distinct target between the
        # low and middle accounts, not a twin of any lowercase account.
        upper_target = "F" + "0" * 63
        self.assertLess(lo, upper_target)
        self.assertLess(upper_target, mid)
        status, doc = self.svc.get_account_absence_proof(upper_target)
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["lower"]["account"], lo)
        self.assertEqual(doc["upper"]["account"], mid)
        self.assertTrue(self.verify(doc, upper_target))

        # The real endpoint accounts answer 409; folding would have masked
        # the distinct uppercase target as present too.
        for present in (lo, mid, hi):
            self.assertEqual(self.svc.get_account_absence_proof(present)[0], 409)

        # No Unicode normalization: a non-ASCII target (U+00E9, code point
        # 233 > "f" 102) sorts past every lowercase hex account, so only the
        # last-slot lower neighbor exists.
        unicode_target = "\u00e9" + "0" * 63
        status, doc = self.svc.get_account_absence_proof(unicode_target)
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["upper"])
        self.assertEqual(doc["lower"]["index"], len(names) - 1)
        self.assertEqual(doc["lower"]["account"], hi)
        self.assertTrue(self.verify(doc, unicode_target))

        # The normalized-looking ASCII twin is likewise distinct and absent.
        ascii_twin = "e" + "0" * 63
        status, doc = self.svc.get_account_absence_proof(ascii_twin)
        self.assertEqual(status, 200, doc)
        self.assertTrue(self.verify(doc, ascii_twin))

class AbsenceProofHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=100_000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
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

    def request(self, path: str, raw: bool = False):
        req = urllib.request.Request(f"{self.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read().decode()
                return resp.status, payload if raw else json.loads(payload)
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode()
            return exc.code, payload if raw else json.loads(payload)

    def test_wire_key_order_and_verification(self) -> None:
        status, body = self.request(f"/v1/accounts/{self.A}/absence-proof")
        self.assertEqual(status, 409, body)
        target = sorted((self.A, self.B))[0] + "m"
        status, raw = self.request(
            f"/v1/accounts/{urllib.parse.quote(target)}/absence-proof", raw=True
        )
        self.assertEqual(status, 200, raw)
        # Contract key order is preserved on the wire.
        self.assertEqual(list(json.loads(raw).keys()),
                         ["account", "state", "lower", "upper"])
        self.assertEqual(list(json.loads(raw)["state"].keys()),
                         ["state_root", "height", "block_hash", "account_count"])
        doc = json.loads(raw)
        self.assertTrue(
            crypto.verify_account_absence_proof(doc, target, doc["state"])
        )

    def test_genesis_history_empty_tree(self) -> None:
        status, body = self.request(
            f"/v1/accounts/{self.A}/absence-proof?height=0"
        )
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["lower"])
        self.assertIsNone(body["upper"])
        self.assertEqual(body["state"]["state_root"], crypto.EMPTY_MERKLE_ROOT)

    def test_http_parameter_and_anchor_codes(self) -> None:
        for bad in ("01", "-1", "x", "1.0", "%200"):
            status, _ = self.request(
                f"/v1/accounts/{self.A}/absence-proof?height={bad}"
            )
            self.assertEqual(status, 400, bad)
        status, _ = self.request(
            f"/v1/accounts/{self.A}/absence-proof?height=1&height=1"
        )
        self.assertEqual(status, 400)
        status, _ = self.request(
            f"/v1/accounts/{self.A}/absence-proof?foo=1"
        )
        self.assertEqual(status, 400)
        status, _ = self.request(
            f"/v1/accounts/{self.A}/absence-proof?height=99"
        )
        self.assertEqual(status, 404)
        # Empty account segment is 404.
        status, _ = self.request("/v1/accounts//absence-proof")
        self.assertEqual(status, 404)

    def test_existing_endpoints_unchanged(self) -> None:
        status, account = self.request(f"/v1/accounts/{self.A}")
        self.assertEqual(status, 200, account)
        status, proof = self.request(f"/v1/accounts/{self.A}/proof")
        self.assertEqual(status, 200, proof)
        # The plain proof endpoint keeps its historical alphabetical wire
        # order; only the shape is asserted here.
        self.assertEqual(
            set(proof),
            {"account", "balance", "confirmed_transactions", "index",
             "state_root", "height", "block_hash", "siblings"},
        )
        status, attested = self.request(
            f"/v1/accounts/{self.A}/attested-proof"
        )
        self.assertEqual(status, 200, attested)
        self.assertEqual(list(attested), ["state", "proof", "auth"])
        status, rootdoc = self.request("/v1/state/root")
        self.assertEqual(status, 200, rootdoc)


if __name__ == "__main__":
    unittest.main(verbosity=2)

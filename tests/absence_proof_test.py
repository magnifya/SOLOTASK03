"""Tests for account-absence (non-membership) proofs.

Covers:

* service GET /v1/accounts/{account}/absence-proof and
  crypto.verify_account_absence_proof: empty-tree documents, predecessor /
  successor framing with strict ordering and adjacent indices, boundary
  documents (before the first / after the last account), historical anchors;
* strict query-parameter handling (malformed / repeated / unknown 400),
  unknown / non-canonical / pending anchors 404, pending default tip 404,
  existing target 409;
* the pure-library verifier: exact field/type/format rules (booleans are not
  numbers, missing/extra keys fail regardless of key order), anchor pinning,
  neighbor inclusion proofs, adjacency and boundary rules, empty-tree root,
  tampering, mixed anchors, out-of-range indices and odd-node phantom slots
  all returning False without raising;
* HTTP wire behavior (fixed key order, repeats, encoding), read-only
  semantics (no ledger / generation / index / audit change), restart and
  fork rebasing, and concurrent reads against a mutating chain.

Run: python3 tests/absence_proof_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
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
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(msg).hex(),
    }


class AbsenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "absence.json")
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

    def state(self, height=None) -> dict:
        status, body = self.svc.get_state_root(height)
        self.assertEqual(status, 200, body)
        return body

    def test_empty_tree_at_genesis(self) -> None:
        status, doc = self.svc.get_account_absence_proof("nobody", {"height": "0"})
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["account", "state", "lower", "upper"])
        self.assertEqual(doc["account"], "nobody")
        self.assertIsNone(doc["lower"])
        self.assertIsNone(doc["upper"])
        state = doc["state"]
        self.assertEqual(
            list(state), ["state_root", "height", "block_hash", "account_count"]
        )
        self.assertEqual(state["account_count"], 0)
        self.assertEqual(state["height"], 0)
        self.assertEqual(state["state_root"], crypto.EMPTY_MERKLE_ROOT)
        anchor = self.state("0")
        self.assertTrue(
            crypto.verify_account_absence_proof(doc, "nobody", anchor)
        )

    def test_boundary_before_first_and_after_last(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        anchor = self.state()
        names = sorted((self.A, self.B))
        # A name sorting before every account: empty string aside, use a
        # single character below any lowercase hex account.
        before = "!"
        status, doc = self.svc.get_account_absence_proof(before)
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["lower"])
        self.assertIsNotNone(doc["upper"])
        self.assertEqual(doc["upper"]["index"], 0)
        self.assertEqual(doc["upper"]["account"], names[0])
        self.assertTrue(
            crypto.verify_account_absence_proof(doc, before, anchor)
        )
        after = "z" * 64
        status, doc = self.svc.get_account_absence_proof(after)
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["upper"])
        self.assertIsNotNone(doc["lower"])
        self.assertEqual(doc["lower"]["index"], anchor["account_count"] - 1)
        self.assertEqual(doc["lower"]["account"], names[-1])
        self.assertTrue(
            crypto.verify_account_absence_proof(doc, after, anchor)
        )

    def test_between_two_neighbors(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.send(self.kc, self.C, self.A, 2)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.C, 1)
        self.mine_and_confirm()
        anchor = self.state()
        names = sorted((self.A, self.B, self.C))
        for i in range(len(names) - 1):
            target = names[i] + "00"
            self.assertLess(names[i], target)
            self.assertLess(target, names[i + 1])
            status, doc = self.svc.get_account_absence_proof(target)
            self.assertEqual(status, 200, doc)
            self.assertEqual(doc["lower"]["account"], names[i])
            self.assertEqual(doc["upper"]["account"], names[i + 1])
            self.assertEqual(doc["lower"]["index"], i)
            self.assertEqual(doc["upper"]["index"], i + 1)
            self.assertTrue(
                crypto.verify_account_absence_proof(doc, target, anchor)
            )
            # Both neighbor documents are ordinary inclusion proofs sharing
            # the same anchor, and their rows come from one confirmed view.
            for neighbor in (doc["lower"], doc["upper"]):
                self.assertTrue(
                    crypto.verify_account_proof(
                        neighbor,
                        anchor["state_root"],
                        anchor["height"],
                        anchor["block_hash"],
                    )
                )

    def test_existing_account_is_409(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        for account in (self.A, self.B):
            status, body = self.svc.get_account_absence_proof(account)
            self.assertEqual(status, 409, body)
            status, body = self.svc.get_account_absence_proof(
                account, {"height": "1"}
            )
            self.assertEqual(status, 409, body)

    def test_historical_absence_and_later_appearance(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        # C is absent at height 1.
        status, h1 = self.svc.get_state_root("1")
        self.assertEqual(status, 200)
        status, doc1 = self.svc.get_account_absence_proof(
            self.C, {"height": "1"}
        )
        self.assertEqual(status, 200, doc1)
        self.assertTrue(
            crypto.verify_account_absence_proof(doc1, self.C, h1)
        )
        # C enters the confirmed set in block 2: the same historical query
        # still verifies, while the current view is 409.
        self.send(self.kb, self.B, self.C, 3)
        self.mine_and_confirm()
        status, doc1b = self.svc.get_account_absence_proof(
            self.C, {"height": "1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(doc1b, doc1)
        self.assertEqual(self.svc.get_account_absence_proof(self.C)[0], 409)
        # A document from height 1 must not verify against the new anchor.
        current = self.state()
        self.assertFalse(
            crypto.verify_account_absence_proof(doc1, self.C, current)
        )

    def test_query_parameter_errors(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        for bad in ("-1", "00", "1.0", " 1", "1 ", "0x1", "+", ""):
            status, body = self.svc.get_account_absence_proof(
                "nobody", {"height": bad}
            )
            self.assertEqual(status, 400, (bad, body))
        status, body = self.svc.get_account_absence_proof(
            "nobody", {"height": 1}
        )
        self.assertEqual(status, 400)
        status, body = self.svc.get_account_absence_proof(
            "nobody", {"foo": "1"}
        )
        self.assertEqual(status, 400)
        status, body = self.svc.get_account_absence_proof(
            "nobody", {"height": "1", "foo": "1"}
        )
        self.assertEqual(status, 400)
        # Unknown / future and non-canonical-looking heights are 404.
        status, body = self.svc.get_account_absence_proof(
            "nobody", {"height": "999"}
        )
        self.assertEqual(status, 404, body)

    def test_pending_tip_and_pending_anchor_404(self) -> None:
        # Genesis is confirmed: empty-tree proof serves at height 0.
        status, _ = self.svc.get_account_absence_proof("nobody")
        self.assertEqual(status, 200)
        self.send(self.ka, self.A, self.B, 10)
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201, pending)
        status, body = self.svc.get_account_absence_proof("nobody")
        self.assertEqual(status, 404, body)
        status, body = self.svc.get_account_absence_proof(
            "nobody", {"height": str(pending["height"])}
        )
        self.assertEqual(status, 404, body)
        # The confirmed historical prefix remains readable.
        status, doc = self.svc.get_account_absence_proof(
            "nobody", {"height": "0"}
        )
        self.assertEqual(status, 200, doc)

    def test_empty_account_is_404_like_inclusion_proof(self) -> None:
        status, body = self.svc.get_account_absence_proof("")
        self.assertEqual(status, 404, body)
        status, body = self.svc.get_account_absence_proof(
            "", {"height": "0"}
        )
        self.assertEqual(status, 404, body)
        status, body = self.svc.get_account_absence_proof(5)
        self.assertEqual(status, 404, body)

    def test_query_is_read_only(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        store = self.svc.store
        generation = store.generation
        events = len(store.audit_events)
        chain_len = len(store.chain)
        mempool = len(store.pending)
        for _ in range(5):
            self.svc.get_account_absence_proof("nobody")
            self.svc.get_account_absence_proof(self.A)
            self.svc.get_account_absence_proof(
                "nobody", {"height": "0"}
            )
        self.assertEqual(store.generation, generation)
        self.assertEqual(len(store.audit_events), events)
        self.assertEqual(len(store.chain), chain_len)
        self.assertEqual(len(store.pending), mempool)
        self.assertEqual(
            self.svc.get_account_proof(self.A)[1]["balance"],
            self.endowment - 10,
        )

    def test_no_case_folding_or_normalization(self) -> None:
        # Distinct byte strings stay distinct rows; ordering is raw code-point
        # order. A target differing only by case is absent and frames the
        # existing account.
        self.send(self.ka, self.A, self.B, 1)
        self.mine_and_confirm()
        # Seed a non-ASCII account directly through a transfer from A.
        uni = "账户乙"
        self.send(self.ka, self.A, uni, 2)
        self.mine_and_confirm()
        anchor = self.state()
        target = "账户乙\u0301"  # combining mark; not equal to the account
        status, doc = self.svc.get_account_absence_proof(target)
        self.assertEqual(status, 200, doc)
        self.assertTrue(
            crypto.verify_account_absence_proof(doc, target, anchor)
        )
        status, body = self.svc.get_account_absence_proof(uni)
        self.assertEqual(status, 409, body)

    def test_restart_keeps_absence_documents(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        status, first = self.svc.get_account_absence_proof("ghost")
        self.assertEqual(status, 200)
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=self.endowment
        )
        status, second = reopened.get_account_absence_proof("ghost")
        self.assertEqual(status, 200)
        self.assertEqual(first, second)

    def test_fork_adoption_rebases_absence(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        old1 = self.state("1")
        genesis = self.svc.store.chain[0]

        kx, X = keypair()
        ky, Y = keypair()
        fb1 = Block.create(
            1,
            genesis.block_hash,
            [_fork_block_tx(kx, X, Y, 11)],
            STATUS_CONFIRMED,
        )
        fb2 = Block.create(
            2,
            fb1.block_hash,
            [_fork_block_tx(ky, Y, X, 3)],
            STATUS_CONFIRMED,
        )
        payload = {"blocks": [b.to_dict() for b in (genesis, fb1, fb2)]}
        status, body = self.svc.submit_fork_candidate(payload)
        self.assertEqual(status, 201, body)
        status, adopted = self.svc.adopt_fork(fb2.block_hash)
        self.assertEqual(status, 200, adopted)
        # A is absent on the adopted fork at height 1; its old-chain absence
        # document is stale and must not verify against the new anchor.
        new1 = self.state("1")
        self.assertNotEqual(new1, old1)
        status, doc = self.svc.get_account_absence_proof(
            self.A, {"height": "1"}
        )
        self.assertEqual(status, 200, doc)
        self.assertTrue(
            crypto.verify_account_absence_proof(doc, self.A, new1)
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, self.A, old1)
        )
        status, body = self.svc.get_account_absence_proof(X, {"height": "1"})
        self.assertEqual(status, 409, body)


def _fork_block_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int):
    from ledger.models import Transaction

    msg = crypto.canonical_message(sender, to, amount)
    return Transaction(sender, to, amount, key.sign(msg).hex())


class AbsenceCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        path = os.path.join(self.tmp, "crypto.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(LedgerStore(path), initial_balance=100_000)

    def _build(self, n: int = 3) -> tuple[dict, dict, str]:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        self.svc.mine_block()
        self.svc.confirm_block("1")
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.C, 1))
        self.svc.mine_block()
        self.svc.confirm_block("2")
        anchor = self.svc.get_state_root()[1]
        names = sorted((self.A, self.B, self.C))
        target = names[1] if n < 3 else names[1] + "00"
        doc = self.svc.get_account_absence_proof(target)[1]
        return doc, anchor, target

    def _empty_doc(self) -> tuple[dict, dict, str]:
        anchor = self.svc.get_state_root("0")[1]
        doc = self.svc.get_account_absence_proof(
            "ghost", {"height": "0"}
        )[1]
        return doc, anchor, "ghost"

    def test_valid_documents_verify(self) -> None:
        doc, anchor, target = self._build()
        self.assertTrue(
            crypto.verify_account_absence_proof(doc, target, anchor)
        )
        doc0, anchor0, target0 = self._empty_doc()
        self.assertTrue(
            crypto.verify_account_absence_proof(doc0, target0, anchor0)
        )
        # Boundary documents.
        before = self.svc.get_account_absence_proof("!")[1]
        self.assertTrue(
            crypto.verify_account_absence_proof(before, "!", anchor)
        )
        after = self.svc.get_account_absence_proof("z" * 64)[1]
        self.assertTrue(
            crypto.verify_account_absence_proof(after, "z" * 64, anchor)
        )

    def test_key_order_does_not_matter(self) -> None:
        doc, anchor, target = self._build()
        reordered = {
            "upper": doc["upper"],
            "account": doc["account"],
            "state": doc["state"],
            "lower": doc["lower"],
        }
        self.assertTrue(
            crypto.verify_account_absence_proof(reordered, target, anchor)
        )
        reordered_state = dict(doc)
        reordered_state["state"] = {
            "account_count": anchor["account_count"],
            "state_root": anchor["state_root"],
            "block_hash": anchor["block_hash"],
            "height": anchor["height"],
        }
        self.assertTrue(
            crypto.verify_account_absence_proof(
                reordered_state, target, anchor
            )
        )

    def test_missing_or_extra_top_level_keys(self) -> None:
        doc, anchor, target = self._build()
        for key in ("account", "state", "lower", "upper"):
            partial = dict(doc)
            del partial[key]
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    partial, target, anchor
                )
            )
        extra = dict(doc)
        extra["unexpected"] = 1
        self.assertFalse(
            crypto.verify_account_absence_proof(extra, target, anchor)
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(
                [doc], target, anchor
            )
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(
                json.dumps(doc), target, anchor
            )
        )

    def test_pinned_account_mismatch(self) -> None:
        doc, anchor, target = self._build()
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, "other", anchor)
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, "", anchor)
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, None, anchor)
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, 7, anchor)
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, True, anchor)
        )
        renamed = dict(doc)
        renamed["account"] = "other"
        self.assertFalse(
            crypto.verify_account_absence_proof(renamed, target, anchor)
        )

    def test_expected_state_mismatch_and_shapes(self) -> None:
        doc, anchor, target = self._build()
        # A missing/extra/typed-wrong pinned anchor is itself invalid.
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, target, None)
        )
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, target, "anchor")
        )
        for key in ("state_root", "height", "block_hash", "account_count"):
            partial = dict(anchor)
            del partial[key]
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    doc, target, partial
                )
            )
            wrong = dict(anchor)
            wrong[key] = None
            self.assertFalse(
                crypto.verify_account_absence_proof(doc, target, wrong)
            )
        extra = dict(anchor)
        extra["more"] = 0
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, target, extra)
        )
        # Tampered anchor values fail, including booleans-as-numbers.
        for key, value in (
            ("state_root", "0" * 64),
            ("height", anchor["height"] + 1),
            ("block_hash", "0" * 64),
            ("account_count", anchor["account_count"] + 1),
        ):
            wrong = dict(anchor)
            wrong[key] = value
            self.assertFalse(
                crypto.verify_account_absence_proof(doc, target, wrong),
                key,
            )
        for key in ("height", "account_count"):
            wrong = dict(anchor)
            wrong[key] = True
            self.assertFalse(
                crypto.verify_account_absence_proof(doc, target, wrong),
                key,
            )
            wrong = dict(anchor)
            wrong[key] = -1
            self.assertFalse(
                crypto.verify_account_absence_proof(doc, target, wrong),
                key,
            )
        bad_root = dict(anchor)
        bad_root["state_root"] = "ZZ" + "0" * 62
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, target, bad_root)
        )

    def test_embedded_state_must_match_pin(self) -> None:
        doc, anchor, target = self._build()
        embedded = dict(doc)
        embedded["state"] = dict(anchor)
        embedded["state"]["height"] = anchor["height"] + 1
        self.assertFalse(
            crypto.verify_account_absence_proof(embedded, target, anchor)
        )
        # The embedded document keeps its old anchor while the caller pins a
        # different one: mixed anchors never verify.
        other = self.svc.get_state_root("1")[1]
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, target, other)
        )

    def test_neighbor_tampering(self) -> None:
        doc, anchor, target = self._build()
        side = "lower"
        for key, value in (
            ("account", "renamed"),
            ("balance", doc[side]["balance"] + 1),
            ("index", 0),
            ("state_root", "0" * 64),
            ("height", anchor["height"] + 1),
            ("block_hash", "0" * 64),
        ):
            tampered = json.loads(json.dumps(doc))
            tampered[side][key] = value
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                ),
                key,
            )
        # A reordered transaction list changes the recomputed leaf.
        tampered = json.loads(json.dumps(doc))
        txs = tampered[side]["confirmed_transactions"]
        if len(txs) >= 2:
            txs[0], txs[1] = txs[1], txs[0]
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                )
            )
        # Any altered sibling hash breaks the Merkle path.
        tampered = json.loads(json.dumps(doc))
        tampered["upper"]["siblings"][0]["hash"] = "f" * 64
        self.assertFalse(
            crypto.verify_account_absence_proof(
                tampered, target, anchor
            )
        )
        tampered = json.loads(json.dumps(doc))
        tampered["upper"]["siblings"][0]["direction"] = "left"
        self.assertFalse(
            crypto.verify_account_absence_proof(
                tampered, target, anchor
            )
        )

    def test_neighbor_extra_and_missing_keys(self) -> None:
        doc, anchor, target = self._build()
        for side in ("lower", "upper"):
            tampered = json.loads(json.dumps(doc))
            tampered[side]["extra"] = True
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                )
            )
            tampered = json.loads(json.dumps(doc))
            del tampered[side]["balance"]
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                )
            )
            tampered = json.loads(json.dumps(doc))
            tampered[side]["siblings"][0]["side"] = "right"
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                )
            )
            tampered = json.loads(json.dumps(doc))
            del tampered[side]["siblings"][0]["hash"]
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                )
            )
            tampered = json.loads(json.dumps(doc))
            tampered[side]["index"] = 1.0
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                )
            )
            tampered = json.loads(json.dumps(doc))
            tampered[side]["balance"] = True
            self.assertFalse(
                crypto.verify_account_absence_proof(
                    tampered, target, anchor
                )
            )

    def test_non_adjacent_and_boundary_violations(self) -> None:
        doc, anchor, target = self._build()
        names = sorted((self.A, self.B, self.C))
        # Two individually-valid inclusion proofs at non-adjacent indices.
        p0 = self.svc.get_account_proof(names[0])[1]
        p2 = self.svc.get_account_proof(names[2])[1]
        between = names[1] + "00"
        forged = {"account": between, "state": anchor, "lower": p0,
                  "upper": p2}
        self.assertFalse(
            crypto.verify_account_absence_proof(forged, between, anchor)
        )
        # A boundary side pointing at the wrong index.
        before_doc = self.svc.get_account_absence_proof("!")[1]
        tampered = json.loads(json.dumps(before_doc))
        tampered["upper"] = p2
        self.assertFalse(
            crypto.verify_account_absence_proof(tampered, "!", anchor)
        )
        after_doc = self.svc.get_account_absence_proof("z" * 64)[1]
        tampered = json.loads(json.dumps(after_doc))
        tampered["lower"] = p0
        self.assertFalse(
            crypto.verify_account_absence_proof(tampered, "z" * 64, anchor)
        )
        # Both neighbors null while account_count is positive.
        tampered = json.loads(json.dumps(doc))
        tampered["lower"] = None
        tampered["upper"] = None
        self.assertFalse(
            crypto.verify_account_absence_proof(
                tampered, target, anchor
            )
        )
        # Wrong framing order: an alleged lower neighbor that actually
        # sorts after the target fails the strict name comparison.
        p1 = self.svc.get_account_proof(names[1])[1]
        swapped = {"account": "!", "state": anchor, "lower": p1,
                   "upper": p2}
        self.assertFalse(
            crypto.verify_account_absence_proof(
                swapped, "!", anchor
            )
        )
        # An alleged upper neighbor sorting before the target fails too.
        swapped = {"account": "z" * 64, "state": anchor, "lower": p0,
                   "upper": p1}
        self.assertFalse(
            crypto.verify_account_absence_proof(
                swapped, "z" * 64, anchor
            )
        )
        # Target equal to a neighbor name is not absent between them.
        equal = {"account": names[1], "state": anchor, "lower": p0,
                 "upper": p2}
        self.assertFalse(
            crypto.verify_account_absence_proof(
                equal, names[1], anchor
            )
        )

    def test_phantom_sibling_slot_rejected(self) -> None:
        # A fabricated lower proof that walks into the odd-node duplicate slot
        # (left sibling equal to the current node) cannot frame a target.
        doc, anchor, target = self._build()
        self.assertEqual(anchor["account_count"], 3)
        # 3 leaves: the last leaf (index 2) has a right self-pair sibling at
        # the first level. Flip the claimed direction of that identical
        # sibling to "left" to address the phantom duplicate slot.
        after_doc = self.svc.get_account_absence_proof("z" * 64)[1]
        last = json.loads(json.dumps(after_doc["lower"]))
        self.assertEqual(last["index"], 2)
        self.assertEqual(last["siblings"][0]["direction"], "right")
        leaf = crypto.account_state_leaf(
            last["account"],
            last["balance"],
            last["confirmed_transactions"],
        )
        self.assertEqual(last["siblings"][0]["hash"], leaf)
        last["siblings"][0]["direction"] = "left"
        forged = {"account": "z" * 64, "state": anchor, "lower": last,
                  "upper": None}
        self.assertFalse(
            crypto.verify_account_absence_proof(forged, target, anchor)
        )

    def test_empty_tree_root_enforced(self) -> None:
        doc0, anchor0, target0 = self._empty_doc()
        tampered = json.loads(json.dumps(doc0))
        tampered["state"]["state_root"] = "0" * 64
        bad_anchor = dict(anchor0)
        bad_anchor["state_root"] = "0" * 64
        self.assertFalse(
            crypto.verify_account_absence_proof(
                tampered, target0, bad_anchor
            )
        )
        # Claiming neighbors inside a zero-count anchor fails.
        doc, anchor, target = self._build()
        zero = dict(anchor)
        zero["account_count"] = 0
        self.assertFalse(
            crypto.verify_account_absence_proof(doc, target, zero)
        )

    def test_never_raises(self) -> None:
        doc, anchor, target = self._build()
        weird = [
            None, True, 0, 1.5, float("nan"), [], {}, object(),
            {"account": None},
            {"account": target, "state": None, "lower": [], "upper": {}},
            {"account": target, "state": anchor, "lower": 7, "upper": None},
            {"account": target, "state": anchor,
             "lower": {"siblings": None}, "upper": None},
        ]
        for value in weird:
            try:
                result = crypto.verify_account_absence_proof(
                    value, target, anchor
                )
            except Exception as exc:  # pragma: no cover - contract failure
                raise AssertionError((value, exc))
            self.assertFalse(result, value)
        # Weird pinned values likewise return False.
        for value in (None, True, 5, [], "x"):
            self.assertFalse(
                crypto.verify_account_absence_proof(doc, target, value)
            )


class AbsenceHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")),
            initial_balance=100_000,
        )
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 10))
        status, blk = cls.service.mine_block()
        assert status == 201
        assert cls.service.confirm_block(blk["height"])[0] == 200
        cls.service.submit_transaction(make_tx(cls.kb, cls.B, cls.C, 2))
        status, blk = cls.service.mine_block()
        assert status == 201
        assert cls.service.confirm_block(blk["height"])[0] == 200
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(
            target=cls.httpd.serve_forever, daemon=True
        )
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()

    def get(self, path: str):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    def raw(self, path: str):
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}{path}"
            ) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode()

    def test_wire_shapes_and_verification(self) -> None:
        status, anchor = self.get("/v1/state/root")
        self.assertEqual(status, 200)
        names = sorted((self.A, self.B, self.C))
        target = names[1] + "00"
        status, body = self.get(
            f"/v1/accounts/{target}/absence-proof"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body), ["account", "state", "lower", "upper"]
        )
        self.assertEqual(
            list(body["state"]),
            ["state_root", "height", "block_hash", "account_count"],
        )
        for side in ("lower", "upper"):
            self.assertEqual(
                list(body[side]),
                [
                    "account",
                    "balance",
                    "confirmed_transactions",
                    "index",
                    "state_root",
                    "height",
                    "block_hash",
                    "siblings",
                ],
            )
        self.assertTrue(
            crypto.verify_account_absence_proof(body, target, anchor)
        )

    def test_http_status_matrix(self) -> None:
        cases_400 = (
            "/v1/accounts/ghost/absence-proof?height=00",
            "/v1/accounts/ghost/absence-proof?height=-1",
            "/v1/accounts/ghost/absence-proof?height=1%20",
            "/v1/accounts/ghost/absence-proof?foo=1",
            "/v1/accounts/ghost/absence-proof?height=1&height=2",
        )
        for path in cases_400:
            status, body = self.get(path)
            self.assertEqual(status, 400, path)
            self.assertIn("error", body)
        status, body = self.get(
            "/v1/accounts/ghost/absence-proof?height=999"
        )
        self.assertEqual(status, 404, body)
        status, body = self.get(f"/v1/accounts/{self.A}/absence-proof")
        self.assertEqual(status, 409, body)
        status, body = self.get("/v1/accounts//absence-proof")
        self.assertEqual(status, 404, body)
        # An encoded empty-ish account is still a non-empty target name.
        status, body = self.get("/v1/accounts/%20/absence-proof")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["account"], " ")
        self.assertIsNone(body["lower"])

    def test_http_historical_and_pending(self) -> None:
        status, anchor = self.get("/v1/state/root/0")
        self.assertEqual(status, 200)
        status, body = self.get(
            "/v1/accounts/ghost/absence-proof?height=0"
        )
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["lower"])
        self.assertIsNone(body["upper"])
        self.assertTrue(
            crypto.verify_account_absence_proof(body, "ghost", anchor)
        )
        # Mine a pending block: default view 404, historical still 200.
        self.service.submit_transaction(
            make_tx(self.kc, self.C, self.A, 1)
        )
        status, pending = self.service.mine_block()
        self.assertEqual(status, 201, pending)
        try:
            status, body = self.get(
                "/v1/accounts/ghost/absence-proof"
            )
            self.assertEqual(status, 404, body)
            status, body = self.get(
                f"/v1/accounts/ghost/absence-proof?height={pending['height']}"
            )
            self.assertEqual(status, 404, body)
            status, body = self.get(
                "/v1/accounts/ghost/absence-proof?height=0"
            )
            self.assertEqual(status, 200, body)
        finally:
            self.service.rollback_block(pending["height"])

    def test_encoded_account_preserved(self) -> None:
        status, body = self.get(
            "/v1/accounts/a%2Fb%2Fc/absence-proof?height=1"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["account"], "a/b/c")
        status, anchor = self.get("/v1/state/root/1")
        self.assertEqual(status, 200)
        self.assertTrue(
            crypto.verify_account_absence_proof(
                body, "a/b/c", anchor
            )
        )

    def test_existing_endpoints_unchanged(self) -> None:
        status, proof = self.get(f"/v1/accounts/{self.A}/proof")
        self.assertEqual(status, 200, proof)
        status, root = self.get("/v1/state/root")
        self.assertEqual(status, 200, root)
        self.assertTrue(
            crypto.verify_account_proof(
                proof,
                root["state_root"],
                root["height"],
                root["block_hash"],
            )
        )
        status, account = self.get(f"/v1/accounts/{self.A}")
        self.assertEqual(status, 200, account)


class AbsenceConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        path = os.path.join(self.tmp, "concurrent.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(path), initial_balance=100_000
        )

    def send(self, key, sender, to, amount) -> None:
        status, body = self.svc.submit_transaction(
            make_tx(key, sender, to, amount)
        )
        self.assertEqual(status, 202, body)

    def mine_and_confirm(self) -> None:
        status, blk = self.svc.mine_block()
        self.assertEqual(status, 201, blk)
        status, body = self.svc.confirm_block(blk["height"])
        self.assertEqual(status, 200, body)

    def test_concurrent_absence_reads_are_consistent(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        _, frozen = self.svc.get_state_root("1")
        errors: list[Exception] = []

        def reader() -> None:
            try:
                for _ in range(200):
                    status, doc = self.svc.get_account_absence_proof(
                        self.C, {"height": "1"}
                    )
                    if status != 200:
                        errors.append(AssertionError(status))
                    elif not crypto.verify_account_absence_proof(
                        doc, self.C, frozen
                    ):
                        errors.append(AssertionError("document fails"))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        self.send(self.kb, self.B, self.A, 9)
        self.mine_and_confirm()
        self.send(self.kc, self.C, self.A, 1)
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201)
        self.svc.rollback_block(pending["height"])
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()

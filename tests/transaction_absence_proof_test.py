"""Tests for transaction-absence (non-inclusion) proofs.

Covers:

* service GET /v1/blocks/{height}/absence-proof/{tx_id} and
  crypto.verify_transaction_absence_proof: empty-block documents,
  predecessor/successor framing with strict ordering and adjacent indices,
  boundary documents (before the first / after the last transaction);
* the strict status matrix (query parameter 400, malformed/unknown height
  404, malformed tx_id 404, pending block 409, present target 409);
* the pure-library verifier: exact field/type/format rules, anchor pinning,
  neighbor inclusion paths, adjacency and boundary rules, the empty-tree
  root, tampering, phantom self-pair slots and excessive depth all
  returning False without raising;
* HTTP wire behavior (fixed key order), read-only semantics, restart
  determinism and the CLI absence-proof command.

Run: python3 tests/transaction_absence_proof_test.py
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
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import cli, crypto
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


class TxAbsenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "absence.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
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

    def leaves(self, height: int) -> list[str]:
        return [tx.tx_id for tx in self.svc.store.chain[height].transactions]

    def test_empty_block_at_genesis(self) -> None:
        target = "0" * 64
        status, doc = self.svc.get_transaction_absence_proof("0", target)
        self.assertEqual(status, 200, doc)
        self.assertEqual(
            list(doc),
            [
                "height",
                "tx_id",
                "transaction_count",
                "merkle_root",
                "block_hash",
                "lower",
                "upper",
            ],
        )
        self.assertEqual(doc["height"], 0)
        self.assertEqual(doc["tx_id"], target)
        self.assertEqual(doc["transaction_count"], 0)
        self.assertEqual(doc["merkle_root"], crypto.EMPTY_MERKLE_ROOT)
        self.assertIsNone(doc["lower"])
        self.assertIsNone(doc["upper"])
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                doc, target, 0, doc["block_hash"], doc["merkle_root"]
            )
        )

    def test_between_two_neighbors(self) -> None:
        for key, sender, to, amount in (
            (self.ka, self.A, self.B, 10),
            (self.kb, self.B, self.C, 5),
            (self.kc, self.C, self.A, 3),
        ):
            self.send(key, sender, to, amount)
        block = self.mine_and_confirm()
        height = block["height"]
        tx_ids = self.leaves(height)
        self.assertEqual(tx_ids, sorted(tx_ids))
        for i in range(len(tx_ids) - 1):
            # A hex id strictly between two neighbors: bump the last nibble
            # of the smaller id downward/upward as needed.
            candidate = tx_ids[i][:-1] + (
                "0" if tx_ids[i][-1] != "0" else "1"
            )
            if not tx_ids[i] < candidate < tx_ids[i + 1]:
                candidate = tx_ids[i + 1][:-1] + (
                    "0" if tx_ids[i + 1][-1] != "0" else "1"
                )
            self.assertLess(tx_ids[i], candidate)
            self.assertLess(candidate, tx_ids[i + 1])
            status, doc = self.svc.get_transaction_absence_proof(
                str(height), candidate
            )
            self.assertEqual(status, 200, doc)
            self.assertEqual(doc["transaction_count"], len(tx_ids))
            self.assertEqual(doc["lower"]["tx_id"], tx_ids[i])
            self.assertEqual(doc["upper"]["tx_id"], tx_ids[i + 1])
            self.assertEqual(doc["lower"]["index"], i)
            self.assertEqual(doc["upper"]["index"], i + 1)
            self.assertEqual(list(doc["lower"]), ["tx_id", "index", "siblings"])
            self.assertEqual(list(doc["upper"]), ["tx_id", "index", "siblings"])
            self.assertTrue(
                crypto.verify_transaction_absence_proof(
                    doc,
                    candidate,
                    height,
                    doc["block_hash"],
                    doc["merkle_root"],
                )
            )

    def test_boundary_before_first_and_after_last(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.send(self.kb, self.B, self.C, 5)
        block = self.mine_and_confirm()
        height = block["height"]
        tx_ids = self.leaves(height)
        before = "00" * 32
        self.assertLess(before, tx_ids[0])
        status, doc = self.svc.get_transaction_absence_proof(str(height), before)
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["lower"])
        self.assertEqual(doc["upper"]["index"], 0)
        self.assertEqual(doc["upper"]["tx_id"], tx_ids[0])
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                doc, before, height, doc["block_hash"], doc["merkle_root"]
            )
        )
        after = "ff" * 32
        self.assertGreater(after, tx_ids[-1])
        status, doc = self.svc.get_transaction_absence_proof(str(height), after)
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["upper"])
        self.assertEqual(doc["lower"]["index"], len(tx_ids) - 1)
        self.assertEqual(doc["lower"]["tx_id"], tx_ids[-1])
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                doc, after, height, doc["block_hash"], doc["merkle_root"]
            )
        )

    def test_status_matrix(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        block = self.mine_and_confirm()
        height = block["height"]
        present = self.leaves(height)[0]
        absent = "0" * 64
        # Any query parameter is 400 {"error":"input"}.
        status, body = self.svc.get_transaction_absence_proof(
            str(height), absent, {"foo": "1"}
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # Malformed or unknown heights are 404 block_not_found.
        for bad in ("-1", "00", "01", "1.0", " 1", "1 ", "0x1", "", "999"):
            status, body = self.svc.get_transaction_absence_proof(bad, absent)
            self.assertEqual(
                (status, body), (404, {"error": "block_not_found"}), bad
            )
        # Malformed tx_ids are 404 transaction_not_found.
        for bad in ("zz", "A" * 64, "0" * 63, "0" * 65, "", 5, None):
            status, body = self.svc.get_transaction_absence_proof(
                str(height), bad
            )
            self.assertEqual(
                (status, body), (404, {"error": "transaction_not_found"}), bad
            )
        # A present target is 409 transaction_present.
        status, body = self.svc.get_transaction_absence_proof(
            str(height), present
        )
        self.assertEqual((status, body), (409, {"error": "transaction_present"}))

    def test_pending_block_is_409(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201, pending)
        status, body = self.svc.get_transaction_absence_proof(
            str(pending["height"]), "0" * 64
        )
        self.assertEqual((status, body), (409, {"error": "block_pending"}))
        # The confirmed prefix stays readable.
        status, doc = self.svc.get_transaction_absence_proof("0", "0" * 64)
        self.assertEqual(status, 200, doc)

    def test_query_is_read_only(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        block = self.mine_and_confirm()
        store = self.svc.store
        snapshot = (
            store.generation,
            len(store.audit_events),
            len(store.chain),
            len(store.pending),
        )
        for _ in range(5):
            self.svc.get_transaction_absence_proof(str(block["height"]), "0" * 64)
            self.svc.get_transaction_absence_proof("0", "1" * 64)
            self.svc.get_transaction_absence_proof(
                str(block["height"]), self.leaves(block["height"])[0]
            )
        self.assertEqual(
            (
                store.generation,
                len(store.audit_events),
                len(store.chain),
                len(store.pending),
            ),
            snapshot,
        )

    def test_restart_keeps_absence_documents(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        block = self.mine_and_confirm()
        target = "0" * 64
        status, first = self.svc.get_transaction_absence_proof(
            str(block["height"]), target
        )
        self.assertEqual(status, 200)
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
        )
        status, second = reopened.get_transaction_absence_proof(
            str(block["height"]), target
        )
        self.assertEqual(status, 200)
        self.assertEqual(first, second)


class TxAbsenceCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "crypto.json")),
            initial_balance=100_000,
        )
        for key, sender, to, amount in (
            (self.ka, self.A, self.B, 10),
            (self.kb, self.B, self.C, 5),
            (self.kc, self.C, self.A, 3),
        ):
            self.svc.submit_transaction(make_tx(key, sender, to, amount))
        status, block = self.svc.mine_block()
        assert status == 201
        self.svc.confirm_block(block["height"])
        self.height = block["height"]
        self.tx_ids = [tx.tx_id for tx in self.svc.store.chain[self.height].transactions]
        self.assertEqual(len(self.tx_ids), 3)
        # A target strictly between the first two leaves.
        self.target = self.tx_ids[0][:-1] + (
            "0" if self.tx_ids[0][-1] != "0" else "1"
        )
        if not self.tx_ids[0] < self.target < self.tx_ids[1]:
            self.target = self.tx_ids[1][:-1] + (
                "0" if self.tx_ids[1][-1] != "0" else "1"
            )
        status, doc = self.svc.get_transaction_absence_proof(
            str(self.height), self.target
        )
        assert status == 200
        self.doc = doc
        self.root = doc["merkle_root"]
        self.hash = doc["block_hash"]

    _UNSET = object()

    def verify(self, doc, target=_UNSET, height=_UNSET, block_hash=_UNSET, root=_UNSET):
        return crypto.verify_transaction_absence_proof(
            doc,
            self.target if target is self._UNSET else target,
            self.height if height is self._UNSET else height,
            self.hash if block_hash is self._UNSET else block_hash,
            self.root if root is self._UNSET else root,
        )

    def test_valid_documents_verify(self) -> None:
        self.assertTrue(self.verify(self.doc))
        for target in ("00" * 32, "ff" * 32):
            doc = self.svc.get_transaction_absence_proof(
                str(self.height), target
            )[1]
            self.assertTrue(self.verify(doc, target=target))
        empty = self.svc.get_transaction_absence_proof("0", "0" * 64)[1]
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                empty, "0" * 64, 0, empty["block_hash"], empty["merkle_root"]
            )
        )

    def test_key_order_does_not_matter(self) -> None:
        reordered = {
            key: self.doc[key]
            for key in (
                "upper",
                "lower",
                "block_hash",
                "merkle_root",
                "transaction_count",
                "tx_id",
                "height",
            )
        }
        self.assertTrue(self.verify(reordered))

    def test_missing_or_extra_keys(self) -> None:
        for key in (
            "height",
            "tx_id",
            "transaction_count",
            "merkle_root",
            "block_hash",
            "lower",
            "upper",
        ):
            partial = dict(self.doc)
            del partial[key]
            self.assertFalse(self.verify(partial), key)
        extra = dict(self.doc)
        extra["unexpected"] = 1
        self.assertFalse(self.verify(extra))
        self.assertFalse(self.verify([self.doc]))
        self.assertFalse(self.verify(json.dumps(self.doc)))

    def test_anchor_pinning(self) -> None:
        self.assertFalse(self.verify(self.doc, target="1" * 64))
        self.assertFalse(self.verify(self.doc, height=self.height + 1))
        self.assertFalse(self.verify(self.doc, block_hash="0" * 64))
        self.assertFalse(self.verify(self.doc, root="0" * 64))
        for weird in (None, True, 5, [], "x"):
            self.assertFalse(self.verify(self.doc, target=weird))
            self.assertFalse(self.verify(self.doc, height=weird))
            self.assertFalse(self.verify(self.doc, block_hash=weird))
            self.assertFalse(self.verify(self.doc, root=weird))
        for key, value in (
            ("tx_id", "1" * 64),
            ("height", self.height + 1),
            ("height", True),
            ("transaction_count", True),
            ("transaction_count", -1),
            ("transaction_count", 1.0),
            ("merkle_root", "0" * 64),
            ("block_hash", "0" * 64),
        ):
            tampered = copy.deepcopy(self.doc)
            tampered[key] = value
            self.assertFalse(self.verify(tampered), (key, value))

    def test_transaction_count_boundaries(self) -> None:
        # A count too small to contain the neighbor indices fails, and so
        # does a count whose tree depth differs from the path length.
        for count in (1, 2, 10):
            tampered = copy.deepcopy(self.doc)
            tampered["transaction_count"] = count
            self.assertFalse(self.verify(tampered), count)
        # Claiming neighbors inside a zero-count document fails.
        tampered = copy.deepcopy(self.doc)
        tampered["transaction_count"] = 0
        self.assertFalse(self.verify(tampered))

    def test_neighbor_tampering(self) -> None:
        for side in ("lower", "upper"):
            for key, value in (
                ("tx_id", "1" * 64),
                ("index", 7),
                ("index", True),
                ("index", 1.0),
            ):
                tampered = copy.deepcopy(self.doc)
                tampered[side][key] = value
                self.assertFalse(self.verify(tampered), (side, key))
            tampered = copy.deepcopy(self.doc)
            tampered[side]["extra"] = True
            self.assertFalse(self.verify(tampered), side)
            tampered = copy.deepcopy(self.doc)
            del tampered[side]["index"]
            self.assertFalse(self.verify(tampered), side)
            tampered = copy.deepcopy(self.doc)
            tampered[side]["siblings"][0]["hash"] = "f" * 64
            self.assertFalse(self.verify(tampered), side)
            tampered = copy.deepcopy(self.doc)
            tampered[side]["siblings"][0]["side"] = "right"
            self.assertFalse(self.verify(tampered), side)
            tampered = copy.deepcopy(self.doc)
            del tampered[side]["siblings"][0]["hash"]
            self.assertFalse(self.verify(tampered), side)
            # A deeper-than-possible path is rejected.
            tampered = copy.deepcopy(self.doc)
            tampered[side]["siblings"].append(
                {"direction": "right", "hash": "0" * 64}
            )
            self.assertFalse(self.verify(tampered), side)

    def test_framing_violations(self) -> None:
        # Swapped neighbors fail the strict ordering.
        tampered = copy.deepcopy(self.doc)
        tampered["lower"], tampered["upper"] = (
            self.doc["upper"],
            self.doc["lower"],
        )
        self.assertFalse(self.verify(tampered))
        # Non-adjacent indices: genuine proofs of leaf 0 and leaf 2 cannot
        # frame a target between leaf 0 and leaf 1.
        p0 = {
            "tx_id": self.tx_ids[0],
            "index": 0,
            "siblings": crypto.merkle_proof(self.tx_ids, 0),
        }
        p2 = {
            "tx_id": self.tx_ids[2],
            "index": 2,
            "siblings": crypto.merkle_proof(self.tx_ids, 2),
        }
        forged = dict(self.doc)
        forged["lower"], forged["upper"] = p0, p2
        self.assertFalse(self.verify(forged))
        # Both neighbors null in a non-empty block.
        tampered = copy.deepcopy(self.doc)
        tampered["lower"] = None
        tampered["upper"] = None
        self.assertFalse(self.verify(tampered))
        # A boundary side pointing at the wrong index.
        after = self.svc.get_transaction_absence_proof(
            str(self.height), "ff" * 32
        )[1]
        tampered = copy.deepcopy(after)
        tampered["lower"] = p0
        self.assertFalse(self.verify(tampered, target="ff" * 32))
        before = self.svc.get_transaction_absence_proof(
            str(self.height), "00" * 32
        )[1]
        tampered = copy.deepcopy(before)
        tampered["upper"] = p2
        self.assertFalse(self.verify(tampered, target="00" * 32))
        # Target equal to a neighbor id is not absent.
        equal = dict(self.doc)
        equal["tx_id"] = self.tx_ids[1]
        self.assertFalse(self.verify(equal, target=self.tx_ids[1]))

    def test_phantom_sibling_slot_rejected(self) -> None:
        # The last leaf of a 3-leaf tree self-pairs at the first level: its
        # right sibling equals the leaf itself. Flipping that sibling to
        # "left" addresses the phantom duplicate slot and must fail.
        after = self.svc.get_transaction_absence_proof(
            str(self.height), "ff" * 32
        )[1]
        last = after["lower"]
        self.assertEqual(last["index"], 2)
        self.assertEqual(last["siblings"][0]["direction"], "right")
        self.assertEqual(last["siblings"][0]["hash"], self.tx_ids[2])
        forged = copy.deepcopy(after)
        forged["lower"]["siblings"][0]["direction"] = "left"
        self.assertFalse(self.verify(forged, target="ff" * 32))

    def test_empty_tree_root_enforced(self) -> None:
        empty = self.svc.get_transaction_absence_proof("0", "0" * 64)[1]
        tampered = copy.deepcopy(empty)
        tampered["merkle_root"] = "0" * 64
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, "0" * 64, 0, tampered["block_hash"], "0" * 64
            )
        )
        tampered = copy.deepcopy(empty)
        tampered["lower"] = {
            "tx_id": "1" * 64,
            "index": 0,
            "siblings": [],
        }
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, "0" * 64, 0, tampered["block_hash"],
                tampered["merkle_root"],
            )
        )

    def test_never_raises(self) -> None:
        weird = [
            None,
            True,
            0,
            1.5,
            float("nan"),
            [],
            {},
            object(),
            {"tx_id": None},
            {
                "height": self.height,
                "tx_id": self.target,
                "transaction_count": 3,
                "merkle_root": self.root,
                "block_hash": self.hash,
                "lower": 7,
                "upper": None,
            },
        ]
        for value in weird:
            try:
                result = self.verify(value)
            except Exception as exc:  # pragma: no cover - contract failure
                raise AssertionError((value, exc))
            self.assertFalse(result, value)


class TxAbsenceHttpTests(unittest.TestCase):
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
        for key, sender, to, amount in (
            (cls.ka, cls.A, cls.B, 10),
            (cls.kb, cls.B, cls.C, 5),
            (cls.kc, cls.C, cls.A, 3),
        ):
            cls.service.submit_transaction(make_tx(key, sender, to, amount))
        status, blk = cls.service.mine_block()
        assert status == 201
        assert cls.service.confirm_block(blk["height"])[0] == 200
        cls.height = blk["height"]
        cls.tx_ids = [
            tx.tx_id for tx in cls.service.store.chain[cls.height].transactions
        ]
        cls.target = cls.tx_ids[0][:-1] + (
            "0" if cls.tx_ids[0][-1] != "0" else "1"
        )
        if not cls.tx_ids[0] < cls.target < cls.tx_ids[1]:
            cls.target = cls.tx_ids[1][:-1] + (
                "0" if cls.tx_ids[1][-1] != "0" else "1"
            )
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
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    def test_wire_shape_and_verification(self) -> None:
        status, body = self.get(
            f"/v1/blocks/{self.height}/absence-proof/{self.target}"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body),
            [
                "height",
                "tx_id",
                "transaction_count",
                "merkle_root",
                "block_hash",
                "lower",
                "upper",
            ],
        )
        for side in ("lower", "upper"):
            self.assertEqual(list(body[side]), ["tx_id", "index", "siblings"])
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                body,
                self.target,
                self.height,
                body["block_hash"],
                body["merkle_root"],
            )
        )

    def test_http_status_matrix(self) -> None:
        for path in (
            f"/v1/blocks/{self.height}/absence-proof/{self.target}?foo=1",
            f"/v1/blocks/{self.height}/absence-proof/{self.target}?height=1",
            f"/v1/blocks/{self.height}/absence-proof/{self.target}?height=1&height=2",
        ):
            status, body = self.get(path)
            self.assertEqual((status, body), (400, {"error": "input"}), path)
        for path in (
            f"/v1/blocks/00/absence-proof/{self.target}",
            f"/v1/blocks/-1/absence-proof/{self.target}",
            f"/v1/blocks/999/absence-proof/{self.target}",
        ):
            status, body = self.get(path)
            self.assertEqual(
                (status, body), (404, {"error": "block_not_found"}), path
            )
        status, body = self.get(f"/v1/blocks/{self.height}/absence-proof/zz")
        self.assertEqual(
            (status, body), (404, {"error": "transaction_not_found"})
        )
        status, body = self.get(
            f"/v1/blocks/{self.height}/absence-proof/{self.tx_ids[0]}"
        )
        self.assertEqual(
            (status, body), (409, {"error": "transaction_present"})
        )

    def test_http_pending_block(self) -> None:
        self.service.submit_transaction(make_tx(self.ka, self.A, self.C, 1))
        status, pending = self.service.mine_block()
        self.assertEqual(status, 201, pending)
        try:
            status, body = self.get(
                f"/v1/blocks/{pending['height']}/absence-proof/{self.target}"
            )
            self.assertEqual(
                (status, body), (409, {"error": "block_pending"})
            )
            status, body = self.get(
                f"/v1/blocks/{self.height}/absence-proof/{self.target}"
            )
            self.assertEqual(status, 200, body)
        finally:
            self.service.rollback_block(pending["height"])

    def test_existing_endpoints_unchanged(self) -> None:
        status, proof = self.get(
            f"/v1/blocks/{self.height}/proof/{self.tx_ids[0]}"
        )
        self.assertEqual(status, 200, proof)
        self.assertTrue(
            crypto.verify_merkle_proof(
                proof["tx_id"],
                proof["siblings"],
                proof["merkle_root"],
                proof["block_hash"],
                proof["block_hash"],
            )
        )
        status, block = self.get(f"/v1/blocks/{self.height}")
        self.assertEqual(status, 200, block)

    def test_cli_absence_proof(self) -> None:
        base = f"http://127.0.0.1:{self.port}"
        buffer = io.StringIO()
        import contextlib

        with contextlib.redirect_stdout(buffer):
            rc = cli.main(
                [
                    "--base-url",
                    base,
                    "absence-proof",
                    str(self.height),
                    self.target,
                ]
            )
        self.assertEqual(rc, 0)
        out = json.loads(buffer.getvalue())
        self.assertEqual(
            list(out),
            [
                "height",
                "tx_id",
                "transaction_count",
                "merkle_root",
                "block_hash",
                "lower",
                "upper",
            ],
        )
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                out, self.target, self.height, out["block_hash"],
                out["merkle_root"],
            )
        )
        # Non-2xx responses exit 1 and print the error body.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = cli.main(
                [
                    "--base-url",
                    base,
                    "absence-proof",
                    str(self.height),
                    self.tx_ids[0],
                ]
            )
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(buffer.getvalue()), {"error": "transaction_present"}
        )
        # Connection failure exits 1.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = cli.main(
                [
                    "--base-url",
                    "http://127.0.0.1:1",
                    "absence-proof",
                    str(self.height),
                    self.target,
                ]
            )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

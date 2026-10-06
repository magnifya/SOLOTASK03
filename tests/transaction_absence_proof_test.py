"""Tests for transaction-absence (non-inclusion) proofs.

Covers:

* service GET /v1/blocks/{height}/absence-proof/{tx_id} and
  crypto.verify_transaction_absence_proof: empty-block documents,
  predecessor/successor framing with strict ordering and adjacent indices,
  boundary documents (before the first / after the last leaf), historical
  confirmed blocks;
* the status matrix: any query parameter 400 {"error":"input"}, malformed
  or unknown height 404 block_not_found, malformed tx_id 404
  transaction_not_found, pending block 409 block_pending, present target
  409 transaction_present;
* the pure-library verifier: exact field/type/format rules (booleans are
  not numbers, missing/extra keys fail regardless of key order), anchor
  pinning, neighbor inclusion paths replayed by index, adjacency and
  boundary rules, the empty-tree root, tampering, out-of-range indices,
  over-deep paths and odd-node phantom slots all returning False without
  raising;
* HTTP wire behavior (fixed key order), read-only semantics, restart
  persistence, and the absence-proof HEIGHT TX_ID CLI subcommand.

Run: python3 tests/transaction_absence_proof_test.py
"""
from __future__ import annotations

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
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

DOC_KEYS = [
    "height",
    "tx_id",
    "transaction_count",
    "merkle_root",
    "block_hash",
    "lower",
    "upper",
]
NEIGHBOR_KEYS = ["tx_id", "index", "siblings"]


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


def shifted(tx_id: str, delta: int) -> str:
    """A 64-hex id ``delta`` above the given one (mod 2**256)."""
    return f"{(int(tx_id, 16) + delta) % (1 << 256):064x}"


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

    def anchor(self, height: str) -> dict:
        status, body = self.svc.get_block(height)
        self.assertEqual(status, 200, body)
        return body

    def verify(self, doc: dict, target: str, height: int) -> bool:
        anchor = self.anchor(str(height))
        return crypto.verify_transaction_absence_proof(
            doc, target, height, anchor["block_hash"], anchor["merkle_root"]
        )

    def test_empty_block_at_genesis(self) -> None:
        ghost = "0" * 64
        status, doc = self.svc.get_transaction_absence_proof("0", ghost)
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), DOC_KEYS)
        self.assertEqual(doc["height"], 0)
        self.assertEqual(doc["tx_id"], ghost)
        self.assertEqual(doc["transaction_count"], 0)
        self.assertEqual(doc["merkle_root"], crypto.EMPTY_MERKLE_ROOT)
        self.assertIsNone(doc["lower"])
        self.assertIsNone(doc["upper"])
        self.assertTrue(self.verify(doc, ghost, 0))

    def test_between_two_neighbors(self) -> None:
        ids = [
            self.send(self.ka, self.A, self.B, 10),
            self.send(self.kb, self.B, self.C, 1),
            self.send(self.kc, self.C, self.A, 2),
        ]
        self.mine_and_confirm()
        ordered = sorted(ids)
        for i in range(len(ordered) - 1):
            target = shifted(ordered[i], 1)
            if target >= ordered[i + 1]:
                target = shifted(ordered[i + 1], -1)
            self.assertLess(ordered[i], target)
            self.assertLess(target, ordered[i + 1])
            status, doc = self.svc.get_transaction_absence_proof("1", target)
            self.assertEqual(status, 200, doc)
            self.assertEqual(doc["transaction_count"], 3)
            self.assertEqual(doc["lower"]["tx_id"], ordered[i])
            self.assertEqual(doc["upper"]["tx_id"], ordered[i + 1])
            self.assertEqual(doc["lower"]["index"], i)
            self.assertEqual(doc["upper"]["index"], i + 1)
            self.assertEqual(list(doc["lower"]), NEIGHBOR_KEYS)
            self.assertEqual(list(doc["upper"]), NEIGHBOR_KEYS)
            self.assertTrue(self.verify(doc, target, 1))

    def test_boundary_before_first_and_after_last(self) -> None:
        ids = [self.send(self.ka, self.A, self.B, 10),
               self.send(self.kb, self.B, self.C, 1)]
        self.mine_and_confirm()
        ordered = sorted(ids)
        before = shifted(ordered[0], -1)
        if before > ordered[0]:
            before = shifted(ordered[0], -2)
        status, doc = self.svc.get_transaction_absence_proof("1", before)
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["lower"])
        self.assertEqual(doc["upper"]["index"], 0)
        self.assertEqual(doc["upper"]["tx_id"], ordered[0])
        self.assertTrue(self.verify(doc, before, 1))
        after = shifted(ordered[-1], 1)
        if after < ordered[-1]:
            after = shifted(ordered[-1], 2)
        status, doc = self.svc.get_transaction_absence_proof("1", after)
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["upper"])
        self.assertEqual(doc["lower"]["index"], 1)
        self.assertEqual(doc["lower"]["tx_id"], ordered[-1])
        self.assertTrue(self.verify(doc, after, 1))

    def test_single_transaction_block(self) -> None:
        tx_id = self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        for target in (shifted(tx_id, -1), shifted(tx_id, 1)):
            status, doc = self.svc.get_transaction_absence_proof("1", target)
            self.assertEqual(status, 200, doc)
            self.assertEqual(doc["transaction_count"], 1)
            neighbor = doc["lower"] or doc["upper"]
            self.assertEqual(neighbor["index"], 0)
            self.assertEqual(neighbor["siblings"], [])
            self.assertTrue(self.verify(doc, target, 1))

    def test_present_target_is_409(self) -> None:
        tx_id = self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        status, body = self.svc.get_transaction_absence_proof("1", tx_id)
        self.assertEqual((status, body), (409, {"error": "transaction_present"}))

    def test_pending_block_is_409(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201)
        status, body = self.svc.get_transaction_absence_proof(
            str(pending["height"]), "0" * 64
        )
        self.assertEqual((status, body), (409, {"error": "block_pending"}))
        # The confirmed prefix stays readable.
        status, doc = self.svc.get_transaction_absence_proof("0", "0" * 64)
        self.assertEqual(status, 200, doc)

    def test_height_and_tx_id_validation(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        ghost = "0" * 64
        for bad in ("-1", "00", "01", "1.0", " 1", "1 ", "0x1", "+1", "",
                    "１２", "1e3"):
            status, body = self.svc.get_transaction_absence_proof(bad, ghost)
            self.assertEqual(
                (status, body), (404, {"error": "block_not_found"}), bad
            )
        for bad in (5, True, None, 1.0):
            status, body = self.svc.get_transaction_absence_proof(bad, ghost)
            self.assertEqual((status, body), (404, {"error": "block_not_found"}))
        status, body = self.svc.get_transaction_absence_proof("999", ghost)
        self.assertEqual((status, body), (404, {"error": "block_not_found"}))
        for bad in ("zz", "A" * 64, "0" * 63, "0" * 65, "", 5, None, True):
            status, body = self.svc.get_transaction_absence_proof("1", bad)
            self.assertEqual(
                (status, body), (404, {"error": "transaction_not_found"}), bad
            )

    def test_query_is_read_only(self) -> None:
        tx_id = self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        store = self.svc.store
        generation = store.generation
        events = len(store.audit_events)
        chain_len = len(store.chain)
        mempool = len(store.pending)
        for _ in range(5):
            self.svc.get_transaction_absence_proof("1", "0" * 64)
            self.svc.get_transaction_absence_proof("1", tx_id)
            self.svc.get_transaction_absence_proof("0", "f" * 64)
        self.assertEqual(store.generation, generation)
        self.assertEqual(len(store.audit_events), events)
        self.assertEqual(len(store.chain), chain_len)
        self.assertEqual(len(store.pending), mempool)

    def test_restart_keeps_documents(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        ghost = "0" * 64
        status, first = self.svc.get_transaction_absence_proof("1", ghost)
        self.assertEqual(status, 200)
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
        )
        status, second = reopened.get_transaction_absence_proof("1", ghost)
        self.assertEqual(status, 200)
        self.assertEqual(first, second)


class TxAbsenceCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        path = os.path.join(self.tmp, "crypto.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(LedgerStore(path), initial_balance=100_000)

    def _build(self) -> tuple[dict, str, int, str, str]:
        ids = [
            self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))[1]["tx_id"],
            self.svc.submit_transaction(make_tx(self.kb, self.B, self.C, 1))[1]["tx_id"],
            self.svc.submit_transaction(make_tx(self.kc, self.C, self.A, 2))[1]["tx_id"],
        ]
        self.svc.mine_block()
        self.svc.confirm_block("1")
        anchor = self.svc.get_block("1")[1]
        ordered = sorted(ids)
        target = shifted(ordered[0], 1)
        if target >= ordered[1]:
            target = shifted(ordered[1], -1)
        doc = self.svc.get_transaction_absence_proof("1", target)[1]
        return doc, target, 1, anchor["block_hash"], anchor["merkle_root"]

    def _empty_doc(self) -> tuple[dict, str, int, str, str]:
        anchor = self.svc.get_block("0")[1]
        target = "0" * 64
        doc = self.svc.get_transaction_absence_proof("0", target)[1]
        return doc, target, 0, anchor["block_hash"], anchor["merkle_root"]

    def test_valid_documents_verify(self) -> None:
        doc, target, height, block_hash, root = self._build()
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                doc, target, height, block_hash, root
            )
        )
        doc0, target0, height0, hash0, root0 = self._empty_doc()
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                doc0, target0, height0, hash0, root0
            )
        )

    def test_key_order_does_not_matter(self) -> None:
        doc, target, height, block_hash, root = self._build()
        reordered = {key: doc[key] for key in reversed(DOC_KEYS)}
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                reordered, target, height, block_hash, root
            )
        )
        flipped = json.loads(json.dumps(doc))
        flipped["lower"] = {
            key: doc["lower"][key] for key in reversed(NEIGHBOR_KEYS)
        }
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                flipped, target, height, block_hash, root
            )
        )

    def test_missing_or_extra_keys(self) -> None:
        doc, target, height, block_hash, root = self._build()
        for key in DOC_KEYS:
            partial = dict(doc)
            del partial[key]
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    partial, target, height, block_hash, root
                ),
                key,
            )
        extra = dict(doc)
        extra["unexpected"] = 1
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                extra, target, height, block_hash, root
            )
        )
        for side in ("lower", "upper"):
            tampered = json.loads(json.dumps(doc))
            tampered[side]["extra"] = True
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    tampered, target, height, block_hash, root
                )
            )
            tampered = json.loads(json.dumps(doc))
            del tampered[side]["index"]
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    tampered, target, height, block_hash, root
                )
            )
            tampered = json.loads(json.dumps(doc))
            tampered[side]["siblings"][0]["side"] = "right"
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    tampered, target, height, block_hash, root
                )
            )

    def test_pinned_value_mismatch(self) -> None:
        doc, target, height, block_hash, root = self._build()
        other = "f" * 64
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                doc, other, height, block_hash, root
            )
        )
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                doc, target, height + 1, block_hash, root
            )
        )
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                doc, target, height, other, root
            )
        )
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                doc, target, height, block_hash, other
            )
        )
        # Renamed document fields fail against the same pins.
        for key, value in (
            ("tx_id", other),
            ("height", height + 1),
            ("block_hash", other),
            ("merkle_root", other),
        ):
            tampered = json.loads(json.dumps(doc))
            tampered[key] = value
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    tampered, target, height, block_hash, root
                ),
                key,
            )
        # Malformed pinned values are rejected too.
        for bad in (None, True, 5, "x", [], {}):
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    doc, bad, height, block_hash, root
                )
            )
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    doc, target, bad, block_hash, root
                )
            )
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    doc, target, height, bad, root
                )
            )
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    doc, target, height, block_hash, bad
                )
            )

    def test_transaction_count_bounds(self) -> None:
        doc, target, height, block_hash, root = self._build()
        for bad in (True, -1, 1.0, "3", None):
            tampered = json.loads(json.dumps(doc))
            tampered["transaction_count"] = bad
            self.assertFalse(
                crypto.verify_transaction_absence_proof(
                    tampered, target, height, block_hash, root
                ),
                bad,
            )
        # An index outside [0, transaction_count) fails.
        tampered = json.loads(json.dumps(doc))
        tampered["lower"]["index"] = doc["transaction_count"]
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )
        # A shrunken count that still contains the indices breaks the
        # exact-depth rule for the recomputed tree.
        tampered = json.loads(json.dumps(doc))
        tampered["transaction_count"] = 2
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )

    def test_neighbor_tampering(self) -> None:
        doc, target, height, block_hash, root = self._build()
        tampered = json.loads(json.dumps(doc))
        tampered["lower"]["tx_id"] = "f" * 64
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )
        tampered = json.loads(json.dumps(doc))
        tampered["upper"]["siblings"][0]["hash"] = "f" * 64
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )
        tampered = json.loads(json.dumps(doc))
        tampered["upper"]["siblings"][0]["direction"] = (
            "left"
            if tampered["upper"]["siblings"][0]["direction"] == "right"
            else "right"
        )
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )
        # An over-deep path is rejected.
        tampered = json.loads(json.dumps(doc))
        tampered["lower"]["siblings"] = tampered["lower"]["siblings"] + [
            {"direction": "right", "hash": "0" * 64}
        ]
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )
        # A path beyond MAX_MERKLE_DEPTH is rejected.
        tampered = json.loads(json.dumps(doc))
        tampered["lower"]["siblings"] = [
            {"direction": "right", "hash": "0" * 64}
        ] * (crypto.MAX_MERKLE_DEPTH + 1)
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )

    def test_phantom_sibling_slot_rejected(self) -> None:
        # 3 leaves: the last leaf (index 2) self-pairs at the first level;
        # flipping that identical sibling to "left" addresses the phantom
        # duplicate slot and must fail.
        doc, target, height, block_hash, root = self._build()
        self.assertEqual(doc["transaction_count"], 3)
        last_leaf = max(
            tx["tx_id"] for tx in self.svc.store.chain[1].to_dict()["transactions"]
        )
        after = shifted(last_leaf, 1)
        if after < last_leaf:
            after = shifted(last_leaf, 2)
        after_doc = self.svc.get_transaction_absence_proof("1", after)[1]
        last = after_doc["lower"]
        self.assertEqual(last["index"], 2)
        self.assertEqual(last["siblings"][0]["direction"], "right")
        self.assertEqual(last["siblings"][0]["hash"], last["tx_id"])
        forged = json.loads(json.dumps(after_doc))
        forged["lower"]["siblings"][0]["direction"] = "left"
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                forged, after, height, block_hash, root
            )
        )

    def test_framing_violations(self) -> None:
        doc, target, height, block_hash, root = self._build()
        ordered = sorted(
            tx["tx_id"] for tx in self.svc.store.chain[1].to_dict()["transactions"]
        )
        proofs = {
            tx_id: self.svc.get_proof("1", tx_id)[1] for tx_id in ordered
        }

        def neighbor(tx_id):
            proof = proofs[tx_id]
            return {
                "tx_id": tx_id,
                "index": proof["index"],
                "siblings": proof["siblings"],
            }

        # Non-adjacent neighbors (indices 0 and 2) cannot frame a target.
        forged = dict(doc)
        forged["lower"] = neighbor(ordered[0])
        forged["upper"] = neighbor(ordered[2])
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                forged, target, height, block_hash, root
            )
        )
        # A boundary side pointing at the wrong index fails.
        before = shifted(ordered[0], -1)
        if before > ordered[0]:
            before = shifted(ordered[0], -2)
        boundary = self.svc.get_transaction_absence_proof("1", before)[1]
        tampered = json.loads(json.dumps(boundary))
        tampered["upper"] = neighbor(ordered[2])
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, before, height, block_hash, root
            )
        )
        # Both neighbors null inside a non-empty block fails.
        tampered = json.loads(json.dumps(doc))
        tampered["lower"] = None
        tampered["upper"] = None
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )
        # A "lower" neighbor sorting after the target fails the strict
        # ordering, as does an "upper" neighbor sorting before it.
        tampered = json.loads(json.dumps(doc))
        tampered["lower"] = neighbor(ordered[2])
        tampered["upper"] = None
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )
        tampered = json.loads(json.dumps(doc))
        tampered["upper"] = neighbor(ordered[0])
        tampered["lower"] = None
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target, height, block_hash, root
            )
        )

    def test_empty_tree_rules(self) -> None:
        doc0, target0, height0, hash0, root0 = self._empty_doc()
        self.assertEqual(root0, crypto.EMPTY_MERKLE_ROOT)
        # A neighbor inside a zero-count document fails.
        tampered = json.loads(json.dumps(doc0))
        tampered["lower"] = {
            "tx_id": "0" * 64,
            "index": 0,
            "siblings": [],
        }
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                tampered, target0, height0, hash0, root0
            )
        )
        # The empty-tree root is enforced against the pinned root.
        doc, target, height, block_hash, root = self._build()
        zero = json.loads(json.dumps(doc0))
        self.assertFalse(
            crypto.verify_transaction_absence_proof(
                zero, target0, height0, hash0, "0" * 64
            )
        )

    def test_never_raises(self) -> None:
        doc, target, height, block_hash, root = self._build()
        weird = [
            None, True, 0, 1.5, float("nan"), [], {}, object(),
            {"tx_id": None},
            {"height": height, "tx_id": target, "transaction_count": 1,
             "merkle_root": root, "block_hash": block_hash,
             "lower": [], "upper": {}},
            {"height": height, "tx_id": target, "transaction_count": 1,
             "merkle_root": root, "block_hash": block_hash,
             "lower": 7, "upper": None},
            {"height": height, "tx_id": target, "transaction_count": 1,
             "merkle_root": root, "block_hash": block_hash,
             "lower": {"tx_id": target, "index": 0, "siblings": None},
             "upper": None},
        ]
        for value in weird:
            try:
                result = crypto.verify_transaction_absence_proof(
                    value, target, height, block_hash, root
                )
            except Exception as exc:  # pragma: no cover - contract failure
                raise AssertionError((value, exc))
            self.assertFalse(result, value)


class TxAbsenceHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")),
            initial_balance=100_000,
        )
        cls.ids = []
        for key, sender, to, amount in (
            (cls.ka, cls.A, cls.B, 10),
            (cls.kb, cls.B, cls.A, 1),
        ):
            status, body = cls.service.submit_transaction(
                make_tx(key, sender, to, amount)
            )
            assert status == 202
            cls.ids.append(body["tx_id"])
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
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def get(self, path: str):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    def run_cli(self, *args) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw)

    def test_wire_shape_and_verification(self) -> None:
        ghost = "0" * 64
        status, body = self.get(f"/v1/blocks/1/absence-proof/{ghost}")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), DOC_KEYS)
        for side in ("lower", "upper"):
            if body[side] is not None:
                self.assertEqual(list(body[side]), NEIGHBOR_KEYS)
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                body, ghost, 1, body["block_hash"], body["merkle_root"]
            )
        )

    def test_http_status_matrix(self) -> None:
        ghost = "0" * 64
        for path in (
            f"/v1/blocks/1/absence-proof/{ghost}?foo=1",
            f"/v1/blocks/1/absence-proof/{ghost}?height=1",
            f"/v1/blocks/1/absence-proof/{ghost}?a=1&a=2",
        ):
            status, body = self.get(path)
            self.assertEqual((status, body), (400, {"error": "input"}), path)
        for height in ("00", "-1", "1%20", "999"):
            status, body = self.get(
                f"/v1/blocks/{height}/absence-proof/{ghost}"
            )
            self.assertEqual(
                (status, body), (404, {"error": "block_not_found"}), height
            )
        status, body = self.get("/v1/blocks/1/absence-proof/zz")
        self.assertEqual((status, body), (404, {"error": "transaction_not_found"}))
        status, body = self.get(f"/v1/blocks/1/absence-proof/{self.ids[0]}")
        self.assertEqual(
            (status, body), (409, {"error": "transaction_present"})
        )

    def test_http_pending_block(self) -> None:
        self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 3))
        status, pending = self.service.mine_block()
        self.assertEqual(status, 201)
        try:
            status, body = self.get(
                f"/v1/blocks/{pending['height']}/absence-proof/{'0' * 64}"
            )
            self.assertEqual(
                (status, body), (409, {"error": "block_pending"})
            )
            status, body = self.get(f"/v1/blocks/1/absence-proof/{'0' * 64}")
            self.assertEqual(status, 200, body)
        finally:
            self.service.rollback_block(pending["height"])

    def test_existing_endpoints_unchanged(self) -> None:
        status, proof = self.get(f"/v1/blocks/1/proof/{self.ids[0]}")
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
        status, block = self.get("/v1/blocks/1")
        self.assertEqual(status, 200, block)

    def test_cli_absence_proof(self) -> None:
        ghost = "0" * 64
        rc, body = self.run_cli("absence-proof", "1", ghost)
        self.assertEqual(rc, 0, body)
        self.assertEqual(list(body), DOC_KEYS)
        self.assertTrue(
            crypto.verify_transaction_absence_proof(
                body, ghost, 1, body["block_hash"], body["merkle_root"]
            )
        )
        # Non-2xx responses are forwarded and exit 1.
        rc, body = self.run_cli("absence-proof", "1", self.ids[0])
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "transaction_present"})
        rc, body = self.run_cli("absence-proof", "01", ghost)
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "block_not_found"})
        rc, body = self.run_cli("absence-proof", "1", "zz")
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "transaction_not_found"})
        # A connection failure exits 1 as well.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(
                ["--base-url", "http://127.0.0.1:1", "absence-proof", "1", ghost]
            )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

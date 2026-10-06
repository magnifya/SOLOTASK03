"""Tests for batch transaction-absence (non-inclusion) proofs.

Covers:

* service POST /v1/blocks/{height}/absence-proofs: the strict
  {"tx_ids": [...]} body contract (1–128 distinct 64-lowercase-hex ids),
  the fixed success key order (height, block_hash, merkle_root,
  transaction_count, tx_ids, proofs) with tx_ids sorted ascending and one
  {tx_id, lower, upper} proof per target, empty-block and boundary
  documents, and the status matrix (400 input / 404 block_not_found /
  409 block_pending / 409 transaction_present);
* crypto.verify_transaction_absence_proof_bundle: exact field/type/format
  rules, anchor pinning, unique-ascending targets, per-target neighbor
  framing, tampering and malformed inputs all returning False without
  raising;
* HTTP wire behavior (fixed key order), read-only semantics, restart
  determinism and the CLI absence-proofs command.

Run: python3 tests/transaction_absence_proofs_batch_test.py
"""
from __future__ import annotations

import contextlib
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


def middle_target(tx_ids: list[str]) -> str:
    """A 64-hex id strictly between the first two (ascending) leaves."""
    candidate = tx_ids[0][:-1] + ("0" if tx_ids[0][-1] != "0" else "1")
    if not tx_ids[0] < candidate < tx_ids[1]:
        candidate = tx_ids[1][:-1] + ("0" if tx_ids[1][-1] != "0" else "1")
    assert tx_ids[0] < candidate < tx_ids[1]
    return candidate


class TxAbsenceBatchServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "absence-batch.json")
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

    def test_success_shape_and_sorting(self) -> None:
        for key, sender, to, amount in (
            (self.ka, self.A, self.B, 10),
            (self.kb, self.B, self.C, 5),
            (self.kc, self.C, self.A, 3),
        ):
            self.send(key, sender, to, amount)
        block = self.mine_and_confirm()
        height = block["height"]
        targets = ["00" * 32, "1" * 64, "f" * 64]
        # Request order must not matter: ask in reverse sorted order.
        status, doc = self.svc.get_transaction_absence_proofs(
            str(height), {"tx_ids": list(reversed(targets))}
        )
        self.assertEqual(status, 200, doc)
        self.assertEqual(
            list(doc),
            [
                "height",
                "block_hash",
                "merkle_root",
                "transaction_count",
                "tx_ids",
                "proofs",
            ],
        )
        self.assertEqual(doc["height"], height)
        self.assertEqual(doc["transaction_count"], 3)
        self.assertEqual(doc["tx_ids"], sorted(targets))
        self.assertEqual(len(doc["proofs"]), len(targets))
        for target, proof in zip(sorted(targets), doc["proofs"]):
            self.assertEqual(list(proof), ["tx_id", "lower", "upper"])
            self.assertEqual(proof["tx_id"], target)
            for side in ("lower", "upper"):
                if proof[side] is not None:
                    self.assertEqual(
                        list(proof[side]), ["tx_id", "index", "siblings"]
                    )
        self.assertTrue(
            crypto.verify_transaction_absence_proof_bundle(
                doc, height, doc["block_hash"], doc["merkle_root"]
            )
        )

    def test_matches_single_endpoint(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.send(self.kb, self.B, self.C, 5)
        block = self.mine_and_confirm()
        height = block["height"]
        targets = ["00" * 32, "1" * 64, "f" * 64]
        status, doc = self.svc.get_transaction_absence_proofs(
            str(height), {"tx_ids": targets}
        )
        self.assertEqual(status, 200, doc)
        for proof in doc["proofs"]:
            status, single = self.svc.get_transaction_absence_proof(
                str(height), proof["tx_id"]
            )
            self.assertEqual(status, 200, single)
            self.assertEqual(proof["lower"], single["lower"])
            self.assertEqual(proof["upper"], single["upper"])

    def test_empty_block(self) -> None:
        targets = ["0" * 64, "f" * 64]
        status, doc = self.svc.get_transaction_absence_proofs(
            "0", {"tx_ids": targets}
        )
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["transaction_count"], 0)
        self.assertEqual(doc["merkle_root"], crypto.EMPTY_MERKLE_ROOT)
        self.assertEqual(doc["tx_ids"], targets)
        for proof in doc["proofs"]:
            self.assertIsNone(proof["lower"])
            self.assertIsNone(proof["upper"])
        self.assertTrue(
            crypto.verify_transaction_absence_proof_bundle(
                doc, 0, doc["block_hash"], doc["merkle_root"]
            )
        )

    def test_body_validation(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        block = self.mine_and_confirm()
        height = str(block["height"])
        bad_payloads = [
            None,
            [],
            "tx_ids",
            {},
            {"tx_ids": ["0" * 64], "extra": 1},
            {"tx_id": ["0" * 64]},
            {"tx_ids": None},
            {"tx_ids": "0" * 64},
            {"tx_ids": []},
            {"tx_ids": ["0" * 64] * 129},
            {"tx_ids": ["0" * 64, "0" * 64]},
            {"tx_ids": ["zz"]},
            {"tx_ids": ["A" * 64]},
            {"tx_ids": ["0" * 63]},
            {"tx_ids": ["0" * 65]},
            {"tx_ids": [5]},
            {"tx_ids": [None]},
            {"tx_ids": [True]},
        ]
        for payload in bad_payloads:
            status, body = self.svc.get_transaction_absence_proofs(
                height, payload
            )
            self.assertEqual(
                (status, body), (400, {"error": "input"}), payload
            )
        # Exactly 128 distinct ids is fine.
        ids = [f"{i:064x}" for i in range(128)]
        status, doc = self.svc.get_transaction_absence_proofs(
            height, {"tx_ids": ids}
        )
        self.assertEqual(status, 200, doc)
        self.assertEqual(len(doc["proofs"]), 128)

    def test_height_and_present_matrix(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        block = self.mine_and_confirm()
        height = block["height"]
        present = self.leaves(height)[0]
        for bad in ("-1", "00", "01", "1.0", " 1", "1 ", "0x1", "", "999"):
            status, body = self.svc.get_transaction_absence_proofs(
                bad, {"tx_ids": ["0" * 64]}
            )
            self.assertEqual(
                (status, body), (404, {"error": "block_not_found"}), bad
            )
        # Any single present target fails the whole batch.
        status, body = self.svc.get_transaction_absence_proofs(
            str(height), {"tx_ids": ["0" * 64, present]}
        )
        self.assertEqual((status, body), (409, {"error": "transaction_present"}))

    def test_pending_block_is_409(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201, pending)
        status, body = self.svc.get_transaction_absence_proofs(
            str(pending["height"]), {"tx_ids": ["0" * 64]}
        )
        self.assertEqual((status, body), (409, {"error": "block_pending"}))
        # The confirmed prefix stays readable.
        status, doc = self.svc.get_transaction_absence_proofs(
            "0", {"tx_ids": ["0" * 64]}
        )
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
            self.svc.get_transaction_absence_proofs(
                str(block["height"]), {"tx_ids": ["0" * 64, "1" * 64]}
            )
            self.svc.get_transaction_absence_proofs("0", {"tx_ids": ["2" * 64]})
            self.svc.get_transaction_absence_proofs(
                str(block["height"]),
                {"tx_ids": [self.leaves(block["height"])[0]]},
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

    def test_restart_keeps_batch_documents(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        block = self.mine_and_confirm()
        payload = {"tx_ids": ["0" * 64, "f" * 64]}
        status, first = self.svc.get_transaction_absence_proofs(
            str(block["height"]), payload
        )
        self.assertEqual(status, 200)
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
        )
        status, second = reopened.get_transaction_absence_proofs(
            str(block["height"]), payload
        )
        self.assertEqual(status, 200)
        self.assertEqual(first, second)


class TxAbsenceBatchCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "crypto-batch.json")),
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
        self.tx_ids = [
            tx.tx_id for tx in self.svc.store.chain[self.height].transactions
        ]
        self.assertEqual(len(self.tx_ids), 3)
        # Targets: before the first leaf, between the first two leaves and
        # after the last leaf (the all-zero / all-one ids are the extremes
        # of the 64-hex space).
        self.targets = ["00" * 32, middle_target(self.tx_ids), "ff" * 32]
        status, doc = self.svc.get_transaction_absence_proofs(
            str(self.height), {"tx_ids": self.targets}
        )
        assert status == 200
        self.doc = doc
        self.root = doc["merkle_root"]
        self.hash = doc["block_hash"]

    _UNSET = object()

    def verify(self, doc, height=_UNSET, block_hash=_UNSET, root=_UNSET):
        return crypto.verify_transaction_absence_proof_bundle(
            doc,
            self.height if height is self._UNSET else height,
            self.hash if block_hash is self._UNSET else block_hash,
            self.root if root is self._UNSET else root,
        )

    def test_valid_bundles_verify(self) -> None:
        self.assertTrue(self.verify(self.doc))
        empty = self.svc.get_transaction_absence_proofs(
            "0", {"tx_ids": ["0" * 64]}
        )[1]
        self.assertTrue(
            crypto.verify_transaction_absence_proof_bundle(
                empty, 0, empty["block_hash"], empty["merkle_root"]
            )
        )

    def test_key_order_does_not_matter(self) -> None:
        reordered = {
            key: self.doc[key]
            for key in (
                "proofs",
                "tx_ids",
                "transaction_count",
                "merkle_root",
                "block_hash",
                "height",
            )
        }
        self.assertTrue(self.verify(reordered))

    def test_missing_or_extra_keys(self) -> None:
        for key in (
            "height",
            "block_hash",
            "merkle_root",
            "transaction_count",
            "tx_ids",
            "proofs",
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
        self.assertFalse(self.verify(self.doc, height=self.height + 1))
        self.assertFalse(self.verify(self.doc, block_hash="0" * 64))
        self.assertFalse(self.verify(self.doc, root="0" * 64))
        for weird in (None, True, 5, [], "x"):
            self.assertFalse(self.verify(self.doc, height=weird))
            self.assertFalse(self.verify(self.doc, block_hash=weird))
            self.assertFalse(self.verify(self.doc, root=weird))
        for key, value in (
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

    def test_target_list_rules(self) -> None:
        # Unsorted, duplicated, malformed, empty and over-long target lists.
        for targets in (
            list(reversed(self.doc["tx_ids"])),
            ["0" * 64, "0" * 64],
            ["zz"],
            ["A" * 64],
            [5],
            [],
            [f"{i:064x}" for i in range(129)],
            "0" * 64,
            None,
        ):
            tampered = copy.deepcopy(self.doc)
            tampered["tx_ids"] = targets
            self.assertFalse(self.verify(tampered), targets)
        # proofs length must match the target count.
        tampered = copy.deepcopy(self.doc)
        tampered["proofs"] = tampered["proofs"][:-1]
        self.assertFalse(self.verify(tampered))
        tampered = copy.deepcopy(self.doc)
        tampered["proofs"] = None
        self.assertFalse(self.verify(tampered))

    def test_proof_alignment_and_shape(self) -> None:
        # A proof whose tx_id does not equal its target fails.
        tampered = copy.deepcopy(self.doc)
        tampered["proofs"][0]["tx_id"] = "1" * 64
        self.assertFalse(self.verify(tampered))
        # Swapping two proofs misaligns them with the targets.
        tampered = copy.deepcopy(self.doc)
        tampered["proofs"][0], tampered["proofs"][1] = (
            tampered["proofs"][1],
            tampered["proofs"][0],
        )
        self.assertFalse(self.verify(tampered))
        # Missing/extra proof keys.
        tampered = copy.deepcopy(self.doc)
        del tampered["proofs"][0]["lower"]
        self.assertFalse(self.verify(tampered))
        tampered = copy.deepcopy(self.doc)
        tampered["proofs"][0]["extra"] = True
        self.assertFalse(self.verify(tampered))

    def test_neighbor_tampering(self) -> None:
        for i in range(len(self.doc["proofs"])):
            for side in ("lower", "upper"):
                if self.doc["proofs"][i][side] is None:
                    continue
                for key, value in (
                    ("tx_id", "1" * 64),
                    ("index", 7),
                    ("index", True),
                    ("index", 1.0),
                ):
                    tampered = copy.deepcopy(self.doc)
                    tampered["proofs"][i][side][key] = value
                    self.assertFalse(self.verify(tampered), (i, side, key))
                tampered = copy.deepcopy(self.doc)
                tampered["proofs"][i][side]["siblings"][0]["hash"] = "f" * 64
                self.assertFalse(self.verify(tampered), (i, side))
                tampered = copy.deepcopy(self.doc)
                tampered["proofs"][i][side]["siblings"].append(
                    {"direction": "right", "hash": "0" * 64}
                )
                self.assertFalse(self.verify(tampered), (i, side))

    def test_framing_violations(self) -> None:
        # Both neighbors null in a non-empty block.
        tampered = copy.deepcopy(self.doc)
        tampered["proofs"][1]["lower"] = None
        tampered["proofs"][1]["upper"] = None
        self.assertFalse(self.verify(tampered))
        # A genuine proof of a non-adjacent pair cannot frame the target.
        middle = self.doc["proofs"][1]
        if middle["lower"] is not None and middle["upper"] is not None:
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
            tampered = copy.deepcopy(self.doc)
            tampered["proofs"][1]["lower"] = p0
            tampered["proofs"][1]["upper"] = p2
            self.assertFalse(self.verify(tampered))
        # A neighbor equal to the target is not an absence.
        tampered = copy.deepcopy(self.doc)
        target = tampered["tx_ids"][1]
        if tampered["proofs"][1]["lower"] is not None:
            tampered["proofs"][1]["lower"]["tx_id"] = target
            self.assertFalse(self.verify(tampered))

    def test_empty_tree_rules(self) -> None:
        empty = self.svc.get_transaction_absence_proofs(
            "0", {"tx_ids": ["0" * 64]}
        )[1]
        tampered = copy.deepcopy(empty)
        tampered["merkle_root"] = "0" * 64
        self.assertFalse(
            crypto.verify_transaction_absence_proof_bundle(
                tampered, 0, tampered["block_hash"], "0" * 64
            )
        )
        tampered = copy.deepcopy(empty)
        tampered["proofs"][0]["lower"] = {
            "tx_id": "1" * 64,
            "index": 0,
            "siblings": [],
        }
        self.assertFalse(
            crypto.verify_transaction_absence_proof_bundle(
                tampered, 0, tampered["block_hash"], tampered["merkle_root"]
            )
        )
        # Claiming neighbors inside a zero-count bundle fails.
        tampered = copy.deepcopy(self.doc)
        tampered["transaction_count"] = 0
        self.assertFalse(self.verify(tampered))

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
            {"tx_ids": None},
            {
                "height": self.height,
                "block_hash": self.hash,
                "merkle_root": self.root,
                "transaction_count": 3,
                "tx_ids": self.doc["tx_ids"],
                "proofs": 7,
            },
        ]
        for value in weird:
            try:
                result = self.verify(value)
            except Exception as exc:  # pragma: no cover - contract failure
                raise AssertionError((value, exc))
            self.assertFalse(result, value)


class TxAbsenceBatchHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http-batch.json")),
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
        cls.targets = ["00" * 32, middle_target(cls.tx_ids), "ff" * 32]
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

    def post(self, path: str, payload, raw: bytes | None = None):
        data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    def test_wire_shape_and_verification(self) -> None:
        status, body = self.post(
            f"/v1/blocks/{self.height}/absence-proofs",
            {"tx_ids": list(reversed(self.targets))},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body),
            [
                "height",
                "block_hash",
                "merkle_root",
                "transaction_count",
                "tx_ids",
                "proofs",
            ],
        )
        self.assertEqual(body["tx_ids"], sorted(self.targets))
        self.assertEqual(
            [proof["tx_id"] for proof in body["proofs"]], body["tx_ids"]
        )
        self.assertTrue(
            crypto.verify_transaction_absence_proof_bundle(
                body, self.height, body["block_hash"], body["merkle_root"]
            )
        )

    def test_http_status_matrix(self) -> None:
        path = f"/v1/blocks/{self.height}/absence-proofs"
        for payload in (
            None,
            [],
            {},
            {"tx_ids": []},
            {"tx_ids": ["0" * 64], "x": 1},
            {"tx_ids": ["0" * 64, "0" * 64]},
            {"tx_ids": ["zz"]},
            {"tx_ids": ["0" * 64] * 129},
        ):
            status, body = self.post(path, payload)
            self.assertEqual(
                (status, body), (400, {"error": "input"}), payload
            )
        # Unparseable JSON is the same fixed 400.
        status, body = self.post(path, None, raw=b"{not json")
        self.assertEqual((status, body), (400, {"error": "input"}))
        for height in ("00", "-1", "999"):
            status, body = self.post(
                f"/v1/blocks/{height}/absence-proofs",
                {"tx_ids": ["0" * 64]},
            )
            self.assertEqual(
                (status, body), (404, {"error": "block_not_found"}), height
            )
        status, body = self.post(path, {"tx_ids": [self.tx_ids[0]]})
        self.assertEqual(
            (status, body), (409, {"error": "transaction_present"})
        )

    def test_http_pending_block(self) -> None:
        self.service.submit_transaction(make_tx(self.ka, self.A, self.C, 1))
        status, pending = self.service.mine_block()
        self.assertEqual(status, 201, pending)
        try:
            status, body = self.post(
                f"/v1/blocks/{pending['height']}/absence-proofs",
                {"tx_ids": ["0" * 64]},
            )
            self.assertEqual(
                (status, body), (409, {"error": "block_pending"})
            )
            status, body = self.post(
                f"/v1/blocks/{self.height}/absence-proofs",
                {"tx_ids": self.targets},
            )
            self.assertEqual(status, 200, body)
        finally:
            self.service.rollback_block(pending["height"])

    def test_single_endpoint_unchanged(self) -> None:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}"
            f"/v1/blocks/{self.height}/absence-proof/{self.targets[1]}"
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read())
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

    def test_cli_absence_proofs(self) -> None:
        base = f"http://127.0.0.1:{self.port}"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = cli.main(
                [
                    "--base-url",
                    base,
                    "absence-proofs",
                    str(self.height),
                    *reversed(self.targets),
                ]
            )
        self.assertEqual(rc, 0)
        out = json.loads(buffer.getvalue())
        self.assertEqual(
            list(out),
            [
                "height",
                "block_hash",
                "merkle_root",
                "transaction_count",
                "tx_ids",
                "proofs",
            ],
        )
        self.assertTrue(
            crypto.verify_transaction_absence_proof_bundle(
                out, self.height, out["block_hash"], out["merkle_root"]
            )
        )
        # Non-2xx responses exit 1 and print the error body.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = cli.main(
                [
                    "--base-url",
                    base,
                    "absence-proofs",
                    str(self.height),
                    self.tx_ids[0],
                ]
            )
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(buffer.getvalue()), {"error": "transaction_present"}
        )
        # A missing tx_id list exits 1 with the input error body.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = cli.main(
                ["--base-url", base, "absence-proofs", str(self.height)]
            )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(buffer.getvalue()), {"error": "input"})
        # Connection failure exits 1.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = cli.main(
                [
                    "--base-url",
                    "http://127.0.0.1:1",
                    "absence-proofs",
                    str(self.height),
                    self.targets[0],
                ]
            )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

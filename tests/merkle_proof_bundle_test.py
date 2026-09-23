"""Tests for batch confirmed-transaction Merkle proofs.

Covers crypto.verify_merkle_proof_bundle (key order, types, uniqueness,
index mapping, leaf-to-root paths, root and block-hash binding), the service
batch lookup (strict 400 body validation, 404/409 semantics, response key
ordering), the POST /v1/blocks/{height}/proofs HTTP route and the CLI
``proofs HEIGHT TX_ID...`` subcommand.

Run: python3 tests/merkle_proof_bundle_test.py
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


def make_bundle(tx_ids: list[str], indices: list[int], block_hash: str) -> dict:
    """Build a well-formed batch bundle for the given leaf indices."""
    tx_ids = sorted(tx_ids)
    root = crypto.merkle_root(tx_ids)
    proofs = []
    for index in sorted(indices):
        proofs.append({
            "tx_id": tx_ids[index],
            "index": index,
            "siblings": crypto.merkle_proof(tx_ids, index),
        })
    return {
        "height": 7,
        "block_hash": block_hash,
        "merkle_root": root,
        "transaction_ids": list(tx_ids),
        "proofs": proofs,
    }


class VerifyBundleCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.block_hash = h("block")

    def test_all_tree_shapes_full_and_subset_bundles(self) -> None:
        for n in (1, 2, 3, 4, 5, 6, 7, 8, 9):
            tx_ids = sorted(h(f"tx-{n}-{i}") for i in range(n))
            root = crypto.merkle_root(tx_ids)
            # Full coverage and various subsets, including only the last leaf.
            subsets = [list(range(n)), [0], [n - 1], [i for i in range(n) if i % 2 == 0]]
            for indices in subsets:
                bundle = make_bundle(tx_ids, indices, self.block_hash)
                self.assertTrue(
                    crypto.verify_merkle_proof_bundle(
                        bundle, self.block_hash, root
                    ),
                    (n, indices),
                )

    def test_response_key_order_is_significant(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        good = make_bundle(tx_ids, [1, 2], self.block_hash)
        root = good["merkle_root"]

        # Top level reordered.
        reordered = {key: good[key] for key in (
            "height", "merkle_root", "block_hash", "transaction_ids", "proofs"
        )}
        self.assertFalse(crypto.verify_merkle_proof_bundle(reordered, self.block_hash, root))
        # Missing / extra top-level keys.
        missing = dict(good)
        del missing["proofs"]
        self.assertFalse(crypto.verify_merkle_proof_bundle(missing, self.block_hash, root))
        extra = dict(good)
        extra["extra"] = 1
        self.assertFalse(crypto.verify_merkle_proof_bundle(extra, self.block_hash, root))

        # Proof entry key order / key set.
        bad = copy.deepcopy(good)
        bad["proofs"][0] = {
            "index": bad["proofs"][0]["index"],
            "tx_id": bad["proofs"][0]["tx_id"],
            "siblings": bad["proofs"][0]["siblings"],
        }
        self.assertFalse(crypto.verify_merkle_proof_bundle(bad, self.block_hash, root))
        bad = copy.deepcopy(good)
        bad["proofs"][0].pop("index")
        self.assertFalse(crypto.verify_merkle_proof_bundle(bad, self.block_hash, root))

        # Sibling entry key order / key set.
        bad = copy.deepcopy(good)
        item = bad["proofs"][0]["siblings"][0]
        bad["proofs"][0]["siblings"][0] = {"hash": item["hash"], "direction": item["direction"]}
        self.assertFalse(crypto.verify_merkle_proof_bundle(bad, self.block_hash, root))
        bad = copy.deepcopy(good)
        bad["proofs"][0]["siblings"][0]["side"] = "left"
        self.assertFalse(crypto.verify_merkle_proof_bundle(bad, self.block_hash, root))

    def test_wrong_types_return_false(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        good = make_bundle(tx_ids, [0, 3], self.block_hash)
        root = good["merkle_root"]

        def rejects(mutated) -> None:
            self.assertFalse(
                crypto.verify_merkle_proof_bundle(mutated, self.block_hash, root)
            )

        for bad_height in ("7", 7.0, True, -1, None):
            mutated = copy.deepcopy(good)
            mutated["height"] = bad_height
            rejects(mutated)
        for bad_hash in (root.upper(), "z" * 64, root[:63], 123, None):
            mutated = copy.deepcopy(good)
            mutated["block_hash"] = bad_hash
            rejects(mutated)
            mutated = copy.deepcopy(good)
            mutated["merkle_root"] = bad_hash
            rejects(mutated)
        # Bad expected anchors.
        self.assertFalse(crypto.verify_merkle_proof_bundle(good, "abc", root))
        self.assertFalse(crypto.verify_merkle_proof_bundle(good, self.block_hash, 7))

        # transaction_ids defects.
        mutated = copy.deepcopy(good)
        mutated["transaction_ids"] = []
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["transaction_ids"][0] = mutated["transaction_ids"][0].upper()
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["transaction_ids"].append(tx_ids[-1])  # duplicate
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["transaction_ids"] = list(reversed(good["transaction_ids"]))
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["transaction_ids"] = tuple(tx_ids)  # wrong type
        rejects(mutated)

        # proofs defects.
        mutated = copy.deepcopy(good)
        mutated["proofs"] = []
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"] = tuple(good["proofs"])
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["index"] = "1"
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["index"] = True
        rejects(mutated)

    def test_uniqueness_order_and_index_mapping(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(5)]
        good = make_bundle(tx_ids, [0, 2, 4], self.block_hash)
        root = good["merkle_root"]

        def rejects(mutated) -> None:
            self.assertFalse(
                crypto.verify_merkle_proof_bundle(mutated, self.block_hash, root)
            )

        # Duplicate proof tx_id.
        mutated = copy.deepcopy(good)
        mutated["proofs"].append(copy.deepcopy(mutated["proofs"][0]))
        rejects(mutated)
        # Proofs not ascending by tx_id.
        mutated = copy.deepcopy(good)
        mutated["proofs"].reverse()
        rejects(mutated)
        # Proof tx_id not in transaction_ids.
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["tx_id"] = h("foreign")
        rejects(mutated)
        # Index wrong / out of range / negative.
        for bad_index in (1, 99, -1):
            mutated = copy.deepcopy(good)
            mutated["proofs"][0]["index"] = bad_index
            rejects(mutated)
        # Index does not match the tx_id's position.
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["index"] = 3
        mutated["proofs"][0]["tx_id"] = tx_ids[0]
        rejects(mutated)

    def test_path_and_root_tampering(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        good = make_bundle(tx_ids, [0, 1, 2, 3], self.block_hash)
        root = good["merkle_root"]

        def rejects(mutated) -> None:
            self.assertFalse(
                crypto.verify_merkle_proof_bundle(mutated, self.block_hash, root)
            )

        # Flip a direction, tamper a sibling hash, illegal direction.
        mutated = copy.deepcopy(good)
        first = mutated["proofs"][0]["siblings"][0]
        first["direction"] = "left" if first["direction"] == "right" else "right"
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][1]["siblings"][0]["hash"] = h("tampered")
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][2]["siblings"][0]["direction"] = "up"
        rejects(mutated)
        # Sibling entry not a dict / path not a list / hash malformed.
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["siblings"][0] = "nope"
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["siblings"] = None
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["siblings"][0]["hash"] = "Z" * 64
        rejects(mutated)
        # Depth beyond any plausible tree.
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["siblings"] = [
            {"direction": "left", "hash": tx_ids[0]}
        ] * (crypto.MAX_MERKLE_DEPTH + 1)
        rejects(mutated)
        # Index too deep for the supplied path.
        mutated = copy.deepcopy(good)
        mutated["proofs"][3]["siblings"] = []
        rejects(mutated)

        # Tampered root / block hash / anchor mismatch.
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(good, self.block_hash, h("other-root"))
        )
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(good, h("other-block"), root)
        )
        mutated = copy.deepcopy(good)
        mutated["merkle_root"] = h("other-root")
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["block_hash"] = h("other-block")
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(mutated, self.block_hash, root)
        )
        # A tampered leaf list cannot be rescued by matching paths: the root is
        # recomputed straight from transaction_ids.
        mutated = copy.deepcopy(good)
        mutated["transaction_ids"][0] = h("tampered-leaf")
        rejects(mutated)

    def test_odd_self_pair_and_phantom_slot(self) -> None:
        # 3 leaves: the last (ascending) leaf starts with a right sibling equal
        # to itself when the level is odd.
        tx_ids = sorted([h(f"leaf-{i}") for i in range(3)])
        good = make_bundle(tx_ids, [2], self.block_hash)
        root = good["merkle_root"]
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(good, self.block_hash, root)
        )
        self.assertEqual(
            good["proofs"][0]["siblings"][0],
            {"direction": "right", "hash": tx_ids[2]},
        )
        # The phantom slot: a left self-sibling must never verify.
        mutated = copy.deepcopy(good)
        mutated["proofs"][0]["siblings"][0] = {
            "direction": "left",
            "hash": tx_ids[2],
        }
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(mutated, self.block_hash, root)
        )

    def test_non_dict_and_junk_inputs_never_raise(self) -> None:
        for junk in (None, 42, "string", [], [1], {"height": 1}, object()):
            self.assertFalse(
                crypto.verify_merkle_proof_bundle(junk, self.block_hash, h("r"))
            )


class BatchProofServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")), initial_balance=100_000
        )

    def tx(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine(self, confirm: bool = True) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        if confirm:
            status, body = self.svc.confirm_block(block["height"])
            self.assertEqual(status, 200, body)
        return block

    def fingerprint(self) -> tuple:
        store = self.svc.store
        return (
            store.generation,
            len(store.chain),
            sorted(store.pending),
            len(store.audit_events),
        )

    def test_full_and_subset_success_shape_and_order(self) -> None:
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
        ]
        block = self.mine()  # height 1, 3 txs
        ordered = sorted(ids)

        # Full batch.
        status, body = self.svc.get_proofs(1, {"tx_ids": ids})
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "merkle_root", "transaction_ids", "proofs"],
        )
        self.assertEqual(body["height"], 1)
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(body["merkle_root"], block["merkle_root"])
        self.assertEqual(body["transaction_ids"], ordered)
        # Proofs sorted by tx_id regardless of request order.
        self.assertEqual([p["tx_id"] for p in body["proofs"]], ordered)
        for position, proof in enumerate(body["proofs"]):
            self.assertEqual(list(proof.keys()), ["tx_id", "index", "siblings"])
            self.assertEqual(proof["tx_id"], ordered[position])
            self.assertEqual(proof["index"], position)
            for item in proof["siblings"]:
                self.assertEqual(list(item.keys()), ["direction", "hash"])
                self.assertIn(item["direction"], ("left", "right"))
                self.assertTrue(crypto.is_hex64(item["hash"]))
            # Every returned bundle fragment verifies offline.
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                body, block["block_hash"], block["merkle_root"]
            )
        )

        # A subset requested out of order: only those proofs, still ascending.
        requested = [ids[2], ids[0]]
        status, subset = self.svc.get_proofs(1, {"tx_ids": requested})
        self.assertEqual(status, 200, subset)
        self.assertEqual(subset["transaction_ids"], ordered)
        self.assertEqual(
            [p["tx_id"] for p in subset["proofs"]],
            sorted(requested),
        )
        self.assertEqual(
            [p["index"] for p in subset["proofs"]],
            [ordered.index(tx_id) for tx_id in sorted(requested)],
        )
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                subset, block["block_hash"], block["merkle_root"]
            )
        )

    def test_single_transaction_block(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        block = self.mine()
        status, body = self.svc.get_proofs(1, {"tx_ids": [tx_id]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["transaction_ids"], [tx_id])
        self.assertEqual(body["proofs"], [{"tx_id": tx_id, "index": 0, "siblings": []}])
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                body, block["block_hash"], block["merkle_root"]
            )
        )

    def test_malformed_bodies_are_400_and_state_untouched(self) -> None:
        self.tx(self.ka, self.A, self.B, 10)
        self.mine()
        valid = "a" * 64
        bad_bodies = [
            None,
            [],
            "nope",
            42,
            {},
            {"tx_ids": []},
            {"tx_ids": [valid, valid]},          # duplicate
            {"tx_ids": [valid]},                 # unknown id is 404, not 400
        ]
        # The first seven are 400; the unknown-but-well-formed id is 404.
        for body in bad_bodies[:-1]:
            before = self.fingerprint()
            status, error = self.svc.get_proofs(1, body)
            self.assertEqual(status, 400, (body, error))
            self.assertIn("error", error)
            self.assertEqual(self.fingerprint(), before)

        malformed_ids = [
            [valid, "b" * 63],
            [valid, "B" * 64],
            [valid, "z" * 64],
            [123],
            [None],
            [valid, 1.5],
        ]
        for ids in malformed_ids:
            before = self.fingerprint()
            status, error = self.svc.get_proofs(1, {"tx_ids": ids})
            self.assertEqual(status, 400, (ids, error))
            self.assertEqual(self.fingerprint(), before)

        # Extra keys and wrong wrapper types.
        for body in (
            {"tx_ids": [valid], "extra": 1},
            {"proofs": [valid]},
            {"tx_ids": valid},
            {"tx_ids": (valid,)},
            {"tx_ids": {valid}},
        ):
            before = self.fingerprint()
            status, error = self.svc.get_proofs(1, body)
            self.assertEqual(status, 400, (body, error))
            self.assertEqual(self.fingerprint(), before)

        # Unknown id remains a 404 lookup miss.
        status, error = self.svc.get_proofs(1, {"tx_ids": [valid]})
        self.assertEqual(status, 404, error)

    def test_lookup_semantics(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        self.mine()

        # Unknown / malformed heights.
        self.assertEqual(self.svc.get_proofs(99, {"tx_ids": [tx_id]})[0], 404)
        self.assertEqual(self.svc.get_proofs("x", {"tx_ids": [tx_id]})[0], 404)
        self.assertEqual(self.svc.get_proofs("01", {"tx_ids": [tx_id]})[0], 404)
        # Empty genesis never holds the transaction.
        self.assertEqual(self.svc.get_proofs(0, {"tx_ids": [tx_id]})[0], 404)
        # One missing id among valid ids makes the whole batch 404.
        other = self.tx(self.kb, self.B, self.A, 1)
        self.assertEqual(
            self.svc.get_proofs(1, {"tx_ids": [tx_id, "a" * 64]})[0], 404
        )
        # A transaction still in the mempool is not at any height.
        self.assertEqual(self.svc.get_proofs(1, {"tx_ids": [other]})[0], 404)

    def test_pending_block_is_409(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        self.mine(confirm=False)  # height 1 stays pending
        status, body = self.svc.get_proofs(1, {"tx_ids": [tx_id]})
        self.assertEqual(status, 409, body)


class BatchProofHttpTests(unittest.TestCase):
    """End-to-end checks against the stdlib HTTP server (random local port)."""

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
        url = f"{self.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
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

    def test_batch_endpoint_end_to_end(self) -> None:
        p1 = make_tx(self.ka, self.A, self.B, 10)
        p2 = make_tx(self.kb, self.B, self.A, 4)
        status, t1 = self.request("POST", "/v1/transactions", p1)
        self.assertEqual(status, 202)
        status, t2 = self.request("POST", "/v1/transactions", p2)
        self.assertEqual(status, 202)
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        height = block["height"]
        status, _ = self.request("POST", f"/v1/blocks/{height}/confirm", {})
        self.assertEqual(status, 200)

        # Request order need not be sorted; the response sorts proofs.
        req = urllib.request.Request(
            f"{self.base}/v1/blocks/{height}/proofs",
            data=json.dumps({"tx_ids": [t2["tx_id"], t1["tx_id"]]}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            status = resp.status
        body = json.loads(raw)
        self.assertEqual(status, 200)
        # The top-level key order is contract-fixed on the wire.
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "merkle_root", "transaction_ids", "proofs"],
        )
        self.assertTrue(raw.startswith('{"height"'))
        for earlier, later in (
            ("height", "block_hash"),
            ("block_hash", "merkle_root"),
            ("merkle_root", "transaction_ids"),
            ("transaction_ids", "proofs"),
        ):
            self.assertLess(raw.index(f'"{earlier}"'), raw.index(f'"{later}"'))
        self.assertEqual(body["height"], height)
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(body["merkle_root"], block["merkle_root"])
        self.assertEqual(body["transaction_ids"], sorted([t1["tx_id"], t2["tx_id"]]))
        self.assertEqual(
            [p["tx_id"] for p in body["proofs"]],
            sorted([t1["tx_id"], t2["tx_id"]]),
        )
        for proof in body["proofs"]:
            self.assertEqual(list(proof.keys()), ["tx_id", "index", "siblings"])
            for sibling in proof["siblings"]:
                self.assertEqual(list(sibling.keys()), ["direction", "hash"])
                self.assertIn(sibling["direction"], ("left", "right"))
                self.assertTrue(crypto.is_hex64(sibling["hash"]))

        # 400: invalid JSON, missing/extra keys, empty/duplicate/bad-format ids.
        self.assertEqual(self.post_raw(f"/v1/blocks/{height}/proofs", b"{not json")[0], 400)
        self.assertEqual(self.post_raw(f"/v1/blocks/{height}/proofs", b"")[0], 400)
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/proofs", [])[0], 400
        )
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/proofs", {})[0], 400
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/proofs",
                {"tx_ids": [t1["tx_id"]], "more": 1},
            )[0],
            400,
        )
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/proofs", {"tx_ids": []})[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/proofs",
                {"tx_ids": [t1["tx_id"], t1["tx_id"]]},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/proofs", {"tx_ids": [t1["tx_id"][:63]]}
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/proofs", {"tx_ids": ["Z" * 64]}
            )[0],
            400,
        )

        # 404: unknown height / missing transaction.
        self.assertEqual(
            self.request("POST", "/v1/blocks/999/proofs", {"tx_ids": [t1["tx_id"]]})[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/proofs", {"tx_ids": ["a" * 64]}
            )[0],
            404,
        )

    def test_pending_block_is_409_over_http(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 7)
        status, tx = self.request("POST", "/v1/transactions", payload)
        self.assertEqual(status, 202)
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        status, body = self.request(
            "POST", f"/v1/blocks/{block['height']}/proofs",
            {"tx_ids": [tx["tx_id"]]},
        )
        self.assertEqual(status, 409, body)


class CliBatchProofTests(unittest.TestCase):
    """CLI proofs subcommand over HTTP; output is one JSON line."""

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

    def test_proofs_cli(self) -> None:
        ids = []
        for key, sender, to, amount in (
            (self.ka, self.A, self.B, 12),
            (self.kb, self.B, self.A, 5),
        ):
            status, body = self.service.submit_transaction(
                make_tx(key, sender, to, amount)
            )
            self.assertEqual(status, 202, body)
            ids.append(body["tx_id"])
        _, block = self.service.mine_block()
        self.service.confirm_block(block["height"])

        rc, body, raw = self.run_cli("proofs", str(block["height"]), *ids)
        self.assertEqual(rc, 0, raw)
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "merkle_root", "transaction_ids", "proofs"],
        )
        # Contract-fixed key order preserved on the single printed line.
        for earlier, later in (
            ("height", "block_hash"),
            ("block_hash", "merkle_root"),
            ("merkle_root", "transaction_ids"),
            ("transaction_ids", "proofs"),
        ):
            self.assertLess(raw.index(f'"{earlier}"'), raw.index(f'"{later}"'))
        self.assertEqual(body["height"], block["height"])
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(len(body["proofs"]), 2)
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                body, block["block_hash"], block["merkle_root"]
            )
        )

        # Non-2xx responses still print one JSON line and exit 1.
        rc, error, _ = self.run_cli(
            "proofs", str(block["height"]), ids[0], ids[0]
        )  # duplicate -> 400
        self.assertEqual(rc, 1)
        self.assertIn("error", error)
        rc, error, _ = self.run_cli("proofs", "999", ids[0])  # unknown height -> 404
        self.assertEqual(rc, 1)
        self.assertIn("error", error)
        rc, error, _ = self.run_cli(
            "proofs", str(block["height"]), "malformed"
        )  # bad format -> 400
        self.assertEqual(rc, 1)
        self.assertIn("error", error)


if __name__ == "__main__":
    unittest.main(verbosity=2)

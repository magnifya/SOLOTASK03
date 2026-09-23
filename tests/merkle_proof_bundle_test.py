"""Tests for the batch Merkle proof endpoint and its offline verifier.

Covers:
- ledger.crypto.verify_merkle_proof_bundle: key order/sets, strict JSON
  types, unique/ordered ids, index mapping, leaf-to-root paths (incl. odd
  self-pairs), root and block-hash binding; every defect returns False.
- LedgerService.get_proofs: strict 400 body validation without state
  changes, 404 unknown height / missing transaction, 409 pending block,
  and the fixed response ordering.
- POST /v1/blocks/{height}/proofs over HTTP, including the exact on-wire
  key order at the top level, per proof and per sibling node, plus
  regressions for the confirm/rollback POST routes under /v1/blocks/.
- The `proofs HEIGHT TX_ID...` CLI subcommand: one JSON line preserving
  the wire order, exit 1 on every non-2xx response.

Run: python3 tests/merkle_proof_bundle_test.py
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


def bundle_for(tx_ids: list[str], subset: list[str], block_hash: str) -> dict:
    """Build a valid bundle for ``subset`` of the block's ordered leaves.

    Leaves are sorted ascending exactly like a mined block stores them.
    """
    tx_ids = sorted(tx_ids)
    root = crypto.merkle_root(tx_ids)
    proofs = []
    for tx_id in sorted(subset):
        index = tx_ids.index(tx_id)
        proofs.append({
            "tx_id": tx_id,
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


class BundleCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.block_hash = h("block")

    def test_valid_bundles_all_shapes_and_subsets(self) -> None:
        for n in range(1, 12):
            tx_ids = [h(f"tx-{n}-{i}") for i in range(n)]
            # Full set, a single leaf, and an arbitrary subset.
            subsets = [tx_ids[:], tx_ids[n // 2 : n // 2 + 1], tx_ids[::2]]
            for subset in subsets:
                if not subset:
                    continue
                bundle = bundle_for(tx_ids, subset, self.block_hash)
                self.assertTrue(
                    crypto.verify_merkle_proof_bundle(
                        bundle, self.block_hash, bundle["merkle_root"]
                    ),
                    (n, subset),
                )

    def test_single_transaction_bundle(self) -> None:
        tx_ids = [h("only")]
        bundle = bundle_for(tx_ids, tx_ids, self.block_hash)
        self.assertEqual(bundle["merkle_root"], tx_ids[0])
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(bundle, self.block_hash, tx_ids[0])
        )

    def test_wrong_anchors(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(5)]
        bundle = bundle_for(tx_ids, [tx_ids[1], tx_ids[3]], self.block_hash)
        good_root = bundle["merkle_root"]
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(bundle, h("other"), good_root)
        )
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(bundle, self.block_hash, h("other-root"))
        )
        # Expected anchors must themselves be well-formed hex.
        self.assertFalse(crypto.verify_merkle_proof_bundle(bundle, "x", good_root))
        self.assertFalse(crypto.verify_merkle_proof_bundle(bundle, self.block_hash, 1))
        self.assertFalse(crypto.verify_merkle_proof_bundle(None, self.block_hash, good_root))
        self.assertFalse(crypto.verify_merkle_proof_bundle([], self.block_hash, good_root))

    def test_top_level_key_set_and_order(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        good = bundle_for(tx_ids, [tx_ids[0]], self.block_hash)
        root = good["merkle_root"]
        # Reordered keys are rejected even though the content is identical.
        reordered = {key: good[key] for key in reversed(list(good))}
        self.assertFalse(crypto.verify_merkle_proof_bundle(reordered, self.block_hash, root))
        # Missing and extra keys.
        for key in list(good):
            missing = dict(good)
            del missing[key]
            self.assertFalse(
                crypto.verify_merkle_proof_bundle(missing, self.block_hash, root), key
            )
        extra = dict(good)
        extra["unexpected"] = 1
        self.assertFalse(crypto.verify_merkle_proof_bundle(extra, self.block_hash, root))

    def test_nested_key_set_and_order(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        good = bundle_for(tx_ids, [tx_ids[1]], self.block_hash)
        root = good["merkle_root"]

        bad = json.loads(json.dumps(good))
        # Proof document key order / extra key.
        bad["proofs"][0] = {"siblings": good["proofs"][0]["siblings"],
                           "index": good["proofs"][0]["index"],
                           "tx_id": good["proofs"][0]["tx_id"]}
        self.assertFalse(crypto.verify_merkle_proof_bundle(bad, self.block_hash, root))
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["extra"] = 1
        self.assertFalse(crypto.verify_merkle_proof_bundle(bad, self.block_hash, root))
        del bad["proofs"][0]["extra"]
        del bad["proofs"][0]["index"]
        self.assertFalse(crypto.verify_merkle_proof_bundle(bad, self.block_hash, root))

        # Sibling node key order / extra key (need a multi-leaf tree).
        deep = bundle_for(tx_ids, [tx_ids[0]], self.block_hash)
        self.assertTrue(deep["proofs"][0]["siblings"])
        tampered = json.loads(json.dumps(deep))
        first = tampered["proofs"][0]["siblings"][0]
        tampered["proofs"][0]["siblings"][0] = {"hash": first["hash"],
                                               "direction": first["direction"]}
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(tampered, self.block_hash, root)
        )
        tampered = json.loads(json.dumps(deep))
        tampered["proofs"][0]["siblings"][0]["side"] = "L"
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(tampered, self.block_hash, root)
        )

    def test_transaction_id_rules(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        good = bundle_for(tx_ids, [tx_ids[0]], self.block_hash)
        root = good["merkle_root"]
        verify = crypto.verify_merkle_proof_bundle

        bad = json.loads(json.dumps(good))
        bad["transaction_ids"] = []
        self.assertFalse(verify(bad, self.block_hash, root))
        bad = json.loads(json.dumps(good))
        bad["transaction_ids"] = "nope"
        self.assertFalse(verify(bad, self.block_hash, root))
        bad = json.loads(json.dumps(good))
        bad["transaction_ids"][0] = tx_ids[0].upper()
        self.assertFalse(verify(bad, self.block_hash, root))
        bad = json.loads(json.dumps(good))
        bad["transaction_ids"][0] = tx_ids[0][:63]
        self.assertFalse(verify(bad, self.block_hash, root))
        # Duplicate leaves.
        bad = json.loads(json.dumps(good))
        bad["transaction_ids"] = list(tx_ids) + [tx_ids[-1]]
        self.assertFalse(verify(bad, self.block_hash, h("whatever")))
        # Leaves out of ascending order change the root.
        bad = json.loads(json.dumps(good))
        shuffled = list(tx_ids)
        shuffled[0], shuffled[1] = shuffled[1], shuffled[0]
        bad["transaction_ids"] = shuffled
        self.assertFalse(verify(bad, self.block_hash, root))
        # Claiming a different root over the same leaves.
        bad = json.loads(json.dumps(good))
        bad["merkle_root"] = h("not-the-root")
        self.assertFalse(verify(bad, self.block_hash, root))

    def test_proof_list_rules(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(6)]
        good = bundle_for(tx_ids, [tx_ids[1], tx_ids[4]], self.block_hash)
        root = good["merkle_root"]
        verify = crypto.verify_merkle_proof_bundle

        bad = json.loads(json.dumps(good))
        bad["proofs"] = []
        self.assertFalse(verify(bad, self.block_hash, root))
        bad = json.loads(json.dumps(good))
        bad["proofs"] = "nope"
        self.assertFalse(verify(bad, self.block_hash, root))
        # Proofs not ordered by ascending tx_id.
        bad = json.loads(json.dumps(good))
        bad["proofs"] = list(reversed(json.loads(json.dumps(good["proofs"]))))
        self.assertFalse(verify(bad, self.block_hash, root))
        # Duplicate proof tx_ids.
        bad = json.loads(json.dumps(good))
        bad["proofs"].append(json.loads(json.dumps(bad["proofs"][0])))
        self.assertFalse(verify(bad, self.block_hash, root))
        # Proof for an id not in the block's leaf list.
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["tx_id"] = h("foreign")
        self.assertFalse(verify(bad, self.block_hash, root))
        # More proofs than leaves.
        bad = json.loads(json.dumps(good))
        bad["proofs"] = [
            {"tx_id": tx_id, "index": i,
             "siblings": crypto.merkle_proof(tx_ids, i)}
            for i, tx_id in enumerate(tx_ids)
        ]
        bad["proofs"].append(json.loads(json.dumps(bad["proofs"][0])))
        self.assertFalse(verify(bad, self.block_hash, root))

    def test_index_rules(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        good = bundle_for(tx_ids, [tx_ids[2]], self.block_hash)
        root = good["merkle_root"]
        verify = crypto.verify_merkle_proof_bundle

        for bad_index in (-1, 4, 99, "2", True, False, 2.0):
            bad = json.loads(json.dumps(good))
            bad["proofs"][0]["index"] = bad_index
            self.assertFalse(
                verify(bad, self.block_hash, root), bad_index
            )
        # In-range but pointing at another leaf.
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["index"] = 1
        self.assertFalse(verify(bad, self.block_hash, root))

    def test_height_types(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(3)]
        good = bundle_for(tx_ids, [tx_ids[0]], self.block_hash)
        root = good["merkle_root"]
        for bad_height in (-1, "7", 7.0, True, None):
            bad = json.loads(json.dumps(good))
            bad["height"] = bad_height
            self.assertFalse(
                crypto.verify_merkle_proof_bundle(bad, self.block_hash, root),
                bad_height,
            )

    def test_path_tampering(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(5)]
        good = bundle_for(tx_ids, [tx_ids[0], tx_ids[3]], self.block_hash)
        root = good["merkle_root"]
        verify = crypto.verify_merkle_proof_bundle

        # Tamper one sibling hash.
        bad = json.loads(json.dumps(good))
        first = bad["proofs"][0]["siblings"][0]
        first["hash"] = h("tampered")
        self.assertFalse(verify(bad, self.block_hash, root))
        # Illegal / missing direction.
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["siblings"][0]["direction"] = "up"
        self.assertFalse(verify(bad, self.block_hash, root))
        bad = json.loads(json.dumps(good))
        del bad["proofs"][0]["siblings"][0]["direction"]
        self.assertFalse(verify(bad, self.block_hash, root))
        # Sibling hash not lowercase hex.
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["siblings"][0]["hash"] = "Z" * 64
        self.assertFalse(verify(bad, self.block_hash, root))
        # Sibling node not a dict; path not a list.
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["siblings"][0] = "nope"
        self.assertFalse(verify(bad, self.block_hash, root))
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["siblings"] = None
        self.assertFalse(verify(bad, self.block_hash, root))
        # A direction disagreeing with the index position fails.
        bad = json.loads(json.dumps(good))
        node = bad["proofs"][0]["siblings"][0]
        # tx index 0 is the left child: its sibling must be on the right.
        node["direction"] = "left"
        self.assertFalse(verify(bad, self.block_hash, root))
        # Path longer than any plausible tree.
        deep = [{"direction": "left", "hash": tx_ids[0]}] * 65
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["siblings"] = deep
        self.assertFalse(verify(bad, self.block_hash, root))

    def test_phantom_self_pair_rejected(self) -> None:
        # A 3-leaf tree: the odd last leaf genuinely pairs with itself via a
        # *right* sibling; a fabricated *left* self-sibling is the phantom
        # duplicate slot and must be rejected.
        tx_ids = sorted([h("a"), h("b"), h("c")])
        good = bundle_for(tx_ids, [tx_ids[2]], self.block_hash)
        self.assertEqual(
            good["proofs"][0]["siblings"][0],
            {"direction": "right", "hash": tx_ids[2]},
        )
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                good, self.block_hash, good["merkle_root"]
            )
        )
        bad = json.loads(json.dumps(good))
        bad["proofs"][0]["siblings"][0] = {"direction": "left", "hash": tx_ids[2]}
        # Index 2 is even, so a left sibling is both a phantom self-pair and
        # a position contradiction: either way it must fail.
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(bad, self.block_hash, good["merkle_root"])
        )

    def test_block_hash_tampering(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(3)]
        good = bundle_for(tx_ids, [tx_ids[0]], self.block_hash)
        bad = json.loads(json.dumps(good))
        bad["block_hash"] = h("other-block")
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(bad, self.block_hash, good["merkle_root"])
        )
        bad = json.loads(json.dumps(good))
        bad["block_hash"] = good["block_hash"].upper()
        self.assertFalse(
            crypto.verify_merkle_proof_bundle(bad, self.block_hash, good["merkle_root"])
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

    def mine_confirmed(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        status, body = self.svc.confirm_block(block["height"])
        self.assertEqual(status, 200, body)
        return block

    def test_batch_success_shape_order_and_content(self) -> None:
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
            self.tx(self.kb, self.B, self.A, 9),
        ]
        block = self.mine_confirmed()
        ordered = sorted(ids)

        # Requested out of order; the response is still tx_id-sorted.
        status, bundle = self.svc.get_proofs(1, {"tx_ids": [ids[3], ids[0]]})
        self.assertEqual(status, 200, bundle)
        self.assertEqual(
            list(bundle),
            ["height", "block_hash", "merkle_root", "transaction_ids", "proofs"],
        )
        self.assertEqual(bundle["height"], 1)
        self.assertEqual(bundle["block_hash"], block["block_hash"])
        self.assertEqual(bundle["merkle_root"], block["merkle_root"])
        self.assertEqual(bundle["transaction_ids"], ordered)
        requested = sorted([ids[3], ids[0]])
        self.assertEqual([p["tx_id"] for p in bundle["proofs"]], requested)
        for proof in bundle["proofs"]:
            self.assertEqual(list(proof), ["tx_id", "index", "siblings"])
            index = ordered.index(proof["tx_id"])
            self.assertEqual(proof["index"], index)
            for sibling in proof["siblings"]:
                self.assertEqual(list(sibling), ["direction", "hash"])
                self.assertIn(sibling["direction"], ("left", "right"))
                self.assertTrue(crypto.is_hex64(sibling["hash"]))
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                bundle, block["block_hash"], block["merkle_root"]
            )
        )

    def test_request_all_and_single(self) -> None:
        ids = sorted([
            self.tx(self.ka, self.A, self.B, 1),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 3),
        ])
        block = self.mine_confirmed()
        status, bundle = self.svc.get_proofs("1", {"tx_ids": ids})
        self.assertEqual(status, 200)
        self.assertEqual(
            [p["tx_id"] for p in bundle["proofs"]], bundle["transaction_ids"]
        )
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                bundle, block["block_hash"], block["merkle_root"]
            )
        )
        status, one = self.svc.get_proofs(1, {"tx_ids": [ids[1]]})
        self.assertEqual(status, 200)
        self.assertEqual(len(one["proofs"]), 1)
        self.assertEqual(one["proofs"][0]["index"], 1)

    def test_empty_genesis_is_404_even_for_valid_body(self) -> None:
        status, body = self.svc.get_proofs(0, {"tx_ids": ["a" * 64]})
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_bad_bodies_are_400(self) -> None:
        ids = [self.tx(self.ka, self.A, self.B, 1)]
        block = self.mine_confirmed()
        call = self.svc.get_proofs

        bad_bodies = [
            None,
            [],
            "nope",
            42,
            {},
            {"tx_ids": ids, "extra": 1},
            {"txid": ids},
            {"tx_ids": None},
            {"tx_ids": "nope"},
            {"tx_ids": []},
            {"tx_ids": [ids[0], ids[0]]},
            {"tx_ids": [ids[0].upper()]},
            {"tx_ids": [ids[0][:63]]},
            {"tx_ids": ["z" * 64]},
            {"tx_ids": [123]},
            {"tx_ids": [True]},
            {"tx_ids": [ids[0], None]},
        ]
        for body in bad_bodies:
            status, error = call(block["height"], body)
            self.assertEqual(status, 400, (body, error))
            self.assertIn("error", error)

    def test_malformed_height_and_missing_tx_are_404(self) -> None:
        ids = [self.tx(self.ka, self.A, self.B, 1)]
        self.mine_confirmed()
        body = {"tx_ids": ids}
        for height in ("x", "1.0", "01", -1, 99):
            self.assertEqual(self.svc.get_proofs(height, body)[0], 404, height)
        # Unknown transaction at a known height.
        status, _ = self.svc.get_proofs(1, {"tx_ids": ["a" * 64]})
        self.assertEqual(status, 404)
        # One missing id in the batch fails the whole request.
        status, _ = self.svc.get_proofs(1, {"tx_ids": [ids[0], "b" * 64]})
        self.assertEqual(status, 404)

    def test_pending_block_is_409(self) -> None:
        ids = [self.tx(self.ka, self.A, self.B, 1)]
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201)
        self.assertEqual(block["status"], "pending")
        status, _ = self.svc.get_proofs(block["height"], {"tx_ids": ids})
        self.assertEqual(status, 409)

    def test_read_only(self) -> None:
        ids = [self.tx(self.ka, self.A, self.B, 1)]
        self.mine_confirmed()
        before = [b.to_summary() for b in self.svc.store.chain]
        mempool_before = set(self.svc.store.pending)
        for body in (
            {"tx_ids": []},
            {"tx_ids": ["z" * 64]},
            {"tx_ids": [ids[0], ids[0]]},
            {"nope": 1},
            "garbage",
        ):
            self.svc.get_proofs(1, body)
        self.assertEqual([b.to_summary() for b in self.svc.store.chain], before)
        self.assertEqual(set(self.svc.store.pending), mempool_before)
        # A failed lookup leaves no partial state either.
        self.svc.get_proofs(99, {"tx_ids": ids})
        self.assertEqual([b.to_summary() for b in self.svc.store.chain], before)


class BatchProofHttpTests(unittest.TestCase):
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

    def raw_post(self, path: str, raw: bytes) -> tuple[int, bytes]:
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def post(self, path: str, payload) -> tuple[int, dict]:
        status, raw = self.raw_post(path, json.dumps(payload).encode())
        return status, json.loads(raw.decode())

    def test_endpoint_wire_order_and_statuses(self) -> None:
        t1 = make_tx(self.ka, self.A, self.B, 10)
        t2 = make_tx(self.kb, self.B, self.A, 4)
        status, r1 = self.post("/v1/transactions", t1)
        self.assertEqual(status, 202)
        status, r2 = self.post("/v1/transactions", t2)
        self.assertEqual(status, 202)
        status, block = self.post("/v1/blocks", {})
        self.assertEqual(status, 201)
        height = block["height"]
        status, _ = self.post(f"/v1/blocks/{height}/confirm", {})
        self.assertEqual(status, 200)

        # Requested out of order; inspect the raw bytes for exact key order.
        status, raw = self.raw_post(
            f"/v1/blocks/{height}/proofs",
            json.dumps({"tx_ids": [r2["tx_id"], r1["tx_id"]]}).encode(),
        )
        self.assertEqual(status, 200, raw)
        text = raw.decode()
        self.assertLess(text.index('"height"'), text.index('"block_hash"'))
        self.assertLess(text.index('"block_hash"'), text.index('"merkle_root"'))
        self.assertLess(text.index('"merkle_root"'), text.index('"transaction_ids"'))
        self.assertLess(text.index('"transaction_ids"'), text.index('"proofs"'))
        bundle = json.loads(text)
        self.assertEqual(
            [p["tx_id"] for p in bundle["proofs"]],
            sorted([r1["tx_id"], r2["tx_id"]]),
        )
        proof_text = text[text.index('"proofs"'):]
        # Each proof: tx_id before index before siblings; nodes: direction before hash.
        self.assertLess(proof_text.index('"tx_id"'), proof_text.index('"index"'))
        self.assertLess(proof_text.index('"index"'), proof_text.index('"siblings"'))
        self.assertLess(
            proof_text.index('"direction"'), proof_text.index('"hash"')
        )
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                bundle, block["block_hash"], block["merkle_root"]
            )
        )

        # 400: malformed JSON, wrong shape, empty, duplicates, bad hex.
        self.assertEqual(self.raw_post(f"/v1/blocks/{height}/proofs", b"{not json")[0], 400)
        self.assertEqual(self.post(f"/v1/blocks/{height}/proofs", [])[0], 400)
        self.assertEqual(self.post(f"/v1/blocks/{height}/proofs", {})[0], 400)
        self.assertEqual(
            self.post(f"/v1/blocks/{height}/proofs", {"tx_ids": [], "x": 1})[0], 400
        )
        self.assertEqual(
            self.post(f"/v1/blocks/{height}/proofs", {"tx_ids": []})[0], 400
        )
        self.assertEqual(
            self.post(
                f"/v1/blocks/{height}/proofs", {"tx_ids": [r1["tx_id"], r1["tx_id"]]}
            )[0],
            400,
        )
        self.assertEqual(
            self.post(f"/v1/blocks/{height}/proofs", {"tx_ids": ["ABC"]})[0], 400
        )
        # 404: unknown height, missing tx.
        self.assertEqual(
            self.post("/v1/blocks/999/proofs", {"tx_ids": [r1["tx_id"]]})[0], 404
        )
        self.assertEqual(
            self.post(f"/v1/blocks/{height}/proofs", {"tx_ids": ["a" * 64]})[0], 404
        )
        self.assertEqual(
            self.post("/v1/blocks/01/proofs", {"tx_ids": [r1["tx_id"]]})[0], 404
        )
        self.assertEqual(
            self.post("/v1/blocks/x/proofs", {"tx_ids": [r1["tx_id"]]})[0], 404
        )

    def test_pending_block_409_and_route_regressions(self) -> None:
        tx = make_tx(self.ka, self.A, self.B, 7)
        status, receipt = self.post("/v1/transactions", tx)
        self.assertEqual(status, 202)
        status, block = self.post("/v1/blocks", {})
        self.assertEqual(status, 201)
        height = block["height"]
        self.assertEqual(
            self.post(f"/v1/blocks/{height}/proofs", {"tx_ids": [receipt["tx_id"]]})[0],
            409,
        )
        # The generic /v1/blocks/{height} POST routes must still work with the
        # new /proofs branch installed.
        status, body = self.post(f"/v1/blocks/{height}/confirm", {})
        self.assertEqual(status, 200, body)
        # Single-proof GET regression.
        status, proof = self.request_get(f"/v1/blocks/{height}/proof/{receipt['tx_id']}")
        self.assertEqual(status, 200, proof)

    def request_get(self, path: str) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())


class CliBatchProofTests(unittest.TestCase):
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

    def run_cli(self, *args) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, raw

    def test_proofs_cli(self) -> None:
        payload1 = make_tx(self.ka, self.A, self.B, 12)
        payload2 = make_tx(self.kb, self.B, self.A, 5)
        self.assertEqual(self.service.submit_transaction(payload1)[0], 202)
        self.assertEqual(self.service.submit_transaction(payload2)[0], 202)
        _, block = self.service.mine_block()
        self.service.confirm_block(block["height"])
        block_obj = self.service.store.chain[block["height"]]
        tx1 = block_obj.transactions[0].tx_id
        tx2 = block_obj.transactions[-1].tx_id

        # Out-of-order args; output keeps the server-mandated orders and key
        # sequence verbatim on one JSON line.
        rc, raw = self.run_cli("proofs", str(block["height"]), tx2, tx1)
        self.assertEqual(rc, 0, raw)
        self.assertLess(raw.index('"height"'), raw.index('"block_hash"'))
        self.assertLess(raw.index('"block_hash"'), raw.index('"merkle_root"'))
        self.assertLess(raw.index('"merkle_root"'), raw.index('"transaction_ids"'))
        self.assertLess(raw.index('"transaction_ids"'), raw.index('"proofs"'))
        bundle = json.loads(raw)
        self.assertEqual([p["tx_id"] for p in bundle["proofs"]], sorted([tx1, tx2]))
        self.assertTrue(
            crypto.verify_merkle_proof_bundle(
                bundle, block["block_hash"], block["merkle_root"]
            )
        )

        # Zero tx_ids: argparse nargs='+' rejects it with exit code 2
        # (asserted in test_proofs_requires_an_id), not an HTTP response.

    def test_proofs_failures_exit_1(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 1)
        self.service.submit_transaction(payload)
        _, block = self.service.mine_block()
        height = block["height"]  # still pending
        tx_id = self.service.store.chain[height].transactions[0].tx_id

        rc, raw = self.run_cli("proofs", str(height), tx_id)
        self.assertEqual(rc, 1)
        self.assertIn("error", json.loads(raw))
        self.service.confirm_block(height)

        rc, raw = self.run_cli("proofs", "999", tx_id)
        self.assertEqual(rc, 1)
        self.assertIn("error", json.loads(raw))
        rc, raw = self.run_cli("proofs", str(height), "a" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("error", json.loads(raw))
        rc, raw = self.run_cli("proofs", str(height), tx_id, tx_id)
        self.assertEqual(rc, 1)
        self.assertIn("error", json.loads(raw))

    def test_proofs_requires_an_id(self) -> None:
        # argparse nargs='+' rejects zero tx_ids with exit code 2.
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                cli_main(["--base-url", self.base_url, "proofs", "1"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()

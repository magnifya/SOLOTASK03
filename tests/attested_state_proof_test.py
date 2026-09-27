"""Tests for the signed (attested) account-state proof.

Covers:

* GET /v1/accounts/{account}/attested-proof service semantics: optional single
  ``height`` with the same strict rules as /proof (malformed/repeated/unknown
  parameter 400; unknown/non-canonical/pending anchor and missing account 404),
  the fixed wire key order state, proof, auth (state reusing state-root fields,
  proof reusing state-proof fields, auth = {key_version, signature});
* the chain, state tree and audit signer snapshotted under one lock and the
  Ed25519 signature over
  SHA256(UTF8("ledger-state-proof-v1") || canonical_json(document without auth));
* ledger.light_client.verify_state_proof: key-order/type/hex/trust input
  failures, unknown-version/bad-signature auth failures, account/anchor/index/
  Merkle-path integrity failures, the fixed success key order, historical
  verification after signer rotation, and never raising on garbage;
* the HTTP route and wire key order.

Run: python3 tests/attested_state_proof_test.py
"""
from __future__ import annotations

import copy
import hashlib
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

from ledger import crypto, light_client
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


class AttestedStateProofServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=100_000,
        )
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 100))
        self.svc.submit_transaction(make_tx(self.kc, self.C, self.A, 40))
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        status, _ = self.svc.confirm_block(1)
        self.assertEqual(status, 200)
        self.block_hash = self.svc.store.chain[1].block_hash
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)

    def document(self, account: str, params=None) -> tuple[int, dict]:
        return self.svc.get_attested_account_proof(account, params)

    def test_success_key_order_and_fields(self) -> None:
        status, doc = self.document(self.A)
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["state", "proof", "auth"])
        self.assertEqual(
            list(doc["state"]),
            ["state_root", "height", "block_hash", "account_count"],
        )
        self.assertEqual(
            list(doc["proof"]),
            ["account", "balance", "confirmed_transactions", "index",
             "state_root", "height", "block_hash", "siblings"],
        )
        self.assertEqual(list(doc["auth"]), ["key_version", "signature"])
        self.assertEqual(doc["state"]["height"], 1)
        self.assertEqual(doc["state"]["block_hash"], self.block_hash)
        self.assertEqual(doc["state"]["account_count"], 3)
        self.assertEqual(doc["proof"]["account"], self.A)
        self.assertEqual(doc["proof"]["height"], 1)
        self.assertEqual(doc["proof"]["block_hash"], self.block_hash)
        self.assertTrue(crypto.is_hex128(doc["auth"]["signature"]))
        self.assertEqual(doc["auth"]["key_version"], 1)
        # State and proof anchor fields agree.
        self.assertEqual(
            doc["state"]["state_root"], doc["proof"]["state_root"])

    def test_signature_uses_state_proof_domain(self) -> None:
        status, doc = self.document(self.B)
        self.assertEqual(status, 200, doc)
        public_key = self.trust["audit_signers"][0]["public_key"]
        unsigned = {"state": doc["state"], "proof": doc["proof"]}
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = hashlib.sha256(
            b"ledger-state-proof-v1" + canonical
        ).digest()
        self.assertTrue(
            crypto.verify_signature(
                public_key, digest, doc["auth"]["signature"])
        )
        # No other domain may authenticate the same body.
        for domain in (b"ledger-headers-v1", b"ledger-finality-v1"):
            self.assertFalse(
                crypto.verify_signature(
                    public_key,
                    hashlib.sha256(domain + canonical).digest(),
                    doc["auth"]["signature"],
                )
            )

    def test_height_parameter_rules(self) -> None:
        # A valid historical anchor re-verifies offline.
        status, doc = self.document(self.A, {"height": "1"})
        self.assertEqual(status, 200, doc)
        self.assertEqual(
            light_client.verify_state_proof(doc, self.A, self.trust)["ok"],
            True,
        )
        # Malformed/unknown query parameters are 400.
        for value in ("01", "-1", "x", "1.0", "", " 1"):
            self.assertEqual(
                self.document(self.A, {"height": value})[0], 400, value
            )
        self.assertEqual(
            self.document(self.A, {"foo": "1"})[0], 400
        )
        # Unknown height is 404; an account absent at the historical state is
        # 404 too (A/B/C do not exist at genesis).
        self.assertEqual(
            self.document(self.A, {"height": "99"})[0], 404)
        self.assertEqual(
            self.document(self.A, {"height": "0"})[0], 404)

    def test_missing_account_and_pending_tip_404(self) -> None:
        self.assertEqual(self.document("0" * 64)[0], 404)
        status, _ = self.svc.submit_transaction(
            make_tx(self.kb, self.B, self.C, 5))
        self.assertEqual(status, 202)
        status, _ = self.svc.mine_block()
        self.assertEqual(status, 201)
        self.assertEqual(self.document(self.A)[0], 404)
        self.assertEqual(
            self.document(self.A, {"height": "2"})[0], 404)
        # Historical confirmed anchors remain available.
        self.assertEqual(
            self.document(self.A, {"height": "1"})[0], 200)


class VerifyStateProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=100_000,
        )
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 100))
        status, _ = self.svc.mine_block()
        self.assertEqual(status, 201)
        status, _ = self.svc.confirm_block(1)
        self.assertEqual(status, 200)
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        status, self.doc = self.svc.get_attested_account_proof(self.A)
        self.assertEqual(status, 200, self.doc)

    def verify(self, document=None, account=None, trust=None):
        return light_client.verify_state_proof(
            self.doc if document is None else document,
            self.A if account is None else account,
            self.trust if trust is None else trust,
        )

    def test_success_shape(self) -> None:
        result = self.verify()
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result),
            ["ok", "account", "height", "block_hash", "state_root"],
        )
        self.assertEqual(result["account"], self.A)
        self.assertEqual(result["height"], 1)
        self.assertEqual(
            result["block_hash"], self.doc["state"]["block_hash"])
        self.assertEqual(
            result["state_root"], self.doc["state"]["state_root"])

    def test_account_mismatch_is_integrity(self) -> None:
        self.assertEqual(
            self.verify(account=self.B),
            {"ok": False, "error": "integrity"},
        )

    def test_bad_account_pin_is_input(self) -> None:
        for pin in (7, b"x", "ZZ", "a" * 63, "A" * 64):
            self.assertEqual(
                light_client.verify_state_proof(
                    self.doc, pin, self.trust)["error"], "input", pin)

    def test_structure_input_failures(self) -> None:
        self.assertEqual(
            self.verify(document=[])["error"], "input")
        self.assertEqual(
            self.verify(document={"x": 1})["error"], "input")
        # Wrong top-level key order / missing / extra keys.
        reordered = {
            "proof": self.doc["proof"],
            "state": self.doc["state"],
            "auth": self.doc["auth"],
        }
        self.assertEqual(self.verify(document=reordered)["error"], "input")
        missing = {"state": self.doc["state"], "proof": self.doc["proof"]}
        self.assertEqual(self.verify(document=missing)["error"], "input")
        extra = dict(self.doc, extra=1)
        self.assertEqual(self.verify(document=extra)["error"], "input")
        # Nested key order defects.
        state_bad_order = {
            "height": self.doc["state"]["height"],
            "state_root": self.doc["state"]["state_root"],
            "block_hash": self.doc["state"]["block_hash"],
            "account_count": self.doc["state"]["account_count"],
        }
        bad = copy.deepcopy(self.doc)
        bad["state"] = state_bad_order
        self.assertEqual(self.verify(document=bad)["error"], "input")
        # Wrong types.
        for field, value in (
            ("height", True),
            ("height", "1"),
            ("account_count", -1),
            ("state_root", "z" * 64),
            ("block_hash", 7),
        ):
            bad = copy.deepcopy(self.doc)
            bad["state"] = {**bad["state"], field: value}
            self.assertEqual(
                self.verify(document=bad)["error"], "input", (field, value))
        for field, value in (
            ("index", True),
            ("index", -1),
            ("balance", -1),
            ("balance", False),
            ("account", "nothex"),
            ("confirmed_transactions", ("x",)),
        ):
            bad = copy.deepcopy(self.doc)
            bad["proof"] = {**bad["proof"], field: value}
            self.assertEqual(
                self.verify(document=bad)["error"], "input", (field, value))
        # Malformed siblings.
        bad = copy.deepcopy(self.doc)
        bad["proof"]["siblings"] = [{"direction": "up", "hash": "a" * 64}]
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["proof"]["siblings"] = [{"direction": "left", "hash": "ZZ"}]
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["proof"]["siblings"] = [{"direction": "left", "hash": "a" * 64,
                                     "extra": 1}]
        self.assertEqual(self.verify(document=bad)["error"], "input")

    def test_auth_input_failures(self) -> None:
        for version, signature in (
            (0, self.doc["auth"]["signature"]),
            (-1, self.doc["auth"]["signature"]),
            (True, self.doc["auth"]["signature"]),
            ("1", self.doc["auth"]["signature"]),
            (1, "z" * 128),
            (1, "a" * 127),
            (1, 9),
        ):
            bad = copy.deepcopy(self.doc)
            bad["auth"] = {"key_version": version, "signature": signature}
            self.assertEqual(
                self.verify(document=bad)["error"], "input",
                (version, signature),
            )

    def test_auth_failures(self) -> None:
        # Unknown version.
        bad = copy.deepcopy(self.doc)
        bad["auth"] = {**bad["auth"], "key_version": 42}
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "auth"})
        # Well-shaped but wrong signature.
        bad = copy.deepcopy(self.doc)
        sig = bad["auth"]["signature"]
        flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
        bad["auth"] = {**bad["auth"], "signature": flipped}
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "auth"})
        # A trust document without usable audit signers is an input defect.
        self.assertEqual(
            self.verify(trust={"genesis_hash": "0" * 64})["error"], "input")

    def test_integrity_failures(self) -> None:
        signer = self.svc.store.audit_signer
        # Tamper with the leaf triple, then re-sign with the current key: the
        # structure and signature are valid but the Merkle path no longer
        # recomputes.
        bad = copy.deepcopy(self.doc)
        bad["proof"] = {**bad["proof"], "balance": 1}
        bad["auth"] = light_client.sign_state_proof(
            signer["private_key"], signer["version"], bad["state"], bad["proof"]
        )
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})
        # Index outside account_count.
        bad = copy.deepcopy(self.doc)
        bad["proof"] = {**bad["proof"], "index": 99}
        bad["auth"] = light_client.sign_state_proof(
            signer["private_key"], signer["version"], bad["state"], bad["proof"]
        )
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})
        # State/proof anchor disagreement.
        bad = copy.deepcopy(self.doc)
        bad["proof"] = {
            **bad["proof"], "height": 0,
            "block_hash": self.svc.store.chain[0].block_hash,
        }
        bad["auth"] = light_client.sign_state_proof(
            signer["private_key"], signer["version"], bad["state"], bad["proof"]
        )
        self.assertEqual(
            self.verify(document=bad)["error"], "integrity")

    def test_single_leaf_tree_empty_siblings(self) -> None:
        # A one-leaf tree carries an empty sibling path and the leaf itself is
        # the root; such a document (signed by the trusted audit key) must
        # verify offline with index 0 and account_count 1.
        account = "b" * 64
        leaf = crypto.account_state_leaf(account, 42, [])
        block_hash = "c" * 64
        state = {
            "state_root": leaf,
            "height": 7,
            "block_hash": block_hash,
            "account_count": 1,
        }
        proof = {
            "account": account,
            "balance": 42,
            "confirmed_transactions": [],
            "index": 0,
            "state_root": leaf,
            "height": 7,
            "block_hash": block_hash,
            "siblings": [],
        }
        signer = self.svc.store.audit_signer
        auth = light_client.sign_state_proof(
            signer["private_key"], signer["version"], state, proof)
        document = {"state": state, "proof": proof, "auth": auth}
        result = light_client.verify_state_proof(
            document, account, self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["height"], 7)
        # An index of 1 against a single leaf is out of range (integrity once
        # re-signed).
        bad_proof = {**proof, "index": 1}
        bad_auth = light_client.sign_state_proof(
            signer["private_key"], signer["version"], state, bad_proof)
        self.assertEqual(
            light_client.verify_state_proof(
                {"state": state, "proof": bad_proof, "auth": bad_auth},
                account, self.trust),
            {"ok": False, "error": "integrity"},
        )

    def test_never_raises_on_garbage(self) -> None:
        for document in (None, 5, "x", object(), {"state": 1},
                         {"state": {}, "proof": {}, "auth": {}}):
            for account in (None, object(), self.A):
                for trust in (None, 7, object(), self.trust):
                    result = light_client.verify_state_proof(
                        document, account, trust)
                    self.assertIn(result.get("ok"), (True, False))
                    if result["ok"] is False:
                        self.assertEqual(set(result), {"ok", "error"})

    def test_verifies_after_signer_rotation(self) -> None:
        old_doc = copy.deepcopy(self.doc)
        seed = crypto.generate_private_key()
        status, body = self.svc.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1})
        self.assertEqual(status, 200, body)
        status, new_trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        # The old version-1 document still verifies via the historical key.
        result = light_client.verify_state_proof(
            old_doc, self.A, new_trust)
        self.assertTrue(result["ok"], result)
        # A fresh document is signed with version 2.
        status, new_doc = self.svc.get_attested_account_proof(self.A)
        self.assertEqual(status, 200, new_doc)
        self.assertEqual(new_doc["auth"]["key_version"], 2)
        result = light_client.verify_state_proof(
            new_doc, self.A, new_trust)
        self.assertTrue(result["ok"], result)
        # A trust document carrying only version 1 cannot verify a version-2
        # document.
        v1_trust = {
            **new_trust,
            "audit_signers": [
                s for s in new_trust["audit_signers"]
                if s["version"] == 1
            ],
        }
        self.assertEqual(
            light_client.verify_state_proof(new_doc, self.A, v1_trust),
            {"ok": False, "error": "auth"},
        )


class AttestedStateProofHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=100_000,
        )
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 100))
        self.svc.mine_block()
        self.svc.confirm_block(1)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.svc))
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def get(self, path: str) -> tuple[int, object]:
        try:
            with urllib.request.urlopen(self.base + path) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_route_key_order_and_offline_verification(self) -> None:
        status, body = self.get(f"/v1/accounts/{self.A}/attested-proof")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), ["state", "proof", "auth"])
        status, trust = self.get("/v1/trust")
        self.assertEqual(status, 200)
        result = light_client.verify_state_proof(body, self.A, trust)
        self.assertTrue(result["ok"], result)

    def test_status_codes(self) -> None:
        for query in ("?height=01", "?height=x", "?foo=1",
                      "?height=1&height=1", "?height=-1"):
            status, _ = self.get(
                f"/v1/accounts/{self.A}/attested-proof{query}")
            self.assertEqual(status, 400, query)
        status, _ = self.get(
            f"/v1/accounts/{self.A}/attested-proof?height=99")
        self.assertEqual(status, 404)
        status, _ = self.get(
            f"/v1/accounts/{'0' * 64}/attested-proof")
        self.assertEqual(status, 404)
        # Historical height works over HTTP.
        status, body = self.get(
            f"/v1/accounts/{self.A}/attested-proof?height=1")
        self.assertEqual(status, 200, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)

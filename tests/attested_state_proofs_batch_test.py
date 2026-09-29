"""Tests for the batch signed (attested) account-state proofs.

Covers POST /v1/accounts/attested-proofs service semantics (strict body
validation 400 without state changes, unknown/non-canonical/pending anchor
and missing account 404), the fixed wire key order state, proofs, auth with
proofs ascending and one shared audit signature over the
ledger-state-proofs-v1 domain, ledger.light_client.verify_state_proofs
input/auth/integrity classification and fixed success key order, plus the
HTTP route.

Run: python3 tests/attested_state_proofs_batch_test.py
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


class BatchAttestedStateProofTests(unittest.TestCase):
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
        status, _ = self.svc.mine_block()
        self.assertEqual(status, 201)
        status, _ = self.svc.confirm_block(1)
        self.assertEqual(status, 200)
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)

    def batch(self, payload: object) -> tuple[int, dict]:
        return self.svc.get_attested_account_proofs(payload)

    def test_success_key_order_and_fields(self) -> None:
        status, doc = self.batch({"accounts": [self.C, self.A, self.B]})
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["state", "proofs", "auth"])
        self.assertEqual(
            list(doc["state"]),
            ["state_root", "height", "block_hash", "account_count"],
        )
        self.assertEqual(
            [proof["account"] for proof in doc["proofs"]],
            sorted([self.A, self.B, self.C]),
        )
        for proof in doc["proofs"]:
            self.assertEqual(
                list(proof),
                ["account", "balance", "confirmed_transactions", "index",
                 "state_root", "height", "block_hash", "siblings"],
            )
            self.assertEqual(proof["state_root"], doc["state"]["state_root"])
            self.assertEqual(proof["height"], doc["state"]["height"])
            self.assertEqual(proof["block_hash"], doc["state"]["block_hash"])
        self.assertEqual(list(doc["auth"]), ["key_version", "signature"])
        self.assertTrue(crypto.is_hex128(doc["auth"]["signature"]))

    def test_bad_bodies_are_400(self) -> None:
        bad_bodies = [
            None, [], "x", 42,
            {}, {"height": "1"}, {"accounts": None},
            {"accounts": []}, {"accounts": ["zz"]},
            {"accounts": [self.A, self.A]},
            {"accounts": [self.A], "extra": 1},
            {"accounts": [self.A], "h": "1"},
            {"accounts": [self.A], "height": 1},
            {"accounts": [self.A], "height": "01"},
            {"accounts": [self.A], "height": "-1"},
            {"accounts": [self.A, self.B.upper()]},
        ]
        for body in bad_bodies:
            status, _ = self.batch(body)
            self.assertEqual(status, 400, body)

    def test_anchor_and_missing_account_are_404(self) -> None:
        self.assertEqual(
            self.batch({"accounts": [self.A], "height": "9"})[0], 404)
        self.assertEqual(self.batch({"accounts": ["0" * 64]})[0], 404)
        # One missing account fails the whole batch.
        self.assertEqual(
            self.batch({"accounts": [self.A, "0" * 64]})[0], 404)

    def test_pending_tip_is_404(self) -> None:
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.A, 5))
        self.assertEqual(self.svc.mine_block()[0], 201)
        self.assertEqual(self.batch({"accounts": [self.A]})[0], 404)

    def test_signature_uses_batch_domain(self) -> None:
        status, doc = self.batch({"accounts": [self.B, self.A], "height": "1"})
        self.assertEqual(status, 200, doc)
        public_key = self.trust["audit_signers"][0]["public_key"]
        unsigned = {"state": doc["state"], "proofs": doc["proofs"]}
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        import hashlib
        digest = hashlib.sha256(
            b"ledger-state-proofs-v1" + canonical
        ).digest()
        self.assertTrue(
            crypto.verify_signature(
                public_key, digest, doc["auth"]["signature"]))

    def test_offline_verify_success_and_key_order(self) -> None:
        status, doc = self.batch({"accounts": [self.B, self.A]})
        self.assertEqual(status, 200, doc)
        result = light_client.verify_state_proofs(
            doc, [self.B, self.A], self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result),
            ["ok", "accounts", "height", "block_hash", "state_root"],
        )
        self.assertEqual(result["accounts"], sorted([self.A, self.B]))
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["state_root"], doc["state"]["state_root"])

    def test_offline_input_failures(self) -> None:
        _, doc = self.batch({"accounts": [self.A, self.B]})
        verify = light_client.verify_state_proofs
        for accounts in (None, [], 7, ["zz"], [self.A, self.A]):
            self.assertEqual(
                verify(doc, accounts, self.trust)["error"], "input", accounts)
        self.assertEqual(verify([], [self.A], self.trust)["error"], "input")
        reordered = {
            "proofs": doc["proofs"], "state": doc["state"],
            "auth": doc["auth"],
        }
        self.assertEqual(
            verify(reordered, [self.A, self.B], self.trust)["error"],
            "input")
        missing = {"state": doc["state"], "proofs": doc["proofs"]}
        self.assertEqual(
            verify(missing, [self.A, self.B], self.trust)["error"], "input")
        self.assertEqual(
            verify({"state": doc["state"], "proofs": [],
                    "auth": doc["auth"]}, [self.A], self.trust)["error"],
            "input")

    def test_offline_auth_failures(self) -> None:
        _, doc = self.batch({"accounts": [self.A, self.B]})
        verify = light_client.verify_state_proofs
        bad = copy.deepcopy(doc)
        bad["auth"]["key_version"] = 99
        self.assertEqual(
            verify(bad, [self.A, self.B], self.trust),
            {"ok": False, "error": "auth"})
        bad = copy.deepcopy(doc)
        bad["auth"]["signature"] = "0" * 128
        self.assertEqual(
            verify(bad, [self.A, self.B], self.trust),
            {"ok": False, "error": "auth"})

    def test_offline_integrity_failures(self) -> None:
        _, doc = self.batch({"accounts": [self.A, self.B]})
        verify = light_client.verify_state_proofs
        signer = self.svc.store.audit_signer
        self.assertEqual(
            verify(doc, [self.A], self.trust),
            {"ok": False, "error": "integrity"})
        # Tampered leaf triple, re-signed: the Merkle path no longer matches.
        bad = copy.deepcopy(doc)
        bad["proofs"][0]["balance"] += 1
        bad["auth"] = light_client.sign_state_proofs(
            signer["private_key"], signer["version"],
            bad["state"], bad["proofs"])
        self.assertEqual(
            verify(bad, [self.A, self.B], self.trust),
            {"ok": False, "error": "integrity"})
        # Out-of-order proofs, re-signed.
        bad = copy.deepcopy(doc)
        bad["proofs"] = list(reversed(bad["proofs"]))
        bad["auth"] = light_client.sign_state_proofs(
            signer["private_key"], signer["version"],
            bad["state"], bad["proofs"])
        self.assertEqual(
            verify(bad, [self.A, self.B], self.trust),
            {"ok": False, "error": "integrity"})

    def test_concurrent_queries_share_stable_order(self) -> None:
        seen = []

        def worker() -> None:
            for _ in range(25):
                status, doc = self.batch({"accounts": [self.B, self.A]})
                self.assertEqual(status, 200)
                seen.append(tuple(p["account"] for p in doc["proofs"]))

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertTrue(seen)
        self.assertTrue(
            all(order == tuple(sorted([self.A, self.B])) for order in seen))

    def test_http_route(self) -> None:
        httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.svc))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            url = (
                f"http://127.0.0.1:{httpd.server_address[1]}"
                "/v1/accounts/attested-proofs"
            )
            request = urllib.request.Request(
                url,
                data=json.dumps(
                    {"accounts": [self.B, self.A]}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                self.assertEqual(response.status, 200)
                doc = json.loads(response.read())
            self.assertEqual(list(doc), ["state", "proofs", "auth"])
            request = urllib.request.Request(
                url,
                data=json.dumps({"accounts": []}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request)
            self.assertEqual(caught.exception.code, 400)
        finally:
            httpd.shutdown()


if __name__ == "__main__":
    unittest.main()

"""Tests for the batched signed (attested) account-state proofs.

Run: python3 tests/attested_state_proofs_test.py
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
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

from ledger import cli, crypto, light_client
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


class AttestedStateProofsServiceTests(unittest.TestCase):
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
        status, _block = self.svc.mine_block()
        self.assertEqual(status, 201)
        status, _ = self.svc.confirm_block(1)
        self.assertEqual(status, 200)
        self.block_hash = self.svc.store.chain[1].block_hash
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)

    def document(self, payload):
        return self.svc.get_attested_account_proofs(payload)

    def test_success_key_order_fields_and_sorting(self) -> None:
        status, doc = self.document({"accounts": [self.C, self.A, self.B]})
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["state", "proofs", "auth"])
        self.assertEqual(
            list(doc["state"]),
            ["state_root", "height", "block_hash", "account_count"],
        )
        self.assertEqual(doc["state"]["height"], 1)
        self.assertEqual(doc["state"]["block_hash"], self.block_hash)
        self.assertEqual(doc["state"]["account_count"], 3)
        accounts = [proof["account"] for proof in doc["proofs"]]
        self.assertEqual(accounts, sorted([self.A, self.B, self.C]))
        self.assertEqual(len(doc["proofs"]), 3)
        for proof in doc["proofs"]:
            self.assertEqual(
                list(proof),
                ["account", "balance", "confirmed_transactions", "index",
                 "state_root", "height", "block_hash", "siblings"],
            )
            self.assertEqual(proof["state_root"], doc["state"]["state_root"])
            self.assertEqual(proof["height"], 1)
            self.assertEqual(proof["block_hash"], self.block_hash)
            self.assertLess(proof["index"], doc["state"]["account_count"])
        self.assertEqual(list(doc["auth"]), ["key_version", "signature"])
        self.assertTrue(crypto.is_hex128(doc["auth"]["signature"]))
        self.assertEqual(
            [proof["index"] for proof in doc["proofs"]], [0, 1, 2])

    def test_single_account_batch_and_offline_verify(self) -> None:
        status, doc = self.document({"accounts": [self.A]})
        self.assertEqual(status, 200, doc)
        result = light_client.verify_state_proofs(doc, [self.A], self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result),
            ["ok", "accounts", "height", "block_hash", "state_root"],
        )
        self.assertEqual(result["accounts"], [self.A])
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["block_hash"], self.block_hash)

    def test_signature_uses_batch_domain(self) -> None:
        status, doc = self.document({"accounts": [self.A, self.B]})
        self.assertEqual(status, 200, doc)
        public_key = self.trust["audit_signers"][0]["public_key"]
        unsigned = {"state": doc["state"], "proofs": doc["proofs"]}
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = hashlib.sha256(b"ledger-state-proofs-v1" + canonical).digest()
        self.assertTrue(
            crypto.verify_signature(
                public_key, digest, doc["auth"]["signature"])
        )
        for domain in (b"ledger-state-proof-v1", b"ledger-headers-v1",
                       b"ledger-finality-v1"):
            self.assertFalse(
                crypto.verify_signature(
                    public_key,
                    hashlib.sha256(domain + canonical).digest(),
                    doc["auth"]["signature"],
                )
            )

    def test_body_validation_400_without_state_change(self) -> None:
        height_before = self.svc.store.tip().height
        bad_payloads = [
            None, [], "x", {},
            {"height": "1"},
            {"accounts": [self.A], "extra": 1},
            {"accounts": []},
            {"accounts": [self.A, self.A]},
            {"accounts": ["z" * 64]},
            {"accounts": [self.A.upper()]},
            {"accounts": [self.A[:-1]]},
            {"accounts": [7]},
            {"accounts": self.A},
            {"accounts": [self.A], "height": 1},
            {"accounts": [self.A], "height": "01"},
            {"accounts": [self.A], "height": "-1"},
            {"accounts": [self.A], "height": "x"},
            {"accounts": [self.A], "height": ""},
        ]
        for payload in bad_payloads:
            status, body = self.document(payload)
            self.assertEqual(status, 400, payload)
            self.assertIn("error", body)
        self.assertEqual(self.svc.store.tip().height, height_before)

    def test_not_found_404(self) -> None:
        self.assertEqual(self.document({"accounts": ["0" * 64]})[0], 404)
        self.assertEqual(
            self.document({"accounts": [self.A, "0" * 64]})[0], 404)
        self.assertEqual(
            self.document({"accounts": [self.A], "height": "99"})[0], 404)
        # A/B/C do not exist at genesis.
        self.assertEqual(
            self.document(
                {"accounts": [self.A, self.B], "height": "0"})[0], 404)
        # Pending tip anchors nothing.
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.C, 5))
        status, _ = self.svc.mine_block()
        self.assertEqual(status, 201)
        self.assertEqual(self.document({"accounts": [self.A]})[0], 404)
        self.assertEqual(
            self.document({"accounts": [self.A], "height": "2"})[0], 404)
        status, doc = self.document(
            {"accounts": [self.A, self.B], "height": "1"})
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["state"]["height"], 1)

    def test_sorting_is_stable_across_restart(self) -> None:
        status, first = self.document({"accounts": [self.C, self.A, self.B]})
        self.assertEqual(status, 200, first)
        restarted = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=100_000,
        )
        status, second = restarted.get_attested_account_proofs(
            {"accounts": [self.B, self.C, self.A]})
        self.assertEqual(status, 200, second)
        self.assertEqual(
            [p["account"] for p in first["proofs"]],
            [p["account"] for p in second["proofs"]],
        )
        self.assertEqual(first["state"], second["state"])


class VerifyStateProofsTests(unittest.TestCase):
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
        status, self.doc = self.svc.get_attested_account_proofs(
            {"accounts": [self.C, self.A, self.B]})
        self.assertEqual(status, 200, self.doc)
        self.accounts = [self.A, self.B, self.C]

    def verify(self, document=None, accounts=None, trust=None):
        return light_client.verify_state_proofs(
            self.doc if document is None else document,
            self.accounts if accounts is None else accounts,
            self.trust if trust is None else trust,
        )

    def test_success_shape(self) -> None:
        result = self.verify()
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result),
            ["ok", "accounts", "height", "block_hash", "state_root"],
        )
        self.assertEqual(result["accounts"], sorted(self.accounts))
        self.assertEqual(result["height"], 1)
        self.assertEqual(
            result["state_root"], self.doc["state"]["state_root"])
        result = self.verify(accounts=[self.C, self.A, self.B])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["accounts"], sorted(self.accounts))

    def test_account_pin_input_failures(self) -> None:
        for pin in (None, 7, "x", [], [self.A, self.A],
                    [self.A, self.A.upper()], [self.A, 7], ["z" * 64]):
            self.assertEqual(
                light_client.verify_state_proofs(
                    self.doc, pin, self.trust)["error"],
                "input", pin)

    def test_structure_input_failures(self) -> None:
        self.assertEqual(self.verify(document=[])["error"], "input")
        self.assertEqual(self.verify(document={"x": 1})["error"], "input")
        reordered = {
            "proofs": self.doc["proofs"],
            "state": self.doc["state"],
            "auth": self.doc["auth"],
        }
        self.assertEqual(self.verify(document=reordered)["error"], "input")
        missing = {
            "state": self.doc["state"], "proofs": self.doc["proofs"]}
        self.assertEqual(self.verify(document=missing)["error"], "input")
        extra = dict(self.doc, extra=1)
        self.assertEqual(self.verify(document=extra)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["proofs"] = []
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["proofs"] = "x"
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["proofs"][0]["siblings"] = [
            {"direction": "up", "hash": "a" * 64}]
        self.assertEqual(self.verify(document=bad)["error"], "input")
        self.assertEqual(
            self.verify(trust={"genesis_hash": "0" * 64})["error"], "input")
        self.assertEqual(
            light_client.verify_state_proofs(
                self.doc, self.accounts, None)["error"], "input")

    def test_auth_input_and_auth_failures(self) -> None:
        for version, signature in (
            (0, self.doc["auth"]["signature"]),
            (True, self.doc["auth"]["signature"]),
            ("1", self.doc["auth"]["signature"]),
            (1, 9),
            (1, "z" * 128),
        ):
            bad = copy.deepcopy(self.doc)
            bad["auth"] = {"key_version": version, "signature": signature}
            self.assertEqual(
                self.verify(document=bad)["error"], "input",
                (version, signature))
        bad = copy.deepcopy(self.doc)
        bad["auth"] = {**bad["auth"], "key_version": 42}
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "auth"})
        bad = copy.deepcopy(self.doc)
        sig = bad["auth"]["signature"]
        flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
        bad["auth"] = {**bad["auth"], "signature": flipped}
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "auth"})

    def test_account_set_and_order_integrity(self) -> None:
        self.assertEqual(
            self.verify(accounts=[self.A, self.B]),
            {"ok": False, "error": "integrity"})
        self.assertEqual(
            self.verify(accounts=self.accounts + ["0" * 64]),
            {"ok": False, "error": "integrity"})
        signer = self.svc.store.audit_signer
        reordered = list(reversed(self.doc["proofs"]))
        bad_auth = light_client.sign_state_proofs(
            signer["private_key"], signer["version"],
            self.doc["state"], reordered)
        bad = {"state": self.doc["state"], "proofs": reordered,
               "auth": bad_auth}
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"})

    def test_tampering_integrity(self) -> None:
        signer = self.svc.store.audit_signer
        bad = copy.deepcopy(self.doc)
        bad["proofs"][1] = {**bad["proofs"][1], "balance": 1}
        bad["auth"] = light_client.sign_state_proofs(
            signer["private_key"], signer["version"],
            bad["state"], bad["proofs"])
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"})
        bad = copy.deepcopy(self.doc)
        bad["proofs"][0] = {**bad["proofs"][0], "index": 99}
        bad["auth"] = light_client.sign_state_proofs(
            signer["private_key"], signer["version"],
            bad["state"], bad["proofs"])
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"})
        bad = copy.deepcopy(self.doc)
        bad["proofs"][2] = {
            **bad["proofs"][2], "height": 0,
            "block_hash": self.svc.store.chain[0].block_hash}
        bad["auth"] = light_client.sign_state_proofs(
            signer["private_key"], signer["version"],
            bad["state"], bad["proofs"])
        self.assertEqual(
            self.verify(document=bad)["error"], "integrity")
        bad = copy.deepcopy(self.doc)
        bad["state"] = {**bad["state"], "state_root": "1" * 64}
        bad["auth"] = light_client.sign_state_proofs(
            signer["private_key"], signer["version"],
            bad["state"], bad["proofs"])
        self.assertEqual(
            self.verify(document=bad)["error"], "integrity")

    def test_domain_separation_from_single_proof(self) -> None:
        status, single = self.svc.get_attested_account_proof(self.A)
        self.assertEqual(status, 200, single)
        self.assertEqual(self.verify(document=single)["error"], "input")
        public_key = self.trust["audit_signers"][0]["public_key"]
        unsigned = {"state": self.doc["state"], "proofs": self.doc["proofs"]}
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")
        self.assertFalse(
            crypto.verify_signature(
                public_key,
                hashlib.sha256(
                    b"ledger-state-proof-v1" + canonical).digest(),
                self.doc["auth"]["signature"],
            )
        )

    def test_verifies_after_signer_rotation(self) -> None:
        old_doc = copy.deepcopy(self.doc)
        seed = crypto.generate_private_key()
        status, _ = self.svc.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1})
        self.assertEqual(status, 200)
        status, new_trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        result = self.verify(document=old_doc, trust=new_trust)
        self.assertTrue(result["ok"], result)
        status, new_doc = self.svc.get_attested_account_proofs(
            {"accounts": [self.A, self.B]})
        self.assertEqual(status, 200, new_doc)
        self.assertEqual(new_doc["auth"]["key_version"], 2)
        result = light_client.verify_state_proofs(
            new_doc, [self.A, self.B], new_trust)
        self.assertTrue(result["ok"], result)

    def test_never_raises_on_garbage(self) -> None:
        for document in (None, 5, "x", object(), {"state": 1},
                         {"state": {}, "proofs": {}, "auth": {}}):
            for accounts in (None, object(), self.accounts):
                for trust in (None, 7, object(), self.trust):
                    result = light_client.verify_state_proofs(
                        document, accounts, trust)
                    self.assertIn(result.get("ok"), (True, False))
                    if result["ok"] is False:
                        self.assertEqual(set(result), {"ok", "error"})


class AttestedStateProofsHTTPTests(unittest.TestCase):
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

    def post(self, raw):
        if isinstance(raw, dict):
            data = json.dumps(raw).encode("utf-8")
        elif isinstance(raw, str):
            data = raw.encode("utf-8")
        else:
            data = raw
        request = urllib.request.Request(
            self.base + "/v1/accounts/attested-proofs", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def get(self, path: str) -> tuple[int, object]:
        try:
            with urllib.request.urlopen(self.base + path) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_route_key_order_and_offline_verification(self) -> None:
        status, body = self.post({"accounts": [self.B, self.A]})
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), ["state", "proofs", "auth"])
        status, trust = self.get("/v1/trust")
        self.assertEqual(status, 200)
        result = light_client.verify_state_proofs(
            body, [self.A, self.B], trust)
        self.assertTrue(result["ok"], result)

    def test_status_codes(self) -> None:
        for raw in (
            b"not json",
            json.dumps({}),
            json.dumps({"accounts": []}),
            json.dumps({"accounts": [self.A, self.A]}),
            json.dumps({"accounts": ["z" * 64]}),
            json.dumps({"accounts": [self.A], "height": "01"}),
            json.dumps({"accounts": [self.A], "extra": 1}),
        ):
            status, _ = self.post(raw)
            self.assertEqual(status, 400, raw)
        status, _ = self.post({"accounts": [self.A], "height": "99"})
        self.assertEqual(status, 404)
        status, _ = self.post({"accounts": ["0" * 64]})
        self.assertEqual(status, 404)
        status, body = self.post(
            {"accounts": [self.A, self.B], "height": "1"})
        self.assertEqual(status, 200, body)


class StateProofsCLITests(unittest.TestCase):
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

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def run_cli(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(argv))
        line = out.getvalue().strip()
        self.assertEqual(len(line.splitlines()), 1, line)
        return code, line

    def test_success_single_line_json(self) -> None:
        code, line = self.run_cli(
            "--base-url", f"http://127.0.0.1:{self.port}",
            "state-proofs", self.B, self.A)
        body = json.loads(line)
        self.assertEqual(code, 0)
        self.assertEqual(list(body), ["state", "proofs", "auth"])
        self.assertEqual(
            [p["account"] for p in body["proofs"]],
            sorted([self.A, self.B]))

    def test_height_forwarded(self) -> None:
        code, line = self.run_cli(
            "--base-url", f"http://127.0.0.1:{self.port}",
            "state-proofs", self.A, "--height", "1")
        self.assertEqual(code, 0, line)
        self.assertEqual(json.loads(line)["state"]["height"], 1)

    def test_local_input_failures(self) -> None:
        for argv in (
            ("state-proofs",),
            ("state-proofs", self.A, self.A),
            ("state-proofs", "z" * 64),
            ("state-proofs", self.A.upper()),
            ("state-proofs", self.A, "--height", "01"),
            ("state-proofs", self.A, "--height", "x"),
        ):
            code, line = self.run_cli(
                "--base-url", f"http://127.0.0.1:{self.port}", *argv)
            self.assertEqual(code, 1, argv)
            self.assertEqual(
                json.loads(line), {"ok": False, "error": "input"}, argv)

    def test_server_error_and_unreachable_exit_1(self) -> None:
        code, line = self.run_cli(
            "--base-url", f"http://127.0.0.1:{self.port}",
            "state-proofs", "0" * 64)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(line)["error"], "account not found")
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        code, line = self.run_cli(
            "--base-url", f"http://127.0.0.1:{dead_port}",
            "state-proofs", self.A)
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(line))


if __name__ == "__main__":
    unittest.main(verbosity=2)

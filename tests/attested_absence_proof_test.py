"""Tests for the signed (attested) account-absence proof.

Covers:

* GET /v1/accounts/{account}/attested-absence-proof service semantics: the
  non-empty-string account (empty 404), optional single ``height`` with the
  same strict rules as /absence-proof (malformed/repeated/unknown parameter
  400; unknown/non-canonical/pending anchor and pending default tip 404;
  existing target 409), and the success document being the plain absence
  proof with ``auth`` appended (account, state, lower, upper, auth);
* the chain, state tree and audit signer snapshotted under one lock and the
  Ed25519 signature over
  SHA256(UTF8("ledger-state-absence-proof-v1") || canonical_json(document
  without auth)), verifiable with historical keys after rotation;
* ledger.light_client.verify_state_absence_proof: key-set/type/hex/trust
  input failures (booleans are not integers, key order irrelevant), unknown
  version/bad signature auth failures, target/anchor/adjacency/index/
  Merkle-path/empty-tree integrity failures, the fixed success key order,
  and never raising on garbage;
* read-only semantics, restart consistency and the HTTP route/wire shapes.

Run: python3 tests/attested_absence_proof_test.py
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


class AttestedAbsenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "absence.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
        )
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 100))
        self.svc.submit_transaction(make_tx(self.kc, self.C, self.A, 40))
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        status, _ = self.svc.confirm_block(1)
        self.assertEqual(status, 200)
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        self.target = sorted((self.A, self.B))[0] + "00"

    def document(self, account: str, params=None) -> tuple[int, dict]:
        return self.svc.get_attested_account_absence_proof(account, params)

    def test_success_appends_auth_to_absence_document(self) -> None:
        status, doc = self.document(self.target)
        self.assertEqual(status, 200, doc)
        self.assertEqual(
            list(doc), ["account", "state", "lower", "upper", "auth"])
        self.assertEqual(list(doc["auth"]), ["key_version", "signature"])
        self.assertEqual(doc["auth"]["key_version"], 1)
        self.assertTrue(crypto.is_hex128(doc["auth"]["signature"]))
        # Everything before auth is exactly the plain absence document.
        status, plain = self.svc.get_account_absence_proof(self.target)
        self.assertEqual(status, 200)
        self.assertEqual(
            {key: doc[key] for key in ("account", "state", "lower", "upper")},
            plain,
        )
        self.assertEqual(doc["state"]["height"], 1)
        self.assertEqual(doc["state"]["account_count"], 3)

    def test_empty_tree_document_is_signed(self) -> None:
        status, doc = self.document("ghost", {"height": "0"})
        self.assertEqual(status, 200, doc)
        self.assertIsNone(doc["lower"])
        self.assertIsNone(doc["upper"])
        self.assertEqual(doc["state"]["account_count"], 0)
        self.assertEqual(
            doc["state"]["state_root"], crypto.EMPTY_MERKLE_ROOT)
        result = light_client.verify_state_absence_proof(
            doc, "ghost", self.trust)
        self.assertTrue(result["ok"], result)

    def test_signature_uses_absence_domain(self) -> None:
        status, doc = self.document(self.target)
        self.assertEqual(status, 200, doc)
        public_key = self.trust["audit_signers"][0]["public_key"]
        unsigned = {key: doc[key]
                    for key in ("account", "state", "lower", "upper")}
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = hashlib.sha256(
            b"ledger-state-absence-proof-v1" + canonical
        ).digest()
        self.assertTrue(
            crypto.verify_signature(
                public_key, digest, doc["auth"]["signature"])
        )
        # No other domain may authenticate the same body.
        for domain in (b"ledger-state-proof-v1", b"ledger-state-proofs-v1",
                       b"ledger-headers-v1"):
            self.assertFalse(
                crypto.verify_signature(
                    public_key,
                    hashlib.sha256(domain + canonical).digest(),
                    doc["auth"]["signature"],
                )
            )

    def test_height_parameter_rules(self) -> None:
        status, doc = self.document(self.target, {"height": "1"})
        self.assertEqual(status, 200, doc)
        self.assertTrue(
            light_client.verify_state_absence_proof(
                doc, self.target, self.trust)["ok"])
        for value in ("01", "-1", "x", "1.0", "", " 1"):
            self.assertEqual(
                self.document(self.target, {"height": value})[0], 400, value)
        self.assertEqual(self.document(self.target, {"height": 1})[0], 400)
        self.assertEqual(self.document(self.target, {"foo": "1"})[0], 400)
        self.assertEqual(
            self.document(self.target, {"height": "1", "foo": "1"})[0], 400)
        self.assertEqual(
            self.document(self.target, {"height": "99"})[0], 404)

    def test_empty_account_and_existing_target(self) -> None:
        self.assertEqual(self.document("")[0], 404)
        self.assertEqual(self.document("", {"height": "0"})[0], 404)
        self.assertEqual(self.document(5)[0], 404)
        for account in (self.A, self.B, self.C):
            self.assertEqual(self.document(account)[0], 409, account)
            self.assertEqual(
                self.document(account, {"height": "1"})[0], 409, account)

    def test_pending_tip_and_pending_anchor_404(self) -> None:
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.C, 5))
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201)
        self.assertEqual(self.document(self.target)[0], 404)
        self.assertEqual(
            self.document(
                self.target, {"height": str(pending["height"])})[0], 404)
        # Historical confirmed anchors remain available.
        self.assertEqual(
            self.document(self.target, {"height": "1"})[0], 200)

    def test_query_is_read_only(self) -> None:
        store = self.svc.store
        generation = store.generation
        events = len(store.audit_events)
        chain_len = len(store.chain)
        mempool = len(store.pending)
        for _ in range(5):
            self.document(self.target)
            self.document(self.A)
            self.document("ghost", {"height": "0"})
        self.assertEqual(store.generation, generation)
        self.assertEqual(len(store.audit_events), events)
        self.assertEqual(len(store.chain), chain_len)
        self.assertEqual(len(store.pending), mempool)

    def test_restart_keeps_documents(self) -> None:
        status, first = self.document(self.target)
        self.assertEqual(status, 200)
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=100_000)
        status, second = reopened.get_attested_account_absence_proof(
            self.target)
        self.assertEqual(status, 200)
        self.assertEqual(first, second)

    def test_verifies_after_signer_rotation(self) -> None:
        status, old_doc = self.document(self.target)
        self.assertEqual(status, 200)
        seed = crypto.generate_private_key()
        status, body = self.svc.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1})
        self.assertEqual(status, 200, body)
        status, new_trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        # The old version-1 document still verifies via the historical key.
        result = light_client.verify_state_absence_proof(
            old_doc, self.target, new_trust)
        self.assertTrue(result["ok"], result)
        # A fresh document is signed with version 2.
        status, new_doc = self.document(self.target)
        self.assertEqual(status, 200)
        self.assertEqual(new_doc["auth"]["key_version"], 2)
        result = light_client.verify_state_absence_proof(
            new_doc, self.target, new_trust)
        self.assertTrue(result["ok"], result)


class VerifyStateAbsenceProofTests(unittest.TestCase):
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
        self.svc.mine_block()
        self.svc.confirm_block(1)
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.C, 7))
        self.svc.mine_block()
        self.svc.confirm_block(2)
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        names = sorted((self.A, self.B, self.C))
        self.target = names[1] + "00"
        status, self.doc = self.svc.get_attested_account_absence_proof(
            self.target)
        self.assertEqual(status, 200, self.doc)

    _DEFAULT = object()

    def verify(self, document=_DEFAULT, account=_DEFAULT, trust=_DEFAULT):
        return light_client.verify_state_absence_proof(
            self.doc if document is self._DEFAULT else document,
            self.target if account is self._DEFAULT else account,
            self.trust if trust is self._DEFAULT else trust,
        )

    def resign(self, document: dict) -> dict:
        """Re-sign the document without its auth envelope."""
        signer = self.svc.store.audit_signer
        unsigned = {key: document[key]
                    for key in ("account", "state", "lower", "upper")}
        return light_client.sign_state_absence_proof(
            signer["private_key"], signer["version"], unsigned)

    def test_success_shape(self) -> None:
        result = self.verify()
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result),
            ["ok", "account", "height", "block_hash", "state_root"],
        )
        self.assertEqual(result["account"], self.target)
        self.assertEqual(result["height"], self.doc["state"]["height"])
        self.assertEqual(
            result["block_hash"], self.doc["state"]["block_hash"])
        self.assertEqual(
            result["state_root"], self.doc["state"]["state_root"])

    def test_key_order_does_not_matter(self) -> None:
        reordered = {
            "auth": self.doc["auth"],
            "upper": self.doc["upper"],
            "account": self.doc["account"],
            "state": self.doc["state"],
            "lower": self.doc["lower"],
        }
        self.assertTrue(self.verify(document=reordered)["ok"])
        shuffled = copy.deepcopy(self.doc)
        shuffled["state"] = {
            "account_count": self.doc["state"]["account_count"],
            "block_hash": self.doc["state"]["block_hash"],
            "height": self.doc["state"]["height"],
            "state_root": self.doc["state"]["state_root"],
        }
        shuffled["lower"] = dict(reversed(list(
            shuffled["lower"].items())))
        shuffled["auth"] = {
            "signature": self.doc["auth"]["signature"],
            "key_version": self.doc["auth"]["key_version"],
        }
        self.assertTrue(self.verify(document=shuffled)["ok"])

    def test_bad_account_pin_is_input(self) -> None:
        for pin in (None, "", 7, True, b"x", [], {}):
            self.assertEqual(
                self.verify(account=pin),
                {"ok": False, "error": "input"},
                pin,
            )

    def test_structure_input_failures(self) -> None:
        self.assertEqual(self.verify(document=[])["error"], "input")
        self.assertEqual(self.verify(document={"x": 1})["error"], "input")
        for key in ("account", "state", "lower", "upper", "auth"):
            missing = dict(self.doc)
            del missing[key]
            self.assertEqual(
                self.verify(document=missing)["error"], "input", key)
        extra = dict(self.doc, extra=1)
        self.assertEqual(self.verify(document=extra)["error"], "input")
        # Malformed document account.
        for value in ("", 7, None, True):
            bad = copy.deepcopy(self.doc)
            bad["account"] = value
            self.assertEqual(
                self.verify(document=bad)["error"], "input", value)
        # State document defects (booleans are not integers).
        for field, value in (
            ("height", True),
            ("height", "1"),
            ("account_count", False),
            ("account_count", -1),
            ("state_root", "z" * 64),
            ("block_hash", 7),
        ):
            bad = copy.deepcopy(self.doc)
            bad["state"] = {**bad["state"], field: value}
            self.assertEqual(
                self.verify(document=bad)["error"], "input", (field, value))
        bad = copy.deepcopy(self.doc)
        bad["state"]["extra"] = 1
        self.assertEqual(self.verify(document=bad)["error"], "input")
        # Neighbor defects.
        for field, value in (
            ("index", True),
            ("index", -1),
            ("balance", False),
            ("balance", -1),
            ("account", ""),
            ("confirmed_transactions", ("x",)),
            ("state_root", "ZZ" + "0" * 62),
        ):
            bad = copy.deepcopy(self.doc)
            bad["lower"] = {**bad["lower"], field: value}
            self.assertEqual(
                self.verify(document=bad)["error"], "input", (field, value))
        bad = copy.deepcopy(self.doc)
        del bad["lower"]["balance"]
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["upper"]["siblings"] = [
            {"direction": "up", "hash": "a" * 64}]
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["upper"]["siblings"] = [
            {"direction": "left", "hash": "a" * 64, "extra": 1}]
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
        bad = copy.deepcopy(self.doc)
        bad["auth"]["extra"] = 1
        self.assertEqual(self.verify(document=bad)["error"], "input")

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
        # A signature from another domain never authenticates this body.
        signer = self.svc.store.audit_signer
        foreign = light_client.sign_state_proof(
            signer["private_key"], signer["version"],
            self.doc["state"], self.doc["lower"])
        bad = copy.deepcopy(self.doc)
        bad["auth"] = foreign
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "auth"})
        # A trust document without usable audit signers is an input defect.
        self.assertEqual(
            self.verify(trust={"genesis_hash": "0" * 64})["error"], "input")
        self.assertEqual(self.verify(trust=None)["error"], "input")

    def test_target_mismatch_is_integrity(self) -> None:
        self.assertEqual(
            self.verify(account="someone-else"),
            {"ok": False, "error": "integrity"},
        )
        # Renaming the target and re-signing still fails integrity.
        bad = copy.deepcopy(self.doc)
        bad["account"] = "someone-else"
        bad["auth"] = self.resign(bad)
        self.assertEqual(
            self.verify(document=bad, account="someone-else"),
            {"ok": False, "error": "integrity"},
        )

    def test_mixed_anchors_are_integrity(self) -> None:
        # A neighbor proof from a different height mixed into this document.
        status, historical = self.svc.get_attested_account_absence_proof(
            self.target, {"height": "1"})
        self.assertEqual(status, 200)
        bad = copy.deepcopy(self.doc)
        bad["lower"] = historical["lower"]
        bad["auth"] = self.resign(bad)
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})
        # A neighbor whose anchor fields were edited, re-signed.
        bad = copy.deepcopy(self.doc)
        bad["upper"] = {**bad["upper"], "height": 0,
                        "block_hash": self.svc.store.chain[0].block_hash}
        bad["auth"] = self.resign(bad)
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})

    def test_non_adjacent_neighbors_are_integrity(self) -> None:
        names = sorted((self.A, self.B, self.C))
        p0 = self.svc.get_account_proof(names[0])[1]
        p2 = self.svc.get_account_proof(names[2])[1]
        forged = {
            "account": self.target,
            "state": self.doc["state"],
            "lower": p0,
            "upper": p2,
        }
        forged["auth"] = self.resign(forged)
        self.assertEqual(self.verify(document=forged),
                         {"ok": False, "error": "integrity"})

    def test_index_out_of_range_is_integrity(self) -> None:
        bad = copy.deepcopy(self.doc)
        bad["lower"] = {**bad["lower"],
                        "index": self.doc["state"]["account_count"] + 5}
        bad["auth"] = self.resign(bad)
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})

    def test_merkle_path_tampering_is_integrity(self) -> None:
        bad = copy.deepcopy(self.doc)
        bad["lower"] = {**bad["lower"], "balance": bad["lower"]["balance"] + 1}
        bad["auth"] = self.resign(bad)
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})
        bad = copy.deepcopy(self.doc)
        bad["upper"]["siblings"][0]["hash"] = "f" * 64
        bad["auth"] = self.resign(bad)
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})

    def test_empty_tree_boundary_is_integrity(self) -> None:
        status, empty = self.svc.get_attested_account_absence_proof(
            "ghost", {"height": "0"})
        self.assertEqual(status, 200)
        self.assertTrue(
            light_client.verify_state_absence_proof(
                empty, "ghost", self.trust)["ok"])
        # A neighbor inside a zero-count tree.
        bad = copy.deepcopy(empty)
        bad["lower"] = self.doc["lower"]
        bad["auth"] = self.resign(bad)
        self.assertEqual(
            light_client.verify_state_absence_proof(
                bad, "ghost", self.trust),
            {"ok": False, "error": "integrity"},
        )
        # A tampered empty-tree root, re-signed.
        bad = copy.deepcopy(empty)
        bad["state"] = {**bad["state"], "state_root": "0" * 64}
        bad["auth"] = self.resign(bad)
        self.assertEqual(
            light_client.verify_state_absence_proof(
                bad, "ghost", self.trust),
            {"ok": False, "error": "integrity"},
        )
        # Both neighbors null inside a non-empty tree.
        bad = copy.deepcopy(self.doc)
        bad["lower"] = None
        bad["upper"] = None
        bad["auth"] = self.resign(bad)
        self.assertEqual(self.verify(document=bad),
                         {"ok": False, "error": "integrity"})

    def test_never_raises_on_garbage(self) -> None:
        for document in (None, 5, "x", object(), {"state": 1},
                         {"account": "a", "state": {}, "lower": None,
                          "upper": None, "auth": {}}):
            for account in (None, object(), "", self.target):
                for trust in (None, 7, object(), self.trust):
                    result = light_client.verify_state_absence_proof(
                        document, account, trust)
                    self.assertIn(result.get("ok"), (True, False))
                    if result["ok"] is False:
                        self.assertEqual(set(result), {"ok", "error"})


class AttestedAbsenceHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "http.json")),
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
        self.target = sorted((self.A, self.B))[0] + "00"

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
        status, body = self.get(
            f"/v1/accounts/{self.target}/attested-absence-proof")
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body), ["account", "state", "lower", "upper", "auth"])
        self.assertEqual(list(body["auth"]), ["key_version", "signature"])
        status, trust = self.get("/v1/trust")
        self.assertEqual(status, 200)
        result = light_client.verify_state_absence_proof(
            body, self.target, trust)
        self.assertTrue(result["ok"], result)

    def test_status_codes(self) -> None:
        for query in ("?height=01", "?height=x", "?foo=1",
                      "?height=1&height=1", "?height=-1"):
            status, _ = self.get(
                f"/v1/accounts/{self.target}/attested-absence-proof{query}")
            self.assertEqual(status, 400, query)
        status, _ = self.get(
            f"/v1/accounts/{self.target}/attested-absence-proof?height=99")
        self.assertEqual(status, 404)
        status, _ = self.get(
            f"/v1/accounts/{self.A}/attested-absence-proof")
        self.assertEqual(status, 409)
        status, _ = self.get("/v1/accounts//attested-absence-proof")
        self.assertEqual(status, 404)
        # Historical height works over HTTP.
        status, body = self.get(
            f"/v1/accounts/{self.target}/attested-absence-proof?height=1")
        self.assertEqual(status, 200, body)
        # Genesis empty tree works over HTTP.
        status, body = self.get(
            "/v1/accounts/ghost/attested-absence-proof?height=0")
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["lower"])
        self.assertIsNone(body["upper"])

    def test_existing_endpoints_unchanged(self) -> None:
        status, body = self.get(
            f"/v1/accounts/{self.target}/absence-proof")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), ["account", "state", "lower", "upper"])
        status, body = self.get(f"/v1/accounts/{self.A}/attested-proof")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), ["state", "proof", "auth"])
        status, body = self.get(f"/v1/accounts/{self.A}/proof")
        self.assertEqual(status, 200, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)

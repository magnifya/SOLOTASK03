"""Tests for the signed account-state proof.

Covers:

* ``GET /v1/accounts/{account}/attested-proof`` (HTTP + service): the
  optional single ``height`` follows exactly the same rules as
  ``/proof`` — malformed/repeated/unknown query parameters are 400, an
  unknown/non-canonical/pending anchor or a missing account is 404;
* the 200 document has the fixed top-level key order ``state, proof,
  auth`` with ``state`` reusing the state-root four fields and
  ``proof`` reusing the state-proof eight fields, and ``auth`` is
  ``{key_version, signature}`` — an Ed25519 signature over
  ``SHA256(UTF8("ledger-state-proof-v1") || canonical_json({state,
  proof}))`` made with the current audit signer, chain/state/signer
  snapshotted under one lock;
* ``ledger.light_client.verify_state_proof(document, account, trust)``:
  key-order/type/64/128-hex/audit_signers defects are ``input``, an
  unknown signer version or bad signature is ``auth``, an account/root/
  height/block-hash binding defect, an out-of-range/depth-inconsistent
  index or a broken Merkle path is ``integrity``; success returns the
  fixed key order ``ok, account, height, block_hash, state_root`` and
  never raises;
* documents signed under an old audit-signer version remain verifiable
  after rotation through that version's historical public key.

Run: python3 tests/attested_state_proof_test.py
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto, light_client
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

TOP_KEYS = ["state", "proof", "auth"]
STATE_KEYS = ["state_root", "height", "block_hash", "account_count"]
PROOF_KEYS = [
    "account",
    "balance",
    "confirmed_transactions",
    "index",
    "state_root",
    "height",
    "block_hash",
    "siblings",
]
AUTH_KEYS = ["key_version", "signature"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class AttestedProofFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "ledger.json"))
        self.service = LedgerService(self.store)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_port
        # Five distinct senders so the state tree spans more than one
        # Merkle level (10 confirmed accounts: senders + recipients).
        self.keys = [Ed25519PrivateKey.generate() for _ in range(5)]
        self.senders = [pub_hex(key) for key in self.keys]
        self.recipients = [f"{i:064d}" for i in range(5)]
        for key, sender, recipient in zip(self.keys, self.senders, self.recipients):
            message = crypto.canonical_message(sender, recipient, 10)
            status, body = self.service.submit_transaction(
                {
                    "from": sender,
                    "to": recipient,
                    "amount": 10,
                    "signature": key.sign(message).hex(),
                }
            )
            self.assertEqual(status, 202, body)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("1")[0], 200)
        self.trust = self.service.get_trust_document()[1]

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get(self, account: str, query: str = "") -> tuple[int, dict, str]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        path = f"/v1/accounts/{account}/attested-proof"
        if query:
            path += f"?{query}"
        connection.request("GET", path)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        connection.close()
        return response.status, json.loads(raw), raw

    def document(self, account: str, query: str = "") -> dict:
        status, body, _ = self.get(account, query)
        self.assertEqual(status, 200, body)
        return body


class HttpContractTests(AttestedProofFixture):
    def test_key_orders_on_the_wire(self) -> None:
        status, body, raw = self.get(self.recipients[0])
        document = body
        self.assertEqual(status, 200)
        self.assertEqual(list(document), TOP_KEYS)
        self.assertEqual(list(document["state"]), STATE_KEYS)
        self.assertEqual(list(document["proof"]), PROOF_KEYS)
        self.assertEqual(list(document["auth"]), AUTH_KEYS)
        positions = [raw.index(f'"{key}"') for key in TOP_KEYS]
        self.assertEqual(positions, sorted(positions))
        state_positions = [
            raw.index(f'"{key}"', raw.index('"state"')) for key in STATE_KEYS
        ]
        self.assertEqual(state_positions, sorted(state_positions))

    def test_state_matches_state_root_endpoint(self) -> None:
        status, root_body = self.service.get_state_root()
        self.assertEqual(status, 200)
        document = self.document(self.recipients[0])
        self.assertEqual(document["state"], root_body)

    def test_proof_matches_plain_proof_endpoint(self) -> None:
        status, plain = self.service.get_account_proof(self.recipients[0], None)
        self.assertEqual(status, 200)
        document = self.document(self.recipients[0])
        self.assertEqual(document["proof"], plain)

    def test_accounts_span_multiple_levels(self) -> None:
        # 10 accounts => a 4-level path for at least one leaf.
        any_deep = False
        for account in [*self.senders, *self.recipients]:
            document = self.document(account)
            self.assertEqual(document["state"]["account_count"], 10)
            self.assertTrue(
                light_client.verify_state_proof(document, account, self.trust)[
                    "ok"
                ],
                account,
            )
            any_deep = any_deep or len(document["proof"]["siblings"]) > 1
        self.assertTrue(any_deep)

    def test_historical_height(self) -> None:
        # The account set does not exist at genesis: 404. Height 1 anchors
        # the same confirmed state as the unanchored endpoint.
        status, _, _ = self.get(self.recipients[0], "height=0")
        self.assertEqual(status, 404)
        document = self.document(self.recipients[0], "height=1")
        self.assertEqual(document["state"]["height"], 1)
        self.assertTrue(
            light_client.verify_state_proof(
                document, self.recipients[0], self.trust
            )["ok"]
        )

    def test_query_parameter_rules_match_state_proof(self) -> None:
        account = self.recipients[0]
        for query, expected in (
            ("height=01", 400),  # leading zero
            ("height=-1", 400),
            ("height=1.0", 400),
            ("height=abc", 400),
            ("height=", 400),  # blank value
            ("bogus=1", 400),  # unknown parameter
            ("height=1&height=2", 400),  # repeated
            ("height=99", 404),  # unknown height
        ):
            status, body, _ = self.get(account, query)
            self.assertEqual(status, expected, (query, body))

    def test_missing_account_is_404(self) -> None:
        status, _, _ = self.get("c" * 64)
        self.assertEqual(status, 404)

    def test_pending_tip_is_404(self) -> None:
        key, sender = self.keys[0], self.senders[0]
        recipient = "0" * 64
        message = crypto.canonical_message(sender, recipient, 1)
        self.assertEqual(
            self.service.submit_transaction(
                {
                    "from": sender,
                    "to": recipient,
                    "amount": 1,
                    "signature": key.sign(message).hex(),
                }
            )[0],
            202,
        )
        self.assertEqual(self.service.mine_block()[0], 201)
        status, _, _ = self.get(sender)
        self.assertEqual(status, 404)


class VerifierTests(AttestedProofFixture):
    def test_success_key_order_and_binding(self) -> None:
        document = self.document(self.recipients[2])
        result = light_client.verify_state_proof(
            document, self.recipients[2], self.trust
        )
        self.assertEqual(
            list(result), ["ok", "account", "height", "block_hash", "state_root"]
        )
        self.assertIs(result["ok"], True)
        self.assertEqual(result["account"], self.recipients[2])
        self.assertEqual(result["height"], document["state"]["height"])
        self.assertEqual(result["block_hash"], document["state"]["block_hash"])
        self.assertEqual(result["state_root"], document["state"]["state_root"])

    def test_structure_and_type_errors_are_input(self) -> None:
        account = self.recipients[0]
        document = self.document(account)

        def mutate(**changes) -> dict:
            clone = json.loads(json.dumps(document))
            clone.update(changes)
            return clone

        # Non-object documents / wrong top-level shape.
        for junk in (None, 1, "x", [], {}, [document]):
            self.assertEqual(
                light_client.verify_state_proof(junk, account, self.trust),
                {"ok": False, "error": "input"},
                junk,
            )
        self.assertEqual(
            light_client.verify_state_proof(document, "zz", self.trust),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.verify_state_proof(document, "A" * 64, self.trust),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.verify_state_proof(document, account, {}),
            {"ok": False, "error": "input"},
        )
        # Nested key order / key set.
        reordered = {key: document[key] for key in reversed(TOP_KEYS)}
        self.assertEqual(
            light_client.verify_state_proof(reordered, account, self.trust)[
                "error"
            ],
            "input",
        )
        extra = mutate(x=1)
        self.assertEqual(
            light_client.verify_state_proof(extra, account, self.trust)["error"],
            "input",
        )
        # Types and hex shapes.
        bad_state = json.loads(json.dumps(document))
        bad_state["state"]["height"] = "1"
        self.assertEqual(
            light_client.verify_state_proof(bad_state, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_state["state"] = {}
        self.assertEqual(
            light_client.verify_state_proof(bad_state, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_bool = json.loads(json.dumps(document))
        bad_bool["state"]["height"] = True
        self.assertEqual(
            light_client.verify_state_proof(bad_bool, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_hash = json.loads(json.dumps(document))
        bad_hash["state"]["state_root"] = "0" * 63
        self.assertEqual(
            light_client.verify_state_proof(bad_hash, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_proof = json.loads(json.dumps(document))
        bad_proof["proof"]["confirmed_transactions"] = "x"
        self.assertEqual(
            light_client.verify_state_proof(bad_proof, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_siblings = json.loads(json.dumps(document))
        bad_siblings["proof"]["siblings"] = [{"direction": "up", "hash": "0" * 64}]
        self.assertEqual(
            light_client.verify_state_proof(bad_siblings, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_sig_shape = json.loads(json.dumps(document))
        bad_sig_shape["auth"]["signature"] = "0" * 127
        self.assertEqual(
            light_client.verify_state_proof(bad_sig_shape, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_sig_shape["auth"]["signature"] = "A" * 128
        self.assertEqual(
            light_client.verify_state_proof(bad_sig_shape, account, self.trust)[
                "error"
            ],
            "input",
        )
        bad_version = json.loads(json.dumps(document))
        bad_version["auth"]["key_version"] = 0
        self.assertEqual(
            light_client.verify_state_proof(bad_version, account, self.trust)[
                "error"
            ],
            "input",
        )

    def test_unknown_version_and_bad_signature_are_auth(self) -> None:
        account = self.recipients[0]
        document = self.document(account)
        unknown = json.loads(json.dumps(document))
        unknown["auth"]["key_version"] = 99
        self.assertEqual(
            light_client.verify_state_proof(unknown, account, self.trust),
            {"ok": False, "error": "auth"},
        )
        bad_sig = json.loads(json.dumps(document))
        bad_sig["auth"]["signature"] = "0" * 128
        self.assertEqual(
            light_client.verify_state_proof(bad_sig, account, self.trust),
            {"ok": False, "error": "auth"},
        )
        # A signature made under a different key over the same bytes fails.
        other_seed = crypto.generate_private_key()
        forged_auth = light_client.sign_state_proof(
            other_seed,
            document["auth"]["key_version"],
            document["state"],
            document["proof"],
        )
        self.assertIsNotNone(forged_auth)
        forged = json.loads(json.dumps(document))
        forged["auth"] = forged_auth
        self.assertEqual(
            light_client.verify_state_proof(forged, account, self.trust),
            {"ok": False, "error": "auth"},
        )

    def test_tampering_after_a_valid_signature_is_integrity_reachable(self) -> None:
        # The signature binds every signed byte, so the verifier can only
        # observe a post-signature mutation by re-signing with a trusted
        # key: with key_version remapped to a rotated-but-trusted key the
        # signature stage passes and the structural/binding checks then
        # surface as integrity.
        account = self.recipients[0]
        document = self.document(account)
        seed = crypto.generate_private_key()
        status, _ = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        trust = self.service.get_trust_document()[1]
        version = len(trust["audit_signers"])

        def resigned(mutator) -> dict:
            clone = json.loads(json.dumps(document))
            mutator(clone)
            clone["auth"] = light_client.sign_state_proof(
                seed, version, clone["state"], clone["proof"]
            )
            return clone

        wrong_account = resigned(lambda c: c.__setitem__("proof", {
            **c["proof"], "account": "1" * 64
        }))
        self.assertEqual(
            light_client.verify_state_proof(wrong_account, account, trust)[
                "error"
            ],
            "integrity",
        )
        mismatched_root = resigned(lambda c: c["state"].__setitem__(
            "state_root", "0" * 64
        ))
        self.assertEqual(
            light_client.verify_state_proof(mismatched_root, account, trust)[
                "error"
            ],
            "integrity",
        )
        mismatched_height = resigned(lambda c: c["state"].__setitem__(
            "height", c["state"]["height"] + 1
        ))
        self.assertEqual(
            light_client.verify_state_proof(mismatched_height, account, trust)[
                "error"
            ],
            "integrity",
        )
        # account_count below the proof's index => index out of range.
        bad_count = resigned(lambda c: c["state"].__setitem__(
            "account_count", 0
        ))
        self.assertEqual(
            light_client.verify_state_proof(bad_count, account, trust)["error"],
            "integrity",
        )
        # Tampered leaf content (balance) breaks the recomputed root.
        bad_leaf = resigned(lambda c: c["proof"].__setitem__(
            "balance", c["proof"]["balance"] + 1
        ))
        self.assertEqual(
            light_client.verify_state_proof(bad_leaf, account, trust)["error"],
            "integrity",
        )
        # Tampered sibling hash breaks the Merkle path.
        bad_sibling = resigned(lambda c: c["proof"]["siblings"].__setitem__(
            0, {**c["proof"]["siblings"][0], "hash": "0" * 64}
        ))
        self.assertEqual(
            light_client.verify_state_proof(bad_sibling, account, trust)[
                "error"
            ],
            "integrity",
        )

    def test_wrong_account_pin_is_integrity(self) -> None:
        document = self.document(self.recipients[0])
        self.assertEqual(
            light_client.verify_state_proof(document, self.recipients[1], self.trust),
            {"ok": False, "error": "integrity"},
        )

    def test_never_raises(self) -> None:
        for junk in (None, True, 42, 3.14, "str", [], {}, object()):
            result = light_client.verify_state_proof(junk, junk, junk)
            self.assertEqual(result.get("ok"), False)
            self.assertIn(result.get("error"), ("input",))

    def test_old_version_still_verifies_after_rotation(self) -> None:
        account = self.recipients[0]
        document = self.document(account)
        self.assertEqual(document["auth"]["key_version"], 1)
        self.assertEqual(
            self.service.rotate_audit_signer(
                {"private_key": crypto.generate_private_key(), "expected_version": 1}
            )[0],
            200,
        )
        rotated_trust = self.service.get_trust_document()[1]
        versions = [entry["version"] for entry in rotated_trust["audit_signers"]]
        self.assertEqual(versions, [1, 2])
        # The v1-signed document still verifies against the v1 historical key.
        result = light_client.verify_state_proof(document, account, rotated_trust)
        self.assertTrue(result["ok"], result)


if __name__ == "__main__":
    unittest.main(verbosity=2)

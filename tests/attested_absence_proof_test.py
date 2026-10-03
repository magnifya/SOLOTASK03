"""Tests for the audit-signed account-absence (non-membership) proof.

Covers:

* service GET /v1/accounts/{account}/attested-absence-proof: empty-tree
  documents, predecessor/successor framing and boundaries, historical
  anchors, the fixed wire key order account, state, lower, upper, auth and
  the Ed25519 signature over
  SHA256(UTF8("ledger-state-absence-proof-v1") || canonical_json(document
  without auth));
* strict query-parameter handling (malformed/repeated/unknown 400), empty
  account 404, unknown/non-canonical/pending anchors and pending default tip
  404, existing target 409;
* ledger.light_client.verify_state_absence_proof: input/auth/integrity
  staging (booleans are not integers, missing/extra keys fail regardless of
  key order), account pinning, mixed anchors, adjacency and boundaries,
  empty-tree root, tampering and out-of-range indices, signer rotation and
  historical-key verification, never raising on garbage, and the fixed
  success key order;
* read-only semantics (no ledger/generation/index/audit change), restart
  determinism, fork rebasing, concurrent reads against a mutating chain and
  the HTTP route (fixed key order, repeats, encoding, status matrix).

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
from ledger.models import STATUS_CONFIRMED, Block
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


class AttestedAbsenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "absence.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.endowment = 100_000
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=self.endowment
        )
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)

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

    def state(self, height=None) -> dict:
        status, body = self.svc.get_state_root(height)
        self.assertEqual(status, 200, body)
        return body

    def fetch(self, account, params=None) -> tuple[int, dict]:
        return self.svc.get_attested_account_absence_proof(account, params)

    def test_empty_tree_at_genesis(self) -> None:
        status, doc = self.fetch("nobody", {"height": "0"})
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["account", "state", "lower", "upper", "auth"])
        self.assertEqual(doc["account"], "nobody")
        self.assertIsNone(doc["lower"])
        self.assertIsNone(doc["upper"])
        self.assertEqual(list(doc["auth"]), ["key_version", "signature"])
        self.assertEqual(
            list(doc["state"]),
            ["state_root", "height", "block_hash", "account_count"],
        )
        self.assertEqual(doc["state"]["account_count"], 0)
        self.assertEqual(doc["state"]["state_root"], crypto.EMPTY_MERKLE_ROOT)
        result = light_client.verify_state_absence_proof(doc, "nobody", self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result), ["ok", "account", "height", "block_hash", "state_root"]
        )
        self.assertEqual(result["account"], "nobody")
        self.assertEqual(result["height"], 0)

    def test_plain_absence_fields_unchanged(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        status, plain = self.svc.get_account_absence_proof("ghost")
        self.assertEqual(status, 200, plain)
        status, doc = self.fetch("ghost")
        self.assertEqual(status, 200, doc)
        for key in ("account", "state", "lower", "upper"):
            self.assertEqual(doc[key], plain[key])

    def test_framing_boundaries_and_between(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.send(self.kc, self.C, self.A, 2)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.C, 1)
        self.mine_and_confirm()
        anchor = self.state()
        names = sorted((self.A, self.B, self.C))
        for target, lower_name, upper_name in (
            ("!", None, names[0]),
            (names[1] + "00", names[1], names[2]),
            ("z" * 64, names[-1], None),
        ):
            status, doc = self.fetch(target)
            self.assertEqual(status, 200, doc)
            result = light_client.verify_state_absence_proof(
                doc, target, self.trust
            )
            self.assertTrue(result["ok"], (target, result))
            self.assertEqual(result["height"], anchor["height"])
            self.assertEqual(result["state_root"], anchor["state_root"])
            if lower_name is None:
                self.assertIsNone(doc["lower"])
            else:
                self.assertEqual(doc["lower"]["account"], lower_name)
            if upper_name is None:
                self.assertIsNone(doc["upper"])
            else:
                self.assertEqual(doc["upper"]["account"], upper_name)

    def test_signature_uses_absence_domain(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        status, doc = self.fetch("ghost")
        self.assertEqual(status, 200, doc)
        public_key = self.trust["audit_signers"][0]["public_key"]
        unsigned = {
            "account": doc["account"],
            "state": doc["state"],
            "lower": doc["lower"],
            "upper": doc["upper"],
        }
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        digest = hashlib.sha256(b"ledger-state-absence-proof-v1" + canonical).digest()
        self.assertTrue(
            crypto.verify_signature(public_key, digest, doc["auth"]["signature"])
        )
        # No other domain may authenticate the same body.
        for domain in (
            b"ledger-state-proof-v1",
            b"ledger-state-proofs-v1",
            b"ledger-headers-v1",
            b"ledger-finality-v1",
        ):
            self.assertFalse(
                crypto.verify_signature(
                    public_key,
                    hashlib.sha256(domain + canonical).digest(),
                    doc["auth"]["signature"],
                )
            )

    def test_existing_account_is_409(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        for account in (self.A, self.B):
            self.assertEqual(self.fetch(account)[0], 409)
            self.assertEqual(self.fetch(account, {"height": "1"})[0], 409)

    def test_historical_absence_and_later_appearance(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        status, doc1 = self.fetch(self.C, {"height": "1"})
        self.assertEqual(status, 200, doc1)
        self.assertTrue(
            light_client.verify_state_absence_proof(doc1, self.C, self.trust)["ok"]
        )
        self.send(self.kb, self.B, self.C, 3)
        self.mine_and_confirm()
        status, doc1b = self.fetch(self.C, {"height": "1"})
        self.assertEqual(status, 200)
        self.assertEqual(doc1b, doc1)
        self.assertEqual(self.fetch(self.C)[0], 409)

    def test_query_parameter_errors(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        for bad in ("-1", "00", "1.0", " 1", "1 ", "0x1", "+", ""):
            self.assertEqual(self.fetch("nobody", {"height": bad})[0], 400, bad)
        self.assertEqual(self.fetch("nobody", {"height": 1})[0], 400)
        self.assertEqual(self.fetch("nobody", {"foo": "1"})[0], 400)
        self.assertEqual(
            self.fetch("nobody", {"height": "1", "foo": "1"})[0], 400
        )
        self.assertEqual(self.fetch("nobody", {"height": "999"})[0], 404)

    def test_pending_tip_and_pending_anchor_404(self) -> None:
        self.assertEqual(self.fetch("nobody")[0], 200)
        self.send(self.ka, self.A, self.B, 10)
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201, pending)
        self.assertEqual(self.fetch("nobody")[0], 404)
        self.assertEqual(
            self.fetch("nobody", {"height": str(pending["height"])})[0], 404
        )
        status, doc = self.fetch("nobody", {"height": "0"})
        self.assertEqual(status, 200, doc)

    def test_empty_account_is_404(self) -> None:
        self.assertEqual(self.fetch("")[0], 404)
        self.assertEqual(self.fetch("", {"height": "0"})[0], 404)
        self.assertEqual(self.fetch(5)[0], 404)

    def test_query_is_read_only(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        store = self.svc.store
        generation = store.generation
        events = len(store.audit_events)
        chain_len = len(store.chain)
        mempool = len(store.pending)
        for _ in range(5):
            self.fetch("nobody")
            self.fetch(self.A)
            self.fetch("nobody", {"height": "0"})
        self.assertEqual(store.generation, generation)
        self.assertEqual(len(store.audit_events), events)
        self.assertEqual(len(store.chain), chain_len)
        self.assertEqual(len(store.pending), mempool)

    def test_restart_is_deterministic(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        status, first = self.fetch("ghost")
        self.assertEqual(status, 200)
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=self.endowment
        )
        status, second = reopened.get_attested_account_absence_proof("ghost")
        self.assertEqual(status, 200)
        self.assertEqual(first, second)
        status, reopened_trust = reopened.get_trust_document()
        self.assertEqual(status, 200)
        self.assertTrue(
            light_client.verify_state_absence_proof(
                second, "ghost", reopened_trust
            )["ok"]
        )

    def test_fork_adoption_rebases_absence(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        genesis = self.svc.store.chain[0]
        kx, X = keypair()
        ky, Y = keypair()
        fb1 = Block.create(
            1,
            genesis.block_hash,
            [_fork_block_tx(kx, X, Y, 11)],
            STATUS_CONFIRMED,
        )
        fb2 = Block.create(
            2,
            fb1.block_hash,
            [_fork_block_tx(ky, Y, X, 3)],
            STATUS_CONFIRMED,
        )
        payload = {"blocks": [b.to_dict() for b in (genesis, fb1, fb2)]}
        status, body = self.svc.submit_fork_candidate(payload)
        self.assertEqual(status, 201, body)
        status, adopted = self.svc.adopt_fork(fb2.block_hash)
        self.assertEqual(status, 200, adopted)
        status, doc = self.fetch(self.A, {"height": "1"})
        self.assertEqual(status, 200, doc)
        self.assertTrue(
            light_client.verify_state_absence_proof(doc, self.A, self.trust)["ok"]
        )
        self.assertEqual(self.fetch(X, {"height": "1"})[0], 409)


def _fork_block_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int):
    from ledger.models import Transaction

    msg = crypto.canonical_message(sender, to, amount)
    return Transaction(sender, to, amount, key.sign(msg).hex())


class VerifyStateAbsenceProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        path = os.path.join(self.tmp, "crypto.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(LedgerStore(path), initial_balance=100_000)
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        self.svc.mine_block()
        self.svc.confirm_block("1")
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.C, 1))
        self.svc.mine_block()
        self.svc.confirm_block("2")
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        names = sorted((self.A, self.B, self.C))
        self.target = names[1] + "00"
        status, self.doc = self.svc.get_attested_account_absence_proof(self.target)
        self.assertEqual(status, 200, self.doc)
        status, empty = self.svc.get_attested_account_absence_proof(
            "ghost", {"height": "0"}
        )
        self.assertEqual(status, 200, empty)
        self.empty_doc = empty

    def verify(self, document=None, account=None, trust=None) -> dict:
        return light_client.verify_state_absence_proof(
            self.doc if document is None else document,
            self.target if account is None else account,
            self.trust if trust is None else trust,
        )

    def test_valid_documents_verify(self) -> None:
        self.assertTrue(self.verify()["ok"], self.verify())
        result = light_client.verify_state_absence_proof(
            self.empty_doc, "ghost", self.trust
        )
        self.assertTrue(result["ok"], result)
        for target in ("!", "z" * 64):
            status, doc = self.svc.get_attested_account_absence_proof(target)
            self.assertEqual(status, 200)
            self.assertTrue(
                light_client.verify_state_absence_proof(
                    doc, target, self.trust
                )["ok"]
            )

    def test_field_reordering_is_accepted(self) -> None:
        reordered = {
            "auth": self.doc["auth"],
            "upper": self.doc["upper"],
            "account": self.doc["account"],
            "lower": self.doc["lower"],
            "state": self.doc["state"],
        }
        self.assertTrue(self.verify(document=reordered)["ok"])
        reordered_state = dict(self.doc)
        anchor = self.doc["state"]
        reordered_state["state"] = {
            "account_count": anchor["account_count"],
            "state_root": anchor["state_root"],
            "block_hash": anchor["block_hash"],
            "height": anchor["height"],
        }
        self.assertTrue(self.verify(document=reordered_state)["ok"])

    def test_missing_or_extra_keys_are_input(self) -> None:
        for key in ("account", "state", "lower", "upper", "auth"):
            partial = dict(self.doc)
            del partial[key]
            self.assertEqual(self.verify(document=partial)["error"], "input", key)
        extra = dict(self.doc)
        extra["unexpected"] = 1
        self.assertEqual(self.verify(document=extra)["error"], "input")
        self.assertEqual(self.verify(document=[self.doc])["error"], "input")
        self.assertEqual(self.verify(document=json.dumps(self.doc))["error"], "input")
        # Extra/missing nested keys.
        bad = copy.deepcopy(self.doc)
        del bad["state"]["block_hash"]
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad["lower"]["extra"] = 1
        self.assertEqual(self.verify(document=bad)["error"], "input")
        bad = copy.deepcopy(self.doc)
        bad_auth = dict(bad["auth"])
        del bad_auth["signature"]
        bad["auth"] = bad_auth
        self.assertEqual(self.verify(document=bad)["error"], "input")

    def test_bad_account_pin_is_input(self) -> None:
        for pin in ("", None, 7, True, b"x", []):
            result = light_client.verify_state_absence_proof(
                self.doc, pin, self.trust
            )
            self.assertEqual(result["error"], "input", pin)
        # A non-string document account is input even when the pin matches.
        bad = copy.deepcopy(self.doc)
        bad["account"] = 7
        self.assertEqual(self.verify(document=bad, account=7)["error"], "input")

    def test_type_and_encoding_errors_are_input(self) -> None:
        for field, value in (
            ("height", True),
            ("height", "2"),
            ("height", -1),
            ("account_count", False),
            ("account_count", -2),
            ("state_root", "z" * 64),
            ("block_hash", 9),
        ):
            bad = copy.deepcopy(self.doc)
            bad["state"] = {**bad["state"], field: value}
            self.assertEqual(
                self.verify(document=bad)["error"], "input", (field, value)
            )
        for field, value in (
            ("index", True),
            ("index", -1),
            ("balance", True),
            ("balance", -5),
            ("account", ""),
            ("confirmed_transactions", ("0" * 64,)),
            ("state_root", "ZZ" + "0" * 62),
        ):
            bad = copy.deepcopy(self.doc)
            bad["lower"] = {**bad["lower"], field: value}
            self.assertEqual(
                self.verify(document=bad)["error"], "input", (field, value)
            )
        # Booleans must not count as integers at the envelope level.
        for field, value in (("key_version", True), ("key_version", 0)):
            bad = copy.deepcopy(self.doc)
            bad["auth"] = {**bad["auth"], field: value}
            self.assertEqual(
                self.verify(document=bad)["error"], "input", (field, value)
            )
        bad = copy.deepcopy(self.doc)
        bad["auth"] = {"key_version": 1, "signature": "z" * 128}
        self.assertEqual(self.verify(document=bad)["error"], "input")
        # A null side must literally be null; wrong type is input.
        bad = copy.deepcopy(self.empty_doc)
        bad["lower"] = []
        self.assertEqual(self.verify(document=bad, account="ghost")["error"], "input")

    def test_trust_material_is_input(self) -> None:
        for trust in (
            None,
            7,
            {},
            {"audit_signers": []},
            {"audit_signers": [{"version": "1", "public_key": "0" * 64}]},
            {"audit_signers": [{"version": 1, "public_key": "x"}]},
            {"audit_signers": [
                {"version": 1, "public_key": "0" * 64},
                {"version": 1, "public_key": "1" * 64},
            ]},
        ):
            result = light_client.verify_state_absence_proof(
                self.doc, self.target, trust
            )
            self.assertEqual(result["error"], "input", trust)

    def test_auth_failures(self) -> None:
        # Unknown signer version.
        bad = copy.deepcopy(self.doc)
        bad["auth"] = {**bad["auth"], "key_version": 42}
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "auth"}
        )
        # Well-formed but wrong signature.
        bad = copy.deepcopy(self.doc)
        sig = bad["auth"]["signature"]
        flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
        bad["auth"] = {**bad["auth"], "signature": flipped}
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "auth"}
        )

    def test_account_mismatch_is_integrity(self) -> None:
        other = self.target + "1"
        self.assertEqual(
            self.verify(account=other), {"ok": False, "error": "integrity"}
        )

    def test_neighbor_and_anchor_tampering_is_integrity(self) -> None:
        signer = self.svc.store.audit_signer

        def resign(document: dict) -> dict:
            document["auth"] = light_client.sign_state_absence_proof(
                signer["private_key"],
                signer["version"],
                document["account"],
                document["state"],
                document["lower"],
                document["upper"],
            )
            return document

        # Tamper with a neighbor leaf field and re-sign: signature and
        # structure are valid, the Merkle path no longer recomputes.
        bad = copy.deepcopy(self.doc)
        bad["lower"]["balance"] += 1
        bad = resign(bad)
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"}
        )
        # Tamper with a sibling hash (re-signed so the auth stage passes).
        bad = copy.deepcopy(self.doc)
        bad["upper"]["siblings"][0]["hash"] = "f" * 64
        bad = resign(bad)
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"}
        )
        # Mixed anchors: the neighbor claims a different height/block.
        status, other = self.svc.get_state_root("1")
        self.assertEqual(status, 200)
        bad = copy.deepcopy(self.doc)
        bad["lower"]["height"] = other["height"]
        bad["lower"]["block_hash"] = other["block_hash"]
        bad["lower"]["state_root"] = other["state_root"]
        bad = resign(bad)
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"}
        )
        # Non-adjacent neighbors.
        names = sorted((self.A, self.B, self.C))
        p0 = self.svc.get_account_proof(names[0])[1]
        p2 = self.svc.get_account_proof(names[2])[1]
        forged = {
            "account": self.target,
            "state": self.doc["state"],
            "lower": p0,
            "upper": p2,
        }
        forged = resign(forged)
        self.assertEqual(
            self.verify(document=forged), {"ok": False, "error": "integrity"}
        )
        # Boundary side pointing at the wrong index.
        status, before = self.svc.get_attested_account_absence_proof("!")
        self.assertEqual(status, 200)
        bad = copy.deepcopy(before)
        bad["upper"] = p2
        bad = resign(bad)
        self.assertEqual(
            self.verify(document=bad, account="!"),
            {"ok": False, "error": "integrity"},
        )
        # Both neighbors null in a non-empty tree.
        bad = copy.deepcopy(self.doc)
        bad["lower"] = None
        bad["upper"] = None
        bad = resign(bad)
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"}
        )
        # Empty-tree root mismatch.
        bad = copy.deepcopy(self.empty_doc)
        bad["state"]["state_root"] = "0" * 64
        bad = resign(bad)
        self.assertEqual(
            self.verify(document=bad, account="ghost"),
            {"ok": False, "error": "integrity"},
        )
        # Index out of range inside a neighbor.
        bad = copy.deepcopy(self.doc)
        bad["upper"]["index"] = 999
        bad = resign(bad)
        self.assertEqual(
            self.verify(document=bad), {"ok": False, "error": "integrity"}
        )

    def test_phantom_sibling_slot_is_integrity(self) -> None:
        names = sorted((self.A, self.B, self.C))
        status, after = self.svc.get_attested_account_absence_proof("z" * 64)
        self.assertEqual(status, 200)
        last = copy.deepcopy(after["lower"])
        self.assertEqual(last["index"], 2)
        self.assertEqual(last["siblings"][0]["direction"], "right")
        last["siblings"][0]["direction"] = "left"
        signer = self.svc.store.audit_signer
        forged = {
            "account": "z" * 64,
            "state": after["state"],
            "lower": last,
            "upper": None,
        }
        forged["auth"] = light_client.sign_state_absence_proof(
            signer["private_key"],
            signer["version"],
            "z" * 64,
            forged["state"],
            forged["lower"],
            None,
        )
        self.assertEqual(
            light_client.verify_state_absence_proof(
                forged, "z" * 64, self.trust
            ),
            {"ok": False, "error": "integrity"},
        )

    def test_verifies_after_signer_rotation(self) -> None:
        old_doc = copy.deepcopy(self.doc)
        seed = crypto.generate_private_key()
        status, body = self.svc.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200, body)
        status, new_trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        # The old version-1 document still verifies via the historical key.
        result = light_client.verify_state_absence_proof(
            old_doc, self.target, new_trust
        )
        self.assertTrue(result["ok"], result)
        # A fresh document is signed with version 2 and verifies.
        status, new_doc = self.svc.get_attested_account_absence_proof(self.target)
        self.assertEqual(status, 200, new_doc)
        self.assertEqual(new_doc["auth"]["key_version"], 2)
        self.assertTrue(
            light_client.verify_state_absence_proof(
                new_doc, self.target, new_trust
            )["ok"]
        )
        # Rotation changes the signature but not the unsigned document.
        for key in ("account", "state", "lower", "upper"):
            self.assertEqual(new_doc[key], old_doc[key])
        # A trust document carrying only version 1 cannot verify version 2.
        v1_trust = {
            **new_trust,
            "audit_signers": [
                s for s in new_trust["audit_signers"] if s["version"] == 1
            ],
        }
        self.assertEqual(
            light_client.verify_state_absence_proof(
                new_doc, self.target, v1_trust
            ),
            {"ok": False, "error": "auth"},
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
            {"account": None},
            {"account": self.target, "state": None, "lower": [], "upper": {}},
            {"account": self.target, "state": self.doc["state"],
             "lower": {"siblings": None}, "upper": None},
        ]
        for value in weird:
            try:
                result = self.verify(document=value)
            except Exception as exc:  # pragma: no cover - contract failure
                raise AssertionError((value, exc))
            self.assertIn(result["ok"], (True, False), value)
            if not result["ok"]:
                self.assertEqual(set(result), {"ok", "error"})
        for trust in (None, 7, object()):
            for account in (None, object(), self.target):
                result = light_client.verify_state_absence_proof(
                    self.doc, account, trust
                )
                self.assertFalse(result["ok"])
                self.assertEqual(set(result), {"ok", "error"})

    def test_failure_result_shape(self) -> None:
        result = self.verify(account="other")
        self.assertEqual(result, {"ok": False, "error": "integrity"})
        result = self.verify(trust={"audit_signers": []})
        self.assertEqual(result, {"ok": False, "error": "input"})


class AttestedAbsenceHttpTests(unittest.TestCase):
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
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 10))
        status, blk = cls.service.mine_block()
        assert status == 201
        assert cls.service.confirm_block(blk["height"])[0] == 200
        cls.service.submit_transaction(make_tx(cls.kb, cls.B, cls.C, 2))
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
        names = sorted((self.A, self.B, self.C))
        target = names[1] + "00"
        status, body = self.get(
            f"/v1/accounts/{target}/attested-absence-proof"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), ["account", "state", "lower", "upper", "auth"])
        for side in ("lower", "upper"):
            self.assertEqual(
                list(body[side]),
                [
                    "account",
                    "balance",
                    "confirmed_transactions",
                    "index",
                    "state_root",
                    "height",
                    "block_hash",
                    "siblings",
                ],
            )
        status, trust = self.get("/v1/trust")
        self.assertEqual(status, 200)
        result = light_client.verify_state_absence_proof(body, target, trust)
        self.assertTrue(result["ok"], result)

    def test_status_matrix(self) -> None:
        for path in (
            "/v1/accounts/ghost/attested-absence-proof?height=00",
            "/v1/accounts/ghost/attested-absence-proof?height=-1",
            "/v1/accounts/ghost/attested-absence-proof?height=1%20",
            "/v1/accounts/ghost/attested-absence-proof?foo=1",
            "/v1/accounts/ghost/attested-absence-proof?height=1&height=2",
        ):
            status, body = self.get(path)
            self.assertEqual(status, 400, path)
            self.assertIn("error", body)
        status, _ = self.get(
            "/v1/accounts/ghost/attested-absence-proof?height=999"
        )
        self.assertEqual(status, 404)
        status, _ = self.get(f"/v1/accounts/{self.A}/attested-absence-proof")
        self.assertEqual(status, 409)
        status, _ = self.get("/v1/accounts//attested-absence-proof")
        self.assertEqual(status, 404)
        # An encoded blank account is a valid non-empty target.
        status, body = self.get("/v1/accounts/%20/attested-absence-proof")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["account"], " ")
        self.assertIsNone(body["lower"])

    def test_historical_and_pending(self) -> None:
        status, body = self.get(
            "/v1/accounts/ghost/attested-absence-proof?height=0"
        )
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["lower"])
        self.assertIsNone(body["upper"])
        status, trust = self.get("/v1/trust")
        self.assertEqual(status, 200)
        self.assertTrue(
            light_client.verify_state_absence_proof(body, "ghost", trust)["ok"]
        )
        self.service.submit_transaction(make_tx(self.kc, self.C, self.A, 1))
        status, pending = self.service.mine_block()
        self.assertEqual(status, 201, pending)
        try:
            status, _ = self.get("/v1/accounts/ghost/attested-absence-proof")
            self.assertEqual(status, 404)
            status, _ = self.get(
                f"/v1/accounts/ghost/attested-absence-proof"
                f"?height={pending['height']}"
            )
            self.assertEqual(status, 404)
            status, _ = self.get(
                "/v1/accounts/ghost/attested-absence-proof?height=0"
            )
            self.assertEqual(status, 200)
        finally:
            self.service.rollback_block(pending["height"])

    def test_encoded_account_preserved(self) -> None:
        status, body = self.get(
            "/v1/accounts/a%2Fb%2Fc/attested-absence-proof?height=1"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["account"], "a/b/c")
        status, trust = self.get("/v1/trust")
        self.assertEqual(status, 200)
        self.assertTrue(
            light_client.verify_state_absence_proof(
                body, "a/b/c", trust
            )["ok"]
        )

    def test_existing_endpoints_unchanged(self) -> None:
        status, plain = self.get(f"/v1/accounts/ghost/absence-proof?height=0")
        self.assertEqual(status, 200, plain)
        self.assertEqual(list(plain), ["account", "state", "lower", "upper"])
        status, inclusion = self.get(f"/v1/accounts/{self.A}/attested-proof")
        self.assertEqual(status, 200, inclusion)
        self.assertEqual(list(inclusion), ["state", "proof", "auth"])
        status, root = self.get("/v1/state/root")
        self.assertEqual(status, 200, root)


class AttestedAbsenceConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        path = os.path.join(self.tmp, "concurrent.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(path), initial_balance=100_000
        )
        status, self.trust = self.svc.get_trust_document()
        self.assertEqual(status, 200)

    def send(self, key, sender, to, amount) -> None:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)

    def mine_and_confirm(self) -> None:
        status, blk = self.svc.mine_block()
        self.assertEqual(status, 201, blk)
        status, body = self.svc.confirm_block(blk["height"])
        self.assertEqual(status, 200, body)

    def test_concurrent_reads_are_consistent(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        errors: list[Exception] = []

        def reader() -> None:
            try:
                for _ in range(200):
                    status, doc = self.svc.get_attested_account_absence_proof(
                        self.C, {"height": "1"}
                    )
                    if status != 200:
                        errors.append(AssertionError(status))
                    else:
                        result = light_client.verify_state_absence_proof(
                            doc, self.C, self.trust
                        )
                        if not result["ok"]:
                            errors.append(AssertionError(result))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        self.send(self.kb, self.B, self.A, 9)
        self.mine_and_confirm()
        self.send(self.kc, self.C, self.A, 1)
        status, pending = self.svc.mine_block()
        self.assertEqual(status, 201)
        self.svc.rollback_block(pending["height"])
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

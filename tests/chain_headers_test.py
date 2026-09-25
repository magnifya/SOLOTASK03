"""Tests for the signed block-header pagination endpoint and its offline verifier.

Covers GET /v1/chain/headers (required after_height/after_hash, strict decimal
and 64-hex formats, limit default 100 / range 1-500, repeated parameters 400,
unknown anchor height 404, malformed anchor hash 400, anchor mismatch 409; the
locked {anchor, headers, tip, auth} response with the contract key orders,
ascending-height header items {height, prev_hash, merkle_root, block_hash,
status}, a pending-only-at-tip header, and an empty page when the anchor is the
tip) and ``ledger.light_client.verify_header_page`` (strict key order/types,
``trust.audit_signers`` lookup by key_version, the Ed25519 signature over
SHA256(UTF8("ledger-headers-v1") || canonical_json(page without auth)), caller
anchor/tip pinning, recomputed header hashes and prev_hash linkage, pending
only at the named tip, tip closure; failures map to input/auth/integrity and
nothing is raised) at the service, HTTP and library surfaces.

Run: python3 tests/chain_headers_test.py
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

from ledger import audit, crypto
from ledger.models import STATUS_PENDING
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore
from ledger.light_client import verify_header_page


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


PAGE_KEYS = ("anchor", "headers", "tip", "auth")
HEADER_KEYS = ("height", "prev_hash", "merkle_root", "block_hash", "status")
TIP_KEYS = ("tip_hash", "height", "length", "status")
AUTH_KEYS = ("key_version", "signature")
ANCHOR_KEYS = ("height", "block_hash")


class HeaderPageServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "h.json"))
        self.service = LedgerService(self.store)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        for amount in (10, 20, 30):
            self.assertEqual(
                self.service.submit_transaction(
                    signed_tx(self.ka, self.A, self.B, amount)
                )[0],
                202,
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0], 200
            )
        self.genesis = self.store.chain[0].block_hash
        self.tip_hash = self.store.chain[3].block_hash

    def test_page_shape_key_orders_and_tip(self) -> None:
        status, page = self.service.get_chain_headers(
            {"after_height": "0", "after_hash": self.genesis, "limit": "2"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(tuple(page.keys()), PAGE_KEYS)
        self.assertEqual(tuple(page["anchor"].keys()), ANCHOR_KEYS)
        self.assertEqual(page["anchor"], {"height": 0, "block_hash": self.genesis})
        self.assertEqual([h["height"] for h in page["headers"]], [1, 2])
        for header in page["headers"]:
            self.assertEqual(tuple(header.keys()), HEADER_KEYS)
            self.assertEqual(header["status"], "confirmed")
        self.assertEqual(tuple(page["tip"].keys()), TIP_KEYS)
        self.assertEqual(
            page["tip"],
            {"tip_hash": self.tip_hash, "height": 3, "length": 4, "status": "confirmed"},
        )
        self.assertEqual(tuple(page["auth"].keys()), AUTH_KEYS)
        self.assertEqual(page["auth"]["key_version"], 1)
        self.assertTrue(crypto.is_hex128(page["auth"]["signature"]))

    def test_default_limit_and_paging_to_the_tip(self) -> None:
        status, page = self.service.get_chain_headers(
            {"after_height": "0", "after_hash": self.genesis}
        )
        self.assertEqual(status, 200)
        self.assertEqual([h["height"] for h in page["headers"]], [1, 2, 3])
        anchor2 = self.store.chain[2]
        status, page2 = self.service.get_chain_headers(
            {"after_height": "2", "after_hash": anchor2.block_hash}
        )
        self.assertEqual(status, 200)
        self.assertEqual([h["height"] for h in page2["headers"]], [3])

    def test_empty_page_at_tip(self) -> None:
        status, page = self.service.get_chain_headers(
            {"after_height": "3", "after_hash": self.tip_hash}
        )
        self.assertEqual(status, 200)
        self.assertEqual(page["headers"], [])
        self.assertEqual(page["anchor"], {"height": 3, "block_hash": self.tip_hash})
        self.assertEqual(page["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(page["tip"]["height"], 3)

    def test_strict_parameters(self) -> None:
        def status_for(**params) -> int:
            return self.service.get_chain_headers(params)[0]

        self.assertEqual(status_for(after_hash=self.genesis), 400)
        self.assertEqual(status_for(after_height="0"), 400)
        self.assertEqual(status_for(after_height="x", after_hash=self.genesis), 400)
        self.assertEqual(status_for(after_height="01", after_hash=self.genesis), 400)
        self.assertEqual(status_for(after_height="-1", after_hash=self.genesis), 400)
        self.assertEqual(
            status_for(after_height="0", after_hash="z" * 64), 400
        )
        self.assertEqual(status_for(after_height="0", after_hash=""), 400)
        self.assertEqual(
            status_for(after_height="0", after_hash=self.genesis, limit="0"), 400
        )
        self.assertEqual(
            status_for(after_height="0", after_hash=self.genesis, limit="501"), 400
        )
        self.assertEqual(
            status_for(after_height="0", after_hash=self.genesis, limit="x"), 400
        )

    def test_unknown_height_404_and_hash_mismatch_409(self) -> None:
        self.assertEqual(
            self.service.get_chain_headers(
                {"after_height": "99", "after_hash": self.genesis}
            )[0],
            404,
        )
        self.assertEqual(
            self.service.get_chain_headers(
                {"after_height": "0", "after_hash": self.store.chain[1].block_hash}
            )[0],
            409,
        )

    def test_pending_tip_is_exported(self) -> None:
        self.assertEqual(
            self.service.submit_transaction(
                signed_tx(self.ka, self.A, self.B, 5)
            )[0],
            202,
        )
        self.assertEqual(self.service.mine_block()[0], 201)
        pending_hash = self.store.chain[4].block_hash
        status, page = self.service.get_chain_headers(
            {"after_height": "3", "after_hash": self.tip_hash}
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(page["headers"]), 1)
        header = page["headers"][0]
        self.assertEqual(header["height"], 4)
        self.assertEqual(header["status"], STATUS_PENDING)
        self.assertEqual(header["block_hash"], pending_hash)
        self.assertEqual(
            page["tip"],
            {
                "tip_hash": pending_hash,
                "height": 4,
                "length": 5,
                "status": STATUS_PENDING,
            },
        )


class VerifyHeaderPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "v.json"))
        self.service = LedgerService(self.store)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        for amount in (10, 20, 30):
            self.service.submit_transaction(signed_tx(self.ka, self.A, self.B, amount))
            self.service.mine_block()
            self.service.confirm_block(str(self.store.tip().height))
        self.genesis = self.store.chain[0].block_hash
        self.tip_hash = self.store.chain[3].block_hash
        self.anchor = {"height": 0, "block_hash": self.genesis}
        _, self.trust = self.service.get_trust_document()
        _, self.page = self.service.get_chain_headers(
            {"after_height": "0", "after_hash": self.genesis, "limit": "2"}
        )

    def resign(self, document: dict, key_version: int | None = None) -> dict:
        """Sign tampered content with the node's current audit signer."""
        out = copy.deepcopy(document)
        unsigned = {key: value for key, value in out.items() if key != "auth"}
        version = (
            self.store.audit_signer["version"] if key_version is None else key_version
        )
        out["auth"] = {
            "key_version": version,
            "signature": audit.sign_header_auth(
                self.store.audit_signer["private_key"], unsigned
            ),
        }
        return out

    def test_success_key_order_and_hashes(self) -> None:
        result = verify_header_page(self.page, self.anchor, self.tip_hash, self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            tuple(result.keys()), ("ok", "anchor", "tip", "verified_block_hashes")
        )
        self.assertEqual(result["anchor"], self.anchor)
        self.assertEqual(result["tip"], self.page["tip"])
        self.assertEqual(
            result["verified_block_hashes"],
            [header["block_hash"] for header in self.page["headers"]],
        )

    def test_empty_page_verifies_only_when_anchor_is_tip(self) -> None:
        _, empty = self.service.get_chain_headers(
            {"after_height": "3", "after_hash": self.tip_hash}
        )
        result = verify_header_page(
            empty, {"height": 3, "block_hash": self.tip_hash}, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_block_hashes"], [])
        # A validly signed empty page whose anchor is not the tip is rejected.
        forged = self.resign(empty)
        result = verify_header_page(forged, self.anchor, self.tip_hash, self.trust)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "integrity")

    def test_pending_tip_page_verifies(self) -> None:
        self.service.submit_transaction(signed_tx(self.ka, self.A, self.B, 5))
        self.service.mine_block()
        pending_hash = self.store.chain[4].block_hash
        _, pending_page = self.service.get_chain_headers(
            {"after_height": "3", "after_hash": self.tip_hash}
        )
        result = verify_header_page(
            pending_page,
            {"height": 3, "block_hash": self.tip_hash},
            pending_hash,
            self.trust,
        )
        self.assertTrue(result["ok"], result)
        # A page ending before the pending tip still names the pending tip.
        _, early = self.service.get_chain_headers(
            {"after_height": "0", "after_hash": self.genesis, "limit": "3"}
        )
        result = verify_header_page(early, self.anchor, pending_hash, self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], STATUS_PENDING)

    def test_auth_failures(self) -> None:
        # Tampered content invalidates the page signature first.
        for mutate in (
            lambda doc: doc["headers"][0].__setitem__("block_hash", "a" * 64),
            lambda doc: doc["headers"][1].__setitem__("prev_hash", "a" * 64),
            lambda doc: doc["tip"].__setitem__("tip_hash", "a" * 64),
        ):
            bad = copy.deepcopy(self.page)
            mutate(bad)
            self.assertEqual(
                verify_header_page(bad, self.anchor, self.tip_hash, self.trust)[
                    "error"
                ],
                "auth",
            )
        bad = copy.deepcopy(self.page)
        bad["auth"]["signature"] = "a" * 128
        self.assertEqual(
            verify_header_page(bad, self.anchor, self.tip_hash, self.trust)["error"],
            "auth",
        )
        bad = copy.deepcopy(self.page)
        bad["auth"]["key_version"] = 99
        self.assertEqual(
            verify_header_page(bad, self.anchor, self.tip_hash, self.trust)["error"],
            "auth",
        )

    def test_integrity_failures(self) -> None:
        bad = copy.deepcopy(self.page)
        bad["headers"][0]["block_hash"] = "a" * 64
        self.assertEqual(
            verify_header_page(
                self.resign(bad), self.anchor, self.tip_hash, self.trust
            )["error"],
            "integrity",
        )
        bad = copy.deepcopy(self.page)
        bad["headers"][1]["prev_hash"] = "a" * 64
        self.assertEqual(
            verify_header_page(
                self.resign(bad), self.anchor, self.tip_hash, self.trust
            )["error"],
            "integrity",
        )
        bad = copy.deepcopy(self.page)
        bad["headers"][0]["merkle_root"] = "a" * 64
        self.assertEqual(
            verify_header_page(
                self.resign(bad), self.anchor, self.tip_hash, self.trust
            )["error"],
            "integrity",
        )
        bad = copy.deepcopy(self.page)
        bad["tip"]["length"] = 99
        self.assertEqual(
            verify_header_page(
                self.resign(bad), self.anchor, self.tip_hash, self.trust
            )["error"],
            "integrity",
        )
        # A pending header in the middle of the page is illegal.
        mid = copy.deepcopy(self.page)
        mid["headers"][0]["status"] = STATUS_PENDING
        self.assertEqual(
            verify_header_page(
                self.resign(mid), self.anchor, self.tip_hash, self.trust
            )["error"],
            "integrity",
        )
        # Caller pins that disagree with a validly signed page are integrity.
        self.assertEqual(
            verify_header_page(
                self.page,
                {"height": 1, "block_hash": self.store.chain[1].block_hash},
                self.tip_hash,
                self.trust,
            )["error"],
            "integrity",
        )
        self.assertEqual(
            verify_header_page(
                self.page, self.anchor, "a" * 64, self.trust
            )["error"],
            "integrity",
        )

    def test_input_failures(self) -> None:
        for document in ("x", {"a": 1}, [], None, object()):
            self.assertEqual(
                verify_header_page(document, self.anchor, self.tip_hash, self.trust)[
                    "error"
                ],
                "input",
            )
        mutations = (
            lambda doc: doc["anchor"].__setitem__("height", "0"),
            lambda doc: doc["headers"].__setitem__(0, "notdict"),
            lambda doc: doc["headers"][0].__setitem__("height", True),
            lambda doc: doc["headers"][0].__setitem__("block_hash", "Z" * 64),
            lambda doc: doc["headers"][0].__setitem__("status", "weird"),
            lambda doc: doc["headers"][0].pop("status"),
            lambda doc: doc["tip"].__setitem__("length", 0),
            lambda doc: doc["auth"].__setitem__("key_version", 0),
            lambda doc: doc["auth"].__setitem__("signature", "a"),
            lambda doc: doc.pop("auth"),
        )
        for mutate in mutations:
            bad = copy.deepcopy(self.page)
            mutate(bad)
            self.assertEqual(
                verify_header_page(bad, self.anchor, self.tip_hash, self.trust)[
                    "error"
                ],
                "input",
            )
        self.assertEqual(
            verify_header_page(
                self.page, {"height": "0", "block_hash": self.genesis},
                self.tip_hash, self.trust,
            )["error"],
            "input",
        )
        self.assertEqual(
            verify_header_page(
                self.page, self.anchor, "nothex", self.trust
            )["error"],
            "input",
        )
        self.assertEqual(
            verify_header_page(
                self.page, self.anchor, self.tip_hash, {"audit_signers": []}
            )["error"],
            "input",
        )
        self.assertEqual(
            verify_header_page(
                self.page, self.anchor, self.tip_hash,
                {"audit_signers": "x"},
            )["error"],
            "input",
        )
        # Wildly malformed arguments never raise.
        self.assertEqual(
            verify_header_page(object(), object(), object(), object())["error"],
            "input",
        )

    def test_signer_rotation_selects_key_by_version(self) -> None:
        rotated = self.service.rotate_audit_signer(
            {"private_key": "22" * 32, "expected_version": 1}
        )[0]
        self.assertEqual(rotated, 200)
        _, trust2 = self.service.get_trust_document()
        _, page2 = self.service.get_chain_headers(
            {"after_height": "0", "after_hash": self.genesis, "limit": "2"}
        )
        self.assertEqual(page2["auth"]["key_version"], 2)
        # The new page verifies under the updated trust document.
        self.assertTrue(
            verify_header_page(page2, self.anchor, self.tip_hash, trust2)["ok"]
        )
        # The old trust document (version 1 only) cannot authenticate it.
        self.assertEqual(
            verify_header_page(page2, self.anchor, self.tip_hash, self.trust)[
                "error"
            ],
            "auth",
        )
        # The old version-1 page still verifies under the new trust document.
        self.assertTrue(
            verify_header_page(
                self.page, self.anchor, self.tip_hash, trust2
            )["ok"]
        )


class HeaderPageHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(LedgerStore(os.path.join(cls.tmp, "http.json")))
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        for amount in (10, 20):
            cls.service.submit_transaction(signed_tx(cls.ka, cls.A, cls.B, amount))
            cls.service.mine_block()
            cls.service.confirm_block(str(cls.service.store.tip().height))
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, path: str):
        try:
            with urllib.request.urlopen(f"{cls.base}{path}") as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_http_page_wire_key_order_and_status_codes(self) -> None:
        genesis = self.service.store.chain[0].block_hash
        status, raw = self.request(
            f"/v1/chain/headers?after_height=0&after_hash={genesis}"
        )
        self.assertEqual(status, 200)
        # The wire serialization preserves the contract key order, not the
        # alphabetical default.
        self.assertTrue(raw.startswith('{"anchor":'), raw[:40])
        body = json.loads(raw)
        self.assertEqual(tuple(body.keys()), PAGE_KEYS)
        self.assertEqual(tuple(body["headers"][0].keys()), HEADER_KEYS)

        self.assertEqual(self.request("/v1/chain/headers")[0], 400)
        self.assertEqual(
            self.request(
                f"/v1/chain/headers?after_height=0&after_height=1&after_hash={genesis}"
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                f"/v1/chain/headers?after_height=99&after_hash={genesis}"
            )[0],
            404,
        )
        other = self.service.store.chain[0]
        # Reversing the lowercase-hex genesis hash keeps a legal hash format
        # but cannot match the block at height 0.
        self.assertEqual(
            self.request(
                f"/v1/chain/headers?after_height=0&after_hash={other.block_hash[::-1]}"
            )[0],
            409,
        )


if __name__ == "__main__":
    unittest.main()

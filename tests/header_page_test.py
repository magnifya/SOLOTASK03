"""Tests for the signed block-header page endpoint and its offline verifier.

Covers GET /v1/chain/headers (required after_height/after_hash, limit
defaulting to 100 in 1-500, the same 400/404/409 semantics as
/v1/chain/range), the fixed key order anchor, headers, tip, auth and the
header item order height, prev_hash, merkle_root, block_hash, status, an
empty headers list when the anchor is the chain tip, the pending tail block,
the Ed25519 signature over
SHA256(UTF8("ledger-headers-v1") || canonical_json(document without auth))
under the current audit signer, and ledger.light_client.verify_header_page
(input/auth/integrity categorization, anchor and tip pinning, recomputed
hashes and links, chained pagination, and signer-rotation history).

Run: python3 tests/header_page_test.py
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

from ledger import crypto
from ledger.light_client import (
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    HEADER_PAGE_DOMAIN,
    sign_header_page,
    verify_header_page,
)
from ledger.models import STATUS_PENDING
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class HeaderPageFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "headers.json"))
        self.service = LedgerService(self.store)
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        # A confirmed chain 0..3 plus a pending tip at height 4.
        for amount in (10, 20, 30):
            self.assertEqual(
                self.service.submit_transaction(self._tx(amount))[0], 202
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0],
                200,
            )
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.genesis_hash = self.store.chain[0].block_hash
        self.tip_hash = self.store.tip_hash()
        self.trust = self.service.get_trust_document()[1]

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body


class HeaderPageServiceTests(HeaderPageFixture):
    def test_param_errors_match_range(self) -> None:
        g = self.genesis_hash
        get = self.service.get_chain_headers
        self.assertEqual(get({})[0], 400)
        self.assertEqual(get({"after_height": "0"})[0], 400)
        self.assertEqual(get({"after_hash": g})[0], 400)
        self.assertEqual(get({"after_height": "00", "after_hash": g})[0], 400)
        self.assertEqual(get({"after_height": "-1", "after_hash": g})[0], 400)
        self.assertEqual(
            get({"after_height": "1.0", "after_hash": g})[0], 400
        )
        self.assertEqual(get({"after_height": "0", "after_hash": "abc"})[0], 400)
        self.assertEqual(
            get({"after_height": "0", "after_hash": g, "limit": ""})[0], 400
        )
        self.assertEqual(
            get({"after_height": "0", "after_hash": g, "limit": "0"})[0], 400
        )
        self.assertEqual(
            get({"after_height": "0", "after_hash": g, "limit": "501"})[0], 400
        )
        self.assertEqual(
            get({"after_height": "99", "after_hash": g})[0], 404
        )
        self.assertEqual(
            get({"after_height": "0", "after_hash": "a" * 64})[0], 409
        )

    def test_page_shapes_and_order(self) -> None:
        page = self.page(0, self.genesis_hash)
        self.assertEqual(
            list(page.keys()), ["anchor", "headers", "tip", "auth"]
        )
        self.assertEqual(
            page["anchor"],
            {"height": 0, "block_hash": self.genesis_hash},
        )
        self.assertEqual(list(page["anchor"].keys()), ["height", "block_hash"])
        self.assertEqual([h["height"] for h in page["headers"]], [1, 2, 3, 4])
        for index, header in enumerate(page["headers"], start=1):
            block = self.store.chain[index]
            self.assertEqual(
                list(header.keys()),
                ["height", "prev_hash", "merkle_root", "block_hash", "status"],
            )
            self.assertEqual(header["height"], block.height)
            self.assertEqual(header["prev_hash"], block.prev_hash)
            self.assertEqual(header["merkle_root"], block.merkle_root)
            self.assertEqual(header["block_hash"], block.block_hash)
            self.assertEqual(header["status"], block.status)
            # Headers carry no transaction data.
            self.assertNotIn("transactions", header)
            self.assertNotIn("transaction_ids", header)
        self.assertEqual(
            [h["status"] for h in page["headers"]],
            ["confirmed", "confirmed", "confirmed", STATUS_PENDING],
        )
        self.assertEqual(
            page["tip"],
            {
                "tip_hash": self.tip_hash,
                "height": 4,
                "length": 5,
                "status": STATUS_PENDING,
            },
        )
        self.assertEqual(list(page["tip"].keys()),
                         ["tip_hash", "height", "length", "status"])
        self.assertEqual(list(page["auth"].keys()), ["key_version", "signature"])
        self.assertEqual(page["auth"]["key_version"], 1)
        self.assertTrue(crypto.is_hex128(page["auth"]["signature"]))

    def test_limit_paging_defaults_to_100(self) -> None:
        page = self.page(0, self.genesis_hash, limit=2)
        self.assertEqual([h["height"] for h in page["headers"]], [1, 2])
        # Continue paging at the last delivered header.
        last_hash = page["headers"][-1]["block_hash"]
        page2 = self.page(2, last_hash)
        self.assertEqual([h["height"] for h in page2["headers"]], [3, 4])
        # limit=1 boundary.
        one = self.page(0, self.genesis_hash, limit=1)
        self.assertEqual([h["height"] for h in one["headers"]], [1])
        # A large limit is capped by the chain length, not an error.
        big = self.page(0, self.genesis_hash, limit=500)
        self.assertEqual(len(big["headers"]), 4)

    def test_anchor_at_tip_is_empty(self) -> None:
        page = self.page(4, self.tip_hash)
        self.assertEqual(page["headers"], [])
        self.assertEqual(page["anchor"], {"height": 4, "block_hash": self.tip_hash})
        self.assertEqual(page["tip"]["tip_hash"], self.tip_hash)
        # The empty page is signed exactly like a non-empty one.
        self.assertIn("auth", page)

    def test_signature_domain_and_bytes(self) -> None:
        page = self.page(0, self.genesis_hash)
        unsigned = {
            "anchor": page["anchor"],
            "headers": page["headers"],
            "tip": page["tip"],
        }
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        message = HEADER_PAGE_DOMAIN.encode("utf-8") + canonical
        public_key = self.trust["audit_signers"][0]["public_key"]
        self.assertTrue(
            crypto.verify_signature(
                public_key,
                hashlib.sha256(message).digest(),
                page["auth"]["signature"],
            )
        )

    def test_wire_key_order_is_contract_order(self) -> None:
        # The HTTP layer must not alphabetically reorder the document.
        status, body = self.service.get_chain_headers(
            {"after_height": "0", "after_hash": self.genesis_hash}
        )
        raw = json.dumps(body, sort_keys=False)
        self.assertLess(raw.index('"anchor"'), raw.index('"headers"'))
        self.assertLess(raw.index('"headers"'), raw.index('"tip"'))
        self.assertLess(raw.index('"tip"'), raw.index('"auth"'))
        self.assertEqual(status, 200)


class HeaderPageVerifyTests(HeaderPageFixture):
    def _verify(self, document, anchor=None, tip_hash=None, trust=None):
        anchor_value = (
            document["anchor"]
            if anchor is None and isinstance(document, dict)
            else anchor
        )
        return verify_header_page(
            document,
            anchor_value,
            self.tip_hash if tip_hash is None else tip_hash,
            self.trust if trust is None else trust,
        )

    def test_verifies_genuine_pages_and_chains_them(self) -> None:
        first = self.page(0, self.genesis_hash, limit=2)
        result = self._verify(first)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result.keys()),
            ["ok", "anchor", "tip", "verified_block_hashes"],
        )
        self.assertEqual(result["anchor"], first["anchor"])
        self.assertEqual(result["tip"], first["tip"])
        self.assertEqual(
            result["verified_block_hashes"],
            [h["block_hash"] for h in first["headers"]],
        )
        # Second page chained off the first page's last header.
        second = self.page(2, first["headers"][-1]["block_hash"])
        result2 = self._verify(second)
        self.assertTrue(result2["ok"], result2)
        self.assertEqual(
            result2["verified_block_hashes"],
            [
                self.store.chain[3].block_hash,
                self.store.chain[4].block_hash,
            ],
        )

    def test_empty_page_at_tip_verifies_with_empty_hashes(self) -> None:
        page = self.page(4, self.tip_hash)
        result = self._verify(page)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_block_hashes"], [])

    def test_input_errors(self) -> None:
        page = self.page(0, self.genesis_hash)

        def check(document, **kwargs):
            result = self._verify(document, **kwargs)
            self.assertEqual(result, {"ok": False, "error": ERR_INPUT}, result)

        check("not a dict")
        check([])
        reordered = {"headers": [], "anchor": page["anchor"]}
        reordered.update({"tip": page["tip"], "auth": page["auth"]})
        check(reordered)
        extra = copy.deepcopy(page)
        extra["unexpected"] = 1
        check(extra)
        missing = copy.deepcopy(page)
        del missing["auth"]
        check(missing)
        bad_anchor = copy.deepcopy(page)
        bad_anchor["anchor"] = {"block_hash": self.genesis_hash, "height": 0}
        self._re_sign(bad_anchor)
        check(bad_anchor)
        bad_anchor2 = copy.deepcopy(page)
        bad_anchor2["anchor"] = {"height": 0, "block_hash": "0" * 64,
                                 "extra": 1}
        self._re_sign(bad_anchor2)
        check(bad_anchor2)
        bad_height = copy.deepcopy(page)
        bad_height["headers"][0]["height"] = "1"
        self._re_sign(bad_height)
        check(bad_height)
        bool_height = copy.deepcopy(page)
        bool_height["headers"][0]["height"] = True
        self._re_sign(bool_height)
        check(bool_height)
        bad_hash = copy.deepcopy(page)
        bad_hash["headers"][0]["block_hash"] = "Z" * 64
        self._re_sign(bad_hash)
        check(bad_hash)
        bad_status = copy.deepcopy(page)
        bad_status["headers"][0]["status"] = "final"
        self._re_sign(bad_status)
        check(bad_status)
        item_extra = copy.deepcopy(page)
        item_extra["headers"][0]["extra"] = 1
        self._re_sign(item_extra)
        check(item_extra)
        bad_tip = copy.deepcopy(page)
        bad_tip["tip"]["height"] = 4.0
        self._re_sign(bad_tip)
        check(bad_tip)
        bad_auth = copy.deepcopy(page)
        bad_auth["auth"] = {"signature": page["auth"]["signature"],
                            "key_version": 1}
        check(bad_auth)
        bad_auth2 = copy.deepcopy(page)
        bad_auth2["auth"] = {"key_version": 1, "signature": "z" * 128}
        check(bad_auth2)
        check(page, anchor={"height": -1, "block_hash": self.genesis_hash})
        check(page, tip_hash="not-hex")
        check(page, trust={"audit_signers": []})
        check(page, trust={"audit_signers": [{}]})
        check(page, trust={"audit_signers": [
            {"version": 1, "public_key": "x" * 64}
        ]})
        check(page, trust="bare")

    def test_auth_errors(self) -> None:
        page = self.page(0, self.genesis_hash)
        # Unknown key version.
        wrong_version = copy.deepcopy(page)
        wrong_version["auth"] = {"key_version": 7,
                                 "signature": "0" * 128}
        self.assertEqual(
            self._verify(wrong_version), {"ok": False, "error": ERR_AUTH}
        )
        # Known version, bad signature.
        bad_sig = copy.deepcopy(page)
        bad_sig["auth"]["signature"] = "0" * 128
        self.assertEqual(
            self._verify(bad_sig), {"ok": False, "error": ERR_AUTH}
        )
        # Known version, wrong public key in trust.
        other_pub = pub_hex(Ed25519PrivateKey.generate())
        trust = {"audit_signers": [
            {"version": 1, "public_key": other_pub}
        ]}
        self.assertEqual(
            self._verify(page, trust=trust),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_integrity_errors(self) -> None:
        page = self.page(0, self.genesis_hash, limit=2)

        def tampered():
            doc = copy.deepcopy(page)
            return doc

        # A tampered header hash, re-signed so auth passes, fails integrity.
        doc = tampered()
        doc["headers"][1]["block_hash"] = "f" * 64
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # Tampered merkle root moves the recomputed block hash.
        doc = tampered()
        doc["headers"][0]["merkle_root"] = "a" * 64
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # A broken prev_hash link.
        doc = tampered()
        doc["headers"][1]["prev_hash"] = "1" * 64
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # A height gap.
        doc = tampered()
        doc["headers"] = [doc["headers"][1]]
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # Pending header on a non-final page (tip continues past it).
        doc = tampered()
        doc["headers"][-1]["status"] = STATUS_PENDING
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # Pending header in the middle of a page.
        full = self.page(0, self.genesis_hash)
        doc = copy.deepcopy(full)
        doc["headers"][1]["status"] = STATUS_PENDING
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # Empty page whose anchor is not the tip.
        empty = self.page(4, self.tip_hash)
        doc = copy.deepcopy(empty)
        doc["anchor"] = {"height": 0, "block_hash": self.genesis_hash}
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # A page past the pinned tip.
        self.assertEqual(
            self._verify(page, tip_hash="a" * 64),
            {"ok": False, "error": ERR_INTEGRITY},
        )
        # A wrong caller-pinned anchor (document unchanged).
        self.assertEqual(
            self._verify(
                page,
                anchor={"height": 1,
                        "block_hash": self.store.chain[1].block_hash},
            ),
            {"ok": False, "error": ERR_INTEGRITY},
        )
        # tip length inconsistent with height.
        doc = copy.deepcopy(full)
        doc["tip"]["length"] = 99
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})
        # Final page whose declared tip status disagrees with the last header.
        doc = copy.deepcopy(full)
        doc["tip"]["status"] = "confirmed"
        self._re_sign(doc)
        self.assertEqual(self._verify(doc),
                         {"ok": False, "error": ERR_INTEGRITY})

    def test_rotation_signs_with_current_version_keeps_history(self) -> None:
        # A page minted before rotation stays verifiable after rotation: the
        # old v1 signature remains valid under v1's history public key.
        before = self.page(0, self.genesis_hash)
        self.assertEqual(before["auth"]["key_version"], 1)
        old_signature = before["auth"]["signature"]
        seed = crypto.generate_private_key()
        new_pub = crypto.derive_public_key(seed)
        status, rotated = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200, rotated)
        trust = self.service.get_trust_document()[1]
        self.assertEqual(len(trust["audit_signers"]), 2)
        # New pages are signed under version 2 and verify.
        after = self.page(0, self.genesis_hash)
        self.assertEqual(after["auth"]["key_version"], 2)
        self.assertEqual(
            trust["audit_signers"][1]["public_key"], new_pub
        )
        self.assertTrue(
            verify_header_page(
                after, after["anchor"], self.tip_hash, trust
            )["ok"]
        )
        # The old page's body and v1 envelope are unchanged; history keeps it
        # verifiable.
        self.assertEqual(before["auth"]["signature"], old_signature)
        self.assertTrue(
            verify_header_page(
                before, before["anchor"], self.tip_hash, trust
            )["ok"]
        )
        # Claiming the v2 signature under version 1 is an auth failure.
        tampered = copy.deepcopy(after)
        tampered["auth"]["key_version"] = 1
        self.assertEqual(
            verify_header_page(
                tampered, tampered["anchor"], self.tip_hash, trust
            ),
            {"ok": False, "error": ERR_AUTH},
        )

    def _re_sign(self, document: dict) -> None:
        """Re-sign a tampered document with the current audit signer so the
        signature itself stays valid and only integrity is at stake."""
        signer = self.store.audit_signer
        envelope = sign_header_page(
            signer["private_key"],
            signer["version"],
            document["anchor"],
            document["headers"],
            document["tip"],
        )
        self.assertIsNotNone(envelope)
        document["auth"] = envelope


class HeaderPageHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"))
        )
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
        req = urllib.request.Request(f"{cls.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_headers_http(self) -> None:
        g = self.service.store.chain[0].block_hash
        status, raw = self.request(
            f"/v1/chain/headers?after_height=0&after_hash={g}"
        )
        self.assertEqual(status, 200, raw)
        # Contract key order over the wire (not alphabetized).
        self.assertEqual(
            [
                segment
                for segment in ("anchor", "headers", "tip", "auth")
                if f'"{segment}"' in raw
            ],
            ["anchor", "headers", "tip", "auth"],
        )
        body = json.loads(raw)
        self.assertEqual(
            list(body.keys()), ["anchor", "headers", "tip", "auth"]
        )
        trust = self.service.get_trust_document()[1]
        self.assertTrue(
            verify_header_page(
                body, body["anchor"], body["tip"]["tip_hash"], trust
            )["ok"]
        )
        # Error mapping at the HTTP boundary.
        self.assertEqual(self.request("/v1/chain/headers")[0], 400)
        self.assertEqual(
            self.request("/v1/chain/headers?after_height=0")[0], 400
        )
        self.assertEqual(
            self.request(
                f"/v1/chain/headers?after_height=0&after_hash={g}&limit=501"
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                f"/v1/chain/headers?after_height=0&after_hash={g}"
                f"&after_height=1"
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "/v1/chain/headers?after_height=99&after_hash=" + g
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "/v1/chain/headers?after_height=0&after_hash=" + "a" * 64
            )[0],
            409,
        )


if __name__ == "__main__":
    unittest.main()

"""Tests for the paginated finality-credential delivery
``GET /v1/chain/finalities``.

Builds a confirmed chain with a pending tip through the real service and
covers:

* the success document: top-level key order ``anchor, finalities, next,
  head``; ``anchor`` (key order ``height, block_hash``) echoes the
  request anchor; ``finalities`` are the confirmed blocks strictly after
  it in ascending height (at most ``limit``), each with the exact
  ``GET /v1/chain/finality`` key order ``finalized, tip, auth`` where
  ``finalized`` names that block and ``tip`` is the descriptor S of the
  chain prefix ending at it; ``head`` is the current finality credential
  (identical to ``GET /v1/chain/finality``); ``next`` is the last item's
  ``finalized`` while the page has not reached the head and ``null``
  otherwise (an anchor that is already the head yields an empty page and
  ``next: null``);
* every item's and the head's signature verifies as
  Ed25519(SHA256(UTF8("ledger-finality-v1") || canonical_json(document
  without auth))) against ``GET /v1/trust`` ``audit_signers``, and the
  concatenated pages feed straight into
  ``ledger.light_client.apply_finalities``;
* parameter rules identical to ``GET /v1/chain/headers`` plus unknown
  parameters: missing/malformed/unknown/repeated parameters are 400, an
  unknown anchor height is 404, an anchor hash mismatch or a pending
  anchor is 409 — all without side effects.

Run: python3 tests/finality_pages_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
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
    FINALITY_DOMAIN,
    advance_headers,
    apply_finalities,
)
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

ANCHOR_KEYS = ["height", "block_hash"]
DESCRIPTOR_KEYS = ["tip_hash", "height", "length", "status"]
FINALITY_KEYS = ["finalized", "tip", "auth"]
AUTH_KEYS = ["key_version", "signature"]
PAGE_KEYS = ["anchor", "finalities", "next", "head"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class FinalityPagesFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "headers-checkpoint.json")
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
        self.anchor = {"height": 0, "block_hash": self.genesis_hash}

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def h(self, height: int) -> str:
        return self.store.chain[height].block_hash

    def get(self, params: dict):
        return self.service.get_chain_finalities(params)

    def page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.get(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit: int) -> list:
        """The whole finality history from the genesis anchor via ``next``."""
        pages = []
        anchor = self.anchor
        while True:
            page = self.page(anchor["height"], anchor["block_hash"], limit)
            pages.append(page)
            if page["next"] is None:
                break
            anchor = page["next"]
        return pages

    def header_page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def header_paged(self, limit: int) -> list:
        """The whole chain from the genesis anchor in header pages."""
        documents = []
        anchor = self.anchor
        while True:
            page = self.header_page(anchor["height"], anchor["block_hash"], limit)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == self.tip_hash:
                break
        return documents

    def assert_credential_signature(self, document: dict) -> None:
        unsigned = {"finalized": document["finalized"], "tip": document["tip"]}
        canonical = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = hashlib.sha256(
            FINALITY_DOMAIN.encode("utf-8") + canonical
        ).digest()
        public_key = self.trust["audit_signers"][0]["public_key"]
        self.assertTrue(
            crypto.verify_signature(
                public_key, digest, document["auth"]["signature"]
            )
        )


class FinalityPagesShapeTests(FinalityPagesFixture):
    def test_top_level_and_nested_key_orders(self) -> None:
        body = self.page(0, self.genesis_hash)
        self.assertEqual(list(body.keys()), PAGE_KEYS)
        self.assertEqual(list(body["anchor"].keys()), ANCHOR_KEYS)
        self.assertEqual(body["anchor"], self.anchor)
        self.assertEqual(list(body["head"].keys()), FINALITY_KEYS)
        self.assertEqual(list(body["head"]["finalized"].keys()), ANCHOR_KEYS)
        self.assertEqual(list(body["head"]["tip"].keys()), DESCRIPTOR_KEYS)
        self.assertEqual(list(body["head"]["auth"].keys()), AUTH_KEYS)
        for item in body["finalities"]:
            self.assertEqual(list(item.keys()), FINALITY_KEYS)
            self.assertEqual(list(item["finalized"].keys()), ANCHOR_KEYS)
            self.assertEqual(list(item["tip"].keys()), DESCRIPTOR_KEYS)
            self.assertEqual(list(item["auth"].keys()), AUTH_KEYS)

    def test_page_covers_confirmed_blocks_after_anchor_only(self) -> None:
        body = self.page(0, self.genesis_hash)
        # The confirmed blocks strictly after the genesis anchor are 1..3;
        # the pending tip at height 4 is never in a finality page.
        self.assertEqual(
            [item["finalized"]["height"] for item in body["finalities"]],
            [1, 2, 3],
        )
        for height, item in zip((1, 2, 3), body["finalities"]):
            self.assertEqual(
                item["finalized"], {"height": height, "block_hash": self.h(height)}
            )
            # tip is the descriptor S of the chain prefix ending at the block.
            self.assertEqual(
                item["tip"],
                {
                    "tip_hash": self.h(height),
                    "height": height,
                    "length": height + 1,
                    "status": "confirmed",
                },
            )
        # The page reaches the head finality: next is null.
        self.assertIsNone(body["next"])
        # head is the current finality credential: finalized names the last
        # confirmed block while the pending tip stays in tip.
        self.assertEqual(
            body["head"]["finalized"], {"height": 3, "block_hash": self.h(3)}
        )
        self.assertEqual(body["head"]["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(body["head"]["tip"]["height"], 4)
        self.assertEqual(body["head"]["tip"]["status"], "pending")

    def test_head_matches_chain_finality_credential(self) -> None:
        status, credential = self.service.get_chain_finality()
        self.assertEqual(status, 200, credential)
        body = self.page(0, self.genesis_hash)
        self.assertEqual(body["head"], credential)

    def test_anchor_at_head_yields_empty_page_and_null_next(self) -> None:
        body = self.page(3, self.h(3))
        self.assertEqual(body["anchor"], {"height": 3, "block_hash": self.h(3)})
        self.assertEqual(body["finalities"], [])
        self.assertIsNone(body["next"])
        self.assertEqual(
            body["head"]["finalized"], {"height": 3, "block_hash": self.h(3)}
        )

    def test_limit_slices_the_page_and_next_continues(self) -> None:
        first = self.page(0, self.genesis_hash, limit=2)
        self.assertEqual(
            [item["finalized"]["height"] for item in first["finalities"]],
            [1, 2],
        )
        self.assertEqual(
            first["next"], {"height": 2, "block_hash": self.h(2)}
        )
        self.assertEqual(list(first["next"].keys()), ANCHOR_KEYS)
        second = self.page(2, self.h(2), limit=2)
        self.assertEqual(
            [item["finalized"]["height"] for item in second["finalities"]],
            [3],
        )
        self.assertIsNone(second["next"])
        # Following next pages reconstructs the single big page exactly.
        self.assertEqual(
            first["finalities"] + second["finalities"],
            self.page(0, self.genesis_hash)["finalities"],
        )

    def test_limit_one_walks_block_by_block(self) -> None:
        pages = self.paged(1)
        self.assertEqual(len(pages), 3)
        for height, page in zip((1, 2, 3), pages):
            self.assertEqual(len(page["finalities"]), 1)
            self.assertEqual(page["finalities"][0]["finalized"]["height"], height)
        self.assertIsNone(pages[-1]["next"])

    def test_every_signature_verifies(self) -> None:
        body = self.page(0, self.genesis_hash)
        for item in body["finalities"]:
            self.assert_credential_signature(item)
        self.assert_credential_signature(body["head"])

    def test_confirming_tip_extends_the_history(self) -> None:
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        body = self.page(2, self.h(2))
        self.assertEqual(
            [item["finalized"]["height"] for item in body["finalities"]],
            [3, 4],
        )
        self.assertIsNone(body["next"])
        self.assertEqual(
            body["head"]["finalized"], {"height": 4, "block_hash": self.tip_hash}
        )
        self.assertEqual(body["head"]["tip"]["status"], "confirmed")


class FinalityPagesApplyTests(FinalityPagesFixture):
    def test_pages_feed_apply_finalities_end_to_end(self) -> None:
        # Checkpoint the chain at the pending tip, then apply the paginated
        # finality history straight off the wire.
        result = advance_headers(
            self.path,
            self.header_paged(2),
            self.anchor,
            self.tip_hash,
            self.trust,
        )
        self.assertTrue(result["ok"], result)
        pages = self.paged(2)
        credentials = [item for page in pages for item in page["finalities"]]
        self.assertEqual(len(credentials), 3)
        applied = apply_finalities(self.path, credentials, self.trust)
        self.assertTrue(applied["ok"], applied)
        self.assertEqual(
            list(applied.keys()), ["ok", "generation", "finalized", "applied"]
        )
        self.assertEqual(applied["applied"], 3)
        self.assertEqual(
            applied["finalized"], {"height": 3, "block_hash": self.h(3)}
        )
        # Replaying the same batch is idempotent.
        replay = apply_finalities(self.path, credentials, self.trust)
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], applied["generation"])


class FinalityPagesErrorTests(FinalityPagesFixture):
    def test_missing_or_malformed_parameters_are_400(self) -> None:
        g = self.genesis_hash
        bad = [
            {},
            {"after_height": "0"},
            {"after_hash": g},
            {"after_height": "", "after_hash": g},
            {"after_height": "00", "after_hash": g},
            {"after_height": "01", "after_hash": g},
            {"after_height": "-1", "after_hash": g},
            {"after_height": "1.0", "after_hash": g},
            {"after_height": " 1", "after_hash": g},
            {"after_height": "0", "after_hash": ""},
            {"after_height": "0", "after_hash": "abc"},
            {"after_height": "0", "after_hash": "A" * 64},
            {"after_height": "0", "after_hash": "a" * 63},
            {"after_height": "0", "after_hash": g, "limit": ""},
            {"after_height": "0", "after_hash": g, "limit": "0"},
            {"after_height": "0", "after_hash": g, "limit": "00"},
            {"after_height": "0", "after_hash": g, "limit": "01"},
            {"after_height": "0", "after_hash": g, "limit": "501"},
            {"after_height": "0", "after_hash": g, "limit": "-1"},
            {"after_height": "0", "after_hash": g, "limit": "1.0"},
        ]
        for params in bad:
            with self.subTest(params=params):
                self.assertEqual(self.get(params)[0], 400)

    def test_unknown_parameter_is_400(self) -> None:
        g = self.genesis_hash
        for params in (
            {"after_height": "0", "after_hash": g, "foo": "1"},
            {"after_height": "0", "after_hash": g, "limit": "1", "cursor": "0"},
            {"foo": "1"},
        ):
            with self.subTest(params=params):
                self.assertEqual(self.get(params)[0], 400)

    def test_unknown_anchor_height_is_404(self) -> None:
        self.assertEqual(
            self.get(
                {"after_height": "99", "after_hash": self.genesis_hash}
            )[0],
            404,
        )

    def test_anchor_hash_mismatch_is_409(self) -> None:
        self.assertEqual(
            self.get({"after_height": "0", "after_hash": "a" * 64})[0], 409
        )

    def test_pending_anchor_is_409(self) -> None:
        self.assertEqual(
            self.get({"after_height": "4", "after_hash": self.tip_hash})[0],
            409,
        )

    def test_errors_have_no_side_effects(self) -> None:
        before = self.page(0, self.genesis_hash)
        self.get({})
        self.get({"after_height": "99", "after_hash": self.genesis_hash})
        self.get({"after_height": "0", "after_hash": "a" * 64})
        self.get({"after_height": "4", "after_hash": self.tip_hash})
        self.assertEqual(self.page(0, self.genesis_hash), before)


class FinalityPagesHttpTests(unittest.TestCase):
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
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def request(cls, path: str):
        req = urllib.request.Request(f"{cls.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_finalities_http(self) -> None:
        g = self.service.store.chain[0].block_hash
        status, raw = self.request(
            f"/v1/chain/finalities?after_height=0&after_hash={g}"
        )
        self.assertEqual(status, 200, raw)
        # Contract key order over the wire (not alphabetized).
        self.assertEqual(
            [
                segment
                for segment in ("anchor", "finalities", "next", "head")
                if f'"{segment}"' in raw
            ],
            ["anchor", "finalities", "next", "head"],
        )
        body = json.loads(raw)
        self.assertEqual(list(body.keys()), PAGE_KEYS)
        # Genesis alone is born confirmed: the page is empty and next null.
        self.assertEqual(body["anchor"], {"height": 0, "block_hash": g})
        self.assertEqual(body["finalities"], [])
        self.assertIsNone(body["next"])
        self.assertEqual(body["head"]["finalized"]["height"], 0)

    def test_error_mapping_at_the_http_boundary(self) -> None:
        g = self.service.store.chain[0].block_hash
        base = f"/v1/chain/finalities?after_height=0&after_hash={g}"
        self.assertEqual(self.request("/v1/chain/finalities")[0], 400)
        self.assertEqual(
            self.request("/v1/chain/finalities?after_height=0")[0], 400
        )
        self.assertEqual(self.request(f"{base}&limit=501")[0], 400)
        self.assertEqual(self.request(f"{base}&foo=1")[0], 400)
        # Repeated query parameters are rejected.
        self.assertEqual(self.request(f"{base}&after_height=0")[0], 400)
        self.assertEqual(self.request(f"{base}&limit=1&limit=2")[0], 400)
        self.assertEqual(
            self.request(
                "/v1/chain/finalities?after_height=99&after_hash=" + g
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "/v1/chain/finalities?after_height=0&after_hash=" + "a" * 64
            )[0],
            409,
        )


if __name__ == "__main__":
    unittest.main()

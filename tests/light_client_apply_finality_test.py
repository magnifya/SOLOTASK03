"""Tests for the signed finality credential ``GET /v1/chain/finality`` and
its durable light-client application
``ledger.light_client.apply_finality``.

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` and covers:

* the service/HTTP credential: 200 key order
  ``finalized, tip, auth`` (``finalized`` key order
  ``height, block_hash`` naming the last confirmed block while a pending
  tip stays in ``tip``; ``auth`` key order ``key_version, signature``);
  any query parameter is 400; the signature verifies as
  Ed25519(SHA256(UTF8("ledger-finality-v1") || canonical_json(document
  without auth))) against ``GET /v1/trust`` ``audit_signers``;
* ``apply_finality(path, document, trust)`` success key order
  ``ok, generation, finalized``: same target is idempotent with
  byte-identical files and no generation bump, raising the boundary bumps
  generation once and atomically rewrites the version-3 checkpoint;
* failure categories: structure/type defects ``input``, unknown key
  version or bad signature ``auth`` (old versions stay verifiable after
  signer rotation), tip/branch/regression defects ``integrity``,
  checkpoint parse/key-order/digest/replay defects ``state`` and missing
  or unwritable files ``io``; failures never change the file bytes and
  nothing is raised.

Run: python3 tests/light_client_apply_finality_test.py
"""
from __future__ import annotations

import copy
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
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_IO,
    ERR_STATE,
    FINALITY_DOMAIN,
    advance_headers,
    apply_finality,
    sign_finality,
)
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

CHECKPOINT_KEYS = [
    "v",
    "generation",
    "anchor",
    "tip",
    "finalized",
    "steps",
    "hash",
]
ANCHOR_KEYS = ["height", "block_hash"]
DESCRIPTOR_KEYS = ["tip_hash", "height", "length", "status"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class FinalityFixture(unittest.TestCase):
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

    def loc(self, height: int, block_hash: str | None = None) -> dict:
        if block_hash is None:
            block_hash = self.h(height)
        return {"height": height, "block_hash": block_hash}

    def page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit: int) -> list:
        """The whole chain from the genesis anchor in ``limit``-sized pages."""
        documents = []
        anchor = self.anchor
        tip_hash = self.store.tip_hash()
        while True:
            page = self.page(anchor["height"], anchor["block_hash"], limit)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == tip_hash:
                break
        return documents

    def credential(self) -> dict:
        status, body = self.service.get_chain_finality()
        self.assertEqual(status, 200, body)
        return body

    def re_sign(self, document: dict, version: int | None = None) -> dict:
        """Re-sign a tampered credential with the current audit signer so the
        signature stays valid and only integrity is at stake."""
        signer = self.store.audit_signer
        envelope = sign_finality(
            signer["private_key"],
            signer["version"] if version is None else version,
            document["finalized"],
            document["tip"],
        )
        self.assertIsNotNone(envelope)
        document["auth"] = envelope
        return document

    def checkpoint_to_pending_tip(self) -> None:
        """Advance once: a checkpoint at pending tip height 4, generation 1."""
        result = advance_headers(
            self.path,
            self.paged(2),
            self.anchor,
            self.tip_hash,
            self.trust,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)

    def apply(self, document, trust=None):
        return apply_finality(
            self.path, document, self.trust if trust is None else trust
        )

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def read_checkpoint(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def write_file(self, data) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            if isinstance(data, str):
                fh.write(data)
            else:
                json.dump(data, fh)

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class FinalityCredentialServiceTests(FinalityFixture):
    def test_credential_shape_and_key_orders(self) -> None:
        doc = self.credential()
        self.assertEqual(list(doc.keys()), ["finalized", "tip", "auth"])
        self.assertEqual(list(doc["finalized"].keys()), ANCHOR_KEYS)
        self.assertEqual(list(doc["tip"].keys()), DESCRIPTOR_KEYS)
        self.assertEqual(list(doc["auth"].keys()), ["key_version", "signature"])
        # The last confirmed block is height 3; the pending tip at 4 is S.
        self.assertEqual(
            doc["finalized"], {"height": 3, "block_hash": self.h(3)}
        )
        self.assertEqual(doc["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(doc["tip"]["height"], 4)
        self.assertEqual(doc["tip"]["length"], 5)
        self.assertEqual(doc["tip"]["status"], "pending")
        self.assertEqual(doc["auth"]["key_version"], 1)
        self.assertTrue(crypto.is_hex128(doc["auth"]["signature"]))

    def test_finalized_equals_tip_when_tip_confirmed(self) -> None:
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        doc = self.credential()
        self.assertEqual(
            doc["finalized"], {"height": 4, "block_hash": self.tip_hash}
        )
        self.assertEqual(doc["tip"]["status"], "confirmed")
        self.assertEqual(doc["finalized"]["block_hash"], doc["tip"]["tip_hash"])

    def test_signature_covers_domain_prefixed_canonical_json(self) -> None:
        doc = self.credential()
        unsigned = {"finalized": doc["finalized"], "tip": doc["tip"]}
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
                public_key, digest, doc["auth"]["signature"]
            )
        )
        # The signature is bound to the finality domain: headers-domain
        # verification must fail.
        headers_bytes = b"ledger-headers-v1" + canonical
        self.assertFalse(
            crypto.verify_signature(
                public_key,
                hashlib.sha256(headers_bytes).digest(),
                doc["auth"]["signature"],
            )
        )

    def test_tip_matches_chain_headers_tip(self) -> None:
        page = self.page(0, self.genesis_hash)
        doc = self.credential()
        self.assertEqual(doc["tip"], page["tip"])


class FinalityCredentialHttpTests(unittest.TestCase):
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

    def test_finality_http(self) -> None:
        status, raw = self.request("/v1/chain/finality")
        self.assertEqual(status, 200, raw)
        # Contract key order over the wire (not alphabetized).
        self.assertEqual(
            [
                segment
                for segment in ("finalized", "tip", "auth")
                if f'"{segment}"' in raw
            ],
            ["finalized", "tip", "auth"],
        )
        body = json.loads(raw)
        self.assertEqual(list(body.keys()), ["finalized", "tip", "auth"])
        # Genesis alone is born confirmed: finalized names the genesis block.
        self.assertEqual(body["finalized"]["height"], 0)
        self.assertEqual(body["tip"]["height"], 0)

    def test_any_query_parameter_is_400(self) -> None:
        self.assertEqual(self.request("/v1/chain/finality?")[0], 200)
        for path in (
            "/v1/chain/finality?x=1",
            "/v1/chain/finality?limit=1",
            "/v1/chain/finality?a=b&c=d",
            "/v1/chain/finality?blank=",
            "/v1/chain/finality?x=1&x=2",
        ):
            self.assertEqual(self.request(path)[0], 400, path)


class ApplyFinalitySuccessTests(FinalityFixture):
    def test_apply_confirmed_boundary_writes_v3(self) -> None:
        self.checkpoint_to_pending_tip()
        result = self.apply(self.credential())
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), ["ok", "generation", "finalized"])
        self.assertEqual(result["generation"], 2)
        self.assertEqual(
            result["finalized"], {"height": 3, "block_hash": self.h(3)}
        )
        self.assertEqual(list(result["finalized"].keys()), ANCHOR_KEYS)

        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        data = json.loads(raw)
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 2)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(
            data["finalized"], {"height": 3, "block_hash": self.h(3)}
        )
        self.assertEqual(data["tip"]["tip_hash"], self.tip_hash)
        body = {key: value for key, value in data.items() if key != "hash"}
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)

    def test_same_target_is_idempotent_byte_identical(self) -> None:
        self.checkpoint_to_pending_tip()
        first = self.apply(self.credential())
        self.assertEqual(first["generation"], 2)
        before = self.read_raw()
        repeat = self.apply(self.credential())
        self.assertTrue(repeat["ok"], repeat)
        self.assertEqual(repeat["generation"], 2)
        self.assertEqual(repeat["finalized"], first["finalized"])
        self.assertEqual(self.read_raw(), before)

    def test_anchor_boundary_on_fresh_checkpoint_is_idempotent(self) -> None:
        self.checkpoint_to_pending_tip()
        doc = self.credential()
        doc["finalized"] = {"height": 0, "block_hash": self.genesis_hash}
        self.re_sign(doc)
        before = self.read_raw()
        result = self.apply(doc)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["finalized"], self.anchor)
        self.assertEqual(self.read_raw(), before)

    def test_raising_boundary_repeatedly_bumps_generation(self) -> None:
        self.checkpoint_to_pending_tip()
        for height in (1, 2, 3):
            doc = self.credential()
            doc["finalized"] = {"height": height, "block_hash": self.h(height)}
            self.re_sign(doc)
            result = self.apply(doc)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["generation"], height + 1)
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 4)
        self.assertEqual(
            data["finalized"], {"height": 3, "block_hash": self.h(3)}
        )

    def test_apply_after_confirming_tip_finalizes_the_tip(self) -> None:
        self.checkpoint_to_pending_tip()
        self.assertEqual(self.apply(self.credential())["generation"], 2)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        advanced = advance_headers(
            self.path, [empty], None, self.tip_hash, self.trust
        )
        self.assertEqual(advanced["generation"], 3)
        result = self.apply(self.credential())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 4)
        self.assertEqual(
            result["finalized"], {"height": 4, "block_hash": self.tip_hash}
        )


class ApplyFinalityInputTests(FinalityFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_path_must_be_a_non_empty_string(self) -> None:
        doc = self.credential()
        for bad_path in ("", None, 7, object()):
            with self.subTest(bad_path=bad_path):
                self.assert_error(apply_finality(bad_path, doc, self.trust), ERR_INPUT)

    def test_document_must_be_an_object_with_exact_key_order(self) -> None:
        for bad_document in (None, 7, "x", [], self.credential()):
            if isinstance(bad_document, dict) and bad_document:
                # The genuine document is valid, not an input error.
                continue
            with self.subTest(bad_document=bad_document):
                self.assert_error(self.apply(bad_document), ERR_INPUT)
        reordered = {"tip": None, "finalized": None, "auth": None}
        self.assert_error(self.apply(reordered), ERR_INPUT)
        genuine = self.credential()
        for extra in ("extra",):
            tampered = dict(genuine)
            tampered[extra] = 1
            self.assert_error(self.apply(tampered), ERR_INPUT)

    def test_finalized_field_shape(self) -> None:
        doc = self.credential()
        bad_doc = copy.deepcopy(doc)
        bad_doc["finalized"] = {"block_hash": self.h(3), "height": 3}
        self.assert_error(self.apply(bad_doc), ERR_INPUT)
        for height in (None, "3", True, False, -1, 3.0, [3]):
            tampered = copy.deepcopy(doc)
            tampered["finalized"] = {"height": height, "block_hash": self.h(3)}
            self.assert_error(self.apply(tampered), ERR_INPUT)
        for bad_hash in (None, 3, "zz", "A" * 64, "a" * 63, "a" * 65, True):
            tampered = copy.deepcopy(doc)
            tampered["finalized"] = {"height": 3, "block_hash": bad_hash}
            self.assert_error(self.apply(tampered), ERR_INPUT)

    def test_tip_field_shape(self) -> None:
        doc = self.credential()
        bad_order = copy.deepcopy(doc)
        bad_order["tip"] = {
            "height": doc["tip"]["height"],
            "tip_hash": doc["tip"]["tip_hash"],
            "length": doc["tip"]["length"],
            "status": doc["tip"]["status"],
        }
        self.assert_error(self.apply(bad_order), ERR_INPUT)
        tampered = copy.deepcopy(doc)
        tampered["tip"] = dict(doc["tip"], status="weird")
        self.re_sign(tampered)
        self.assert_error(self.apply(tampered), ERR_INPUT)
        for field, value in (
            ("tip_hash", 3),
            ("height", True),
            ("length", 0),
            ("status", 5),
        ):
            broken = copy.deepcopy(doc)
            broken["tip"] = dict(doc["tip"], **{field: value})
            self.assert_error(self.apply(broken), ERR_INPUT)

    def test_auth_field_shape(self) -> None:
        doc = self.credential()
        for version in (None, "1", True, False, 0, -1, 1.0):
            tampered = copy.deepcopy(doc)
            tampered["auth"] = {
                "key_version": version,
                "signature": doc["auth"]["signature"],
            }
            self.assert_error(self.apply(tampered), ERR_INPUT)
        for signature in (None, 3, "abc", "A" * 128, "a" * 127, "a" * 129):
            tampered = copy.deepcopy(doc)
            tampered["auth"] = {
                "key_version": 1,
                "signature": signature,
            }
            self.assert_error(self.apply(tampered), ERR_INPUT)
        self.assert_error(
            self.apply({"finalized": doc["finalized"], "tip": doc["tip"]}),
            ERR_INPUT,
        )

    def test_trust_must_carry_audit_signers(self) -> None:
        doc = self.credential()
        for bad_trust in (None, 7, [], {}, {"audit_signers": []}, {"audit_signers": None}):
            with self.subTest(bad_trust=bad_trust):
                self.assert_error(
                    apply_finality(self.path, doc, bad_trust), ERR_INPUT
                )

    def test_never_raises_on_garbage(self) -> None:
        self.assert_error(
            apply_finality(object(), object(), object()), ERR_INPUT
        )


class ApplyFinalityAuthTests(FinalityFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_unknown_key_version_is_auth(self) -> None:
        doc = self.credential()
        doc["auth"]["key_version"] = 99
        self.assert_error(self.apply(doc), ERR_AUTH)

    def test_bad_signature_is_auth(self) -> None:
        doc = self.credential()
        signature = doc["auth"]["signature"]
        doc["auth"]["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        self.assert_error(self.apply(doc), ERR_AUTH)

    def test_signature_over_modified_body_is_auth(self) -> None:
        doc = self.credential()
        doc["finalized"] = {"height": 2, "block_hash": self.h(2)}
        # Re-signing is deliberately omitted: the stale signature fails.
        self.assert_error(self.apply(doc), ERR_AUTH)

    def test_old_version_credential_still_applies_after_rotation(self) -> None:
        old = self.credential()
        self.assertEqual(old["auth"]["key_version"], 1)
        seed = crypto.generate_private_key()
        new_pub = crypto.derive_public_key(seed)
        status, _ = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        rotated_trust = self.service.get_trust_document()[1]
        self.assertEqual(len(rotated_trust["audit_signers"]), 2)
        # A fresh credential is signed by version 2.
        new = self.credential()
        self.assertEqual(new["auth"]["key_version"], 2)
        self.assertEqual(
            rotated_trust["audit_signers"][1]["public_key"], new_pub
        )
        # The version-1 credential still authenticates via signer history
        # and raises the boundary once (generation 1 -> 2).
        result = self.apply(old, rotated_trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        before = self.read_raw()
        # Replaying the same boundary with the v2 credential is idempotent.
        repeat = self.apply(new, rotated_trust)
        self.assertEqual(repeat["generation"], 2)
        self.assertEqual(self.read_raw(), before)


class ApplyFinalityIntegrityTests(FinalityFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_tip_must_equal_replayed_tip(self) -> None:
        doc = self.credential()
        doc["tip"] = dict(doc["tip"], length=99)
        self.re_sign(doc)
        before = self.read_raw()
        self.assert_error(self.apply(doc), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_stale_pending_tip_after_confirmation_is_integrity(self) -> None:
        stale = self.credential()
        self.assertEqual(self.apply(stale)["generation"], 2)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        # The checkpoint is advanced to the confirmed tip; the old
        # credential still describes the pending descriptor.
        empty = self.page(4, self.tip_hash)
        self.assertEqual(
            advance_headers(self.path, [empty], None, self.tip_hash, self.trust)[
                "generation"
            ],
            3,
        )
        before = self.read_raw()
        self.assert_error(self.apply(stale), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_pending_header_cannot_be_finalized(self) -> None:
        doc = self.credential()
        doc["finalized"] = {"height": 4, "block_hash": self.tip_hash}
        self.re_sign(doc)
        before = self.read_raw()
        self.assert_error(self.apply(doc), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_unknown_hash_at_known_height_is_integrity(self) -> None:
        doc = self.credential()
        doc["finalized"] = {"height": 2, "block_hash": "f" * 64}
        self.re_sign(doc)
        self.assert_error(self.apply(doc), ERR_INTEGRITY)

    def test_height_past_tip_is_integrity(self) -> None:
        doc = self.credential()
        for height in (5, 99):
            doc["finalized"] = {"height": height, "block_hash": "a" * 64}
            self.re_sign(doc)
            self.assert_error(self.apply(doc), ERR_INTEGRITY)

    def test_boundary_cannot_move_backwards_or_sideways(self) -> None:
        first = self.apply(self.credential())
        self.assertEqual(first["generation"], 2)
        before = self.read_raw()
        lower = self.credential()
        lower["finalized"] = {"height": 1, "block_hash": self.h(1)}
        self.re_sign(lower)
        self.assert_error(self.apply(lower), ERR_INTEGRITY)
        genesis = self.credential()
        genesis["finalized"] = {"height": 0, "block_hash": self.genesis_hash}
        self.re_sign(genesis)
        self.assert_error(self.apply(genesis), ERR_INTEGRITY)
        sideways = self.credential()
        sideways["finalized"] = {"height": 3, "block_hash": "f" * 64}
        self.re_sign(sideways)
        self.assert_error(self.apply(sideways), ERR_INTEGRITY)
        # Every failed attempt leaves bytes and generation untouched.
        self.assertEqual(self.read_raw(), before)
        self.assertEqual(self.read_checkpoint()["generation"], 2)

    def test_failed_apply_never_bumps_generation(self) -> None:
        before = self.read_raw()
        bad = self.credential()
        bad["finalized"] = {"height": 4, "block_hash": self.tip_hash}
        self.re_sign(bad)
        self.assert_error(self.apply(bad), ERR_INTEGRITY)
        self.assert_error(self.apply(bad), ERR_INTEGRITY)
        # The next valid application still lands at generation 2.
        result = self.apply(self.credential())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertNotEqual(self.read_raw(), before)


class ApplyFinalityStateTests(FinalityFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_corrupt_json_is_state(self) -> None:
        self.write_file("{not json")
        self.assert_error(self.apply(self.credential()), ERR_STATE)

    def test_tampered_hash_is_state(self) -> None:
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        self.write_file(data)
        self.assert_error(self.apply(self.credential()), ERR_STATE)

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        payload = json.dumps(data)
        self.write_file(payload)
        self.assert_error(self.apply(self.credential()), ERR_STATE)
        self.assertEqual(self.read_raw().decode("utf-8"), payload)

    def test_corrupt_state_wins_over_auth_and_integrity(self) -> None:
        # Persisted state is settled before the credential is judged: a
        # forged/unverifiable credential against a corrupt checkpoint is
        # still ``state``, never ``auth`` or ``integrity``.
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        self.write_file(data)
        forged = self.credential()
        forged["auth"]["key_version"] = 99
        self.assert_error(self.apply(forged), ERR_STATE)
        tampered = self.credential()
        signature = tampered["auth"]["signature"]
        tampered["auth"]["signature"] = (
            ("0" if signature[0] != "0" else "1") + signature[1:]
        )
        self.assert_error(self.apply(tampered), ERR_STATE)


class ApplyFinalityIoTests(FinalityFixture):
    def test_missing_file_is_io(self) -> None:
        doc = LedgerService(self.store).get_chain_finality()[1]
        self.assert_error(
            apply_finality(self.path, doc, self.trust), ERR_IO
        )

    def test_missing_file_wins_over_auth(self) -> None:
        # A forged credential against a not-yet-created checkpoint is io.
        forged = LedgerService(self.store).get_chain_finality()[1]
        forged["auth"]["key_version"] = 99
        self.assert_error(
            apply_finality(self.path, forged, self.trust), ERR_IO
        )

    def test_unwritable_target_path_is_io(self) -> None:
        self.checkpoint_to_pending_tip()
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        self.assert_error(
            apply_finality(directory, self.credential(), self.trust), ERR_IO
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

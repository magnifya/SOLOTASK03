"""Strict raw-type validation of block/transaction documents across entries.

A string, float or boolean must never be coerced into a plausible integer and
accepted as a valid chain document: every block ``height`` must be a
non-boolean non-negative integer equal to its array position and every
transaction ``amount`` a non-boolean positive integer, checked on the raw JSON
value BEFORE the canonical message, tx_id, signature, Merkle root, prev_hash
and block_hash are recomputed.

Covers:
- POST /v1/forks/candidates: disguised height/amount -> 400, no fork, no
  audit event, no generation advance (service and HTTP surface).
- POST /v1/forks/sync: same 400 rules; a malformed document under an already
  used idempotency key must not replay the cached 200.
- Offline ``verify_bundle``: the same defects -> {"ok": False, "error":
  "input"}; valid integer documents keep verifying.
- Startup recovery: wrong types in the canonical chain or the pending set
  raise StateRecoveryError (with path and reason); wrong types confined to
  persisted candidates or sync records are silently discarded per the cache
  rules while the valid canonical chain still loads; legacy snapshots without
  a ``status`` field keep defaulting to confirmed.

Run: python3 tests/strict_type_validation_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import bundle_signing_digest, verify_bundle
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

NOW = 1_000_000_000
FUTURE = NOW + 10_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(msg).hex(),
    }


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(signed_tx(key, sender, to, amount))


class ServiceFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def valid_blocks(self, amount: int = 10) -> list[dict]:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, amount)]
        )
        return [self.genesis.to_dict(), block.to_dict()]

    def state_fingerprint(self) -> tuple:
        return (
            dict(self.store.forks),
            dict(self.store.syncs),
            self.store.generation,
            len(self.store.audit_events),
        )

    def assert_untouched(self, before: tuple) -> None:
        self.assertEqual(self.store.forks, before[0])
        self.assertEqual(self.store.syncs, before[1])
        self.assertEqual(self.store.generation, before[2])
        self.assertEqual(len(self.store.audit_events), before[3])


class CandidateStrictTypeTests(ServiceFixture):
    """POST /v1/forks/candidates: disguised numeric types are 400."""

    def submit(self, blocks: list[dict]):
        return self.svc.submit_fork_candidate({"blocks": blocks})

    def test_height_disguises_rejected(self) -> None:
        for bad_height in ("1", 1.0, True):
            blocks = self.valid_blocks()
            blocks[1]["height"] = bad_height
            before = self.state_fingerprint()
            status, body = self.submit(blocks)
            self.assertEqual(status, 400, (bad_height, body))
            self.assert_untouched(before)

    def test_amount_disguises_rejected(self) -> None:
        # Each disguised amount carries a signature that WOULD verify against
        # the coerced integer, so only raw-type checking can reject it.
        for bad_amount, signed_amount in (("10", 10), (10.0, 10), (True, 1)):
            blocks = self.valid_blocks(amount=signed_amount)
            blocks[1]["transactions"][0]["amount"] = bad_amount
            before = self.state_fingerprint()
            status, body = self.submit(blocks)
            self.assertEqual(status, 400, (bad_amount, body))
            self.assert_untouched(before)

    def test_non_positive_amounts_rejected(self) -> None:
        for bad_amount in (0, -5):
            blocks = self.valid_blocks()
            blocks[1]["transactions"][0]["amount"] = bad_amount
            before = self.state_fingerprint()
            status, body = self.submit(blocks)
            self.assertEqual(status, 400, (bad_amount, body))
            self.assert_untouched(before)

    def test_valid_integer_document_still_accepted(self) -> None:
        status, body = self.submit(self.valid_blocks())
        self.assertEqual(status, 201, body)
        self.assertEqual(body["height"], 1)
        self.assertEqual(body["length"], 2)


class SyncStrictTypeTests(ServiceFixture):
    """POST /v1/forks/sync: 400 for disguised types, no idempotent replay."""

    SOURCE = "node-2"

    def setUp(self) -> None:
        super().setUp()
        status, body = self.svc.register_trust_source(
            {
                "source": self.SOURCE,
                "public_key": "ab" * 32,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        self.assertIn(status, (200, 201), body)

    def sync(self, request_id: str, blocks: list[dict]):
        return self.svc.submit_fork_sync(
            {
                "source": self.SOURCE,
                "request_id": request_id,
                "expires_at": int(time.time()) + 3600,
                "candidate": {"blocks": blocks},
            }
        )

    def test_malformed_candidate_400_and_unrecorded(self) -> None:
        blocks = self.valid_blocks()
        blocks[1]["transactions"][0]["amount"] = "10"
        before = self.state_fingerprint()
        status, body = self.sync("req-bad-1", blocks)
        self.assertEqual(status, 400, body)
        self.assert_untouched(before)
        # No sync lifecycle event was written either.
        self.assertFalse(
            any(
                event.get("request_id") == "req-bad-1"
                for event in self.store.audit_events
            )
        )

    def test_malformed_height_400(self) -> None:
        blocks = self.valid_blocks()
        blocks[1]["height"] = 1.0
        before = self.state_fingerprint()
        status, body = self.sync("req-bad-2", blocks)
        self.assertEqual(status, 400, body)
        self.assert_untouched(before)

    def test_same_key_malformed_document_does_not_replay_200(self) -> None:
        status, body = self.sync("req-ok", self.valid_blocks())
        self.assertEqual(status, 201, body)
        # Identical content replays the original result as 200.
        status, replay = self.sync("req-ok", self.valid_blocks())
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay["tip_hash"], body["tip_hash"])
        # A malformed document under the same key is 400, never a 200 replay.
        malformed = self.valid_blocks()
        malformed[1]["transactions"][0]["amount"] = "10"
        before = self.state_fingerprint()
        status, _ = self.sync("req-ok", malformed)
        self.assertEqual(status, 400)
        self.assert_untouched(before)
        # The recorded result is still intact and keeps replaying.
        status, replay = self.sync("req-ok", self.valid_blocks())
        self.assertEqual(status, 200, replay)


class LightClientStrictTypeTests(unittest.TestCase):
    """Offline verify: disguised types are {"ok": false, "error": "input"}."""

    def setUp(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        source_pub = self.source_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.alice_key, self.alice_pub = keypair()
        _, self.bob = keypair()
        self.genesis = LedgerStore.create_genesis()
        self.trust = {
            "genesis_hash": self.genesis.block_hash,
            "sources": {
                "node-a": {"public_key": source_pub, "expires_at": FUTURE}
            },
            "allowlist": {},
        }

    def bundle(self, amount: int = 100) -> dict:
        tx = tx_obj(self.alice_key, self.alice_pub, self.bob, amount)
        block = Block.create(1, self.genesis.block_hash, [tx])
        bundle = {
            "source": "node-a",
            "expires_at": FUTURE,
            "response": {
                "tip_hash": block.block_hash,
                "height": 1,
                "length": 2,
                "status": "confirmed",
            },
            "candidate": [self.genesis.to_dict(), block.to_dict()],
            "proofs": [],
        }
        bundle["signature"] = self.source_key.sign(
            bundle_signing_digest(bundle)
        ).hex()
        return bundle

    def resign(self, bundle: dict) -> None:
        bundle.pop("signature", None)
        bundle["signature"] = self.source_key.sign(
            bundle_signing_digest(bundle)
        ).hex()

    def assert_input(self, bundle: dict) -> None:
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": "input"},
        )

    def test_valid_bundle_ok(self) -> None:
        result = verify_bundle(self.bundle(), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)

    def test_height_type_defects_are_input(self) -> None:
        for bad_height in ("1", 1.0, True, -1):
            bundle = self.bundle()
            bundle["candidate"][1]["height"] = bad_height
            self.assert_input(bundle)

    def test_amount_type_defects_are_input(self) -> None:
        for bad_amount, signed in (("100", 100), (100.0, 100), (True, 1), (0, 100), (-3, 100)):
            bundle = self.bundle(amount=signed)
            bundle["candidate"][1]["transactions"][0]["amount"] = bad_amount
            self.assert_input(bundle)


class RecoveryStrictTypeTests(ServiceFixture):
    """Startup recovery: canonical/pending type errors raise; cached
    candidates and sync records with type errors are discarded."""

    def rewrite_state(self, mutate) -> None:
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        mutate(doc)
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)

    def extend_canonical(self) -> Block:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        self.store.chain.append(block)
        self.store.rebuild_derived()
        self.store.save()
        return block

    def test_canonical_string_height_raises(self) -> None:
        self.extend_canonical()
        self.rewrite_state(lambda doc: doc["chain"][1].__setitem__("height", "1"))
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertTrue(ctx.exception.path)
        self.assertTrue(ctx.exception.reason)

    def test_canonical_bool_amount_raises(self) -> None:
        self.extend_canonical()
        self.rewrite_state(
            lambda doc: doc["chain"][1]["transactions"][0].__setitem__("amount", True)
        )
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertTrue(ctx.exception.path)
        self.assertTrue(ctx.exception.reason)

    def test_pending_float_amount_raises(self) -> None:
        status, _ = self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, 10))
        self.assertEqual(status, 202)
        self.rewrite_state(
            lambda doc: doc["pending"][0].__setitem__("amount", 10.5)
        )
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertTrue(ctx.exception.path)
        self.assertTrue(ctx.exception.reason)

    def test_persisted_candidate_bad_types_dropped(self) -> None:
        status, body = self.svc.submit_fork_candidate(
            {"blocks": self.valid_blocks()}
        )
        self.assertEqual(status, 201, body)

        def corrupt(doc: dict) -> None:
            doc["forks"][0][1]["height"] = "1"

        self.rewrite_state(corrupt)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(reopened.forks, {})
        # The valid canonical chain is unaffected.
        self.assertEqual(reopened.tip_hash(), self.genesis.block_hash)

    def test_persisted_sync_record_bad_types_dropped(self) -> None:
        status, body = self.svc.register_trust_source(
            {
                "source": "node-2",
                "public_key": "cd" * 32,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        self.assertIn(status, (200, 201), body)
        status, body = self.svc.submit_fork_sync(
            {
                "source": "node-2",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "candidate": {"blocks": self.valid_blocks()},
            }
        )
        self.assertEqual(status, 201, body)

        def corrupt(doc: dict) -> None:
            doc["forks"][0][1]["transactions"][0]["amount"] = "10"

        self.rewrite_state(corrupt)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        # The invalid fork and the sync record pointing at it are discarded;
        # the canonical chain and its audit history survive.
        self.assertEqual(reopened.forks, {})
        self.assertEqual(reopened.syncs, {})
        self.assertEqual(reopened.tip_hash(), self.genesis.block_hash)

    def test_legacy_missing_status_still_defaults_confirmed(self) -> None:
        self.extend_canonical()

        def strip_status(doc: dict) -> None:
            for block in doc["chain"]:
                block.pop("status", None)

        self.rewrite_state(strip_status)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(len(reopened.chain), 2)
        self.assertTrue(all(b.status == "confirmed" for b in reopened.chain))


class HttpStrictTypeTests(unittest.TestCase):
    """The POST endpoints surface the same 400 rejections over HTTP."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.genesis = cls.service.store.chain[0]
        cls.ka, cls.A = keypair()
        _, cls.B = keypair()
        status, _ = cls.service.register_trust_source(
            {
                "source": "node-2",
                "public_key": "ef" * 32,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        assert status in (200, 201), status

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, method: str, path: str, payload=None):
        url = f"{cls.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    @classmethod
    def valid_blocks(cls) -> list[dict]:
        block = Block.create(
            1, cls.genesis.block_hash, [tx_obj(cls.ka, cls.A, cls.B, 10)]
        )
        return [cls.genesis.to_dict(), block.to_dict()]

    def test_candidates_string_amount_400_over_http(self) -> None:
        blocks = self.valid_blocks()
        blocks[1]["transactions"][0]["amount"] = "10"
        status, body = self.request("POST", "/v1/forks/candidates", {"blocks": blocks})
        self.assertEqual(status, 400, body)
        # Nothing was stored.
        status, chain = self.request("GET", "/v1/chain")
        self.assertEqual(status, 200)
        self.assertEqual(chain["candidates"], [])

    def test_sync_bool_height_400_over_http(self) -> None:
        blocks = self.valid_blocks()
        blocks[1]["height"] = True
        status, body = self.request(
            "POST",
            "/v1/forks/sync",
            {
                "source": "node-2",
                "request_id": "req-http-1",
                "expires_at": int(time.time()) + 3600,
                "candidate": {"blocks": blocks},
            },
        )
        self.assertEqual(status, 400, body)
        status, listing = self.request("GET", "/v1/forks/sync?source=node-2")
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

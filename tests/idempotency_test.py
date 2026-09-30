"""Tests for the unified Idempotency-Key protection on state-changing routes.

Covers every requirement of the request-idempotency feature:

* an Idempotency-Key is 1..128 visible ASCII characters; absent, behavior is
  byte-for-byte the legacy one (CLI included);
* a first success keeps its ORIGINAL status (200/201/202 are not normalized),
  body and JSON key order, and answers ``Idempotency-Key`` echo plus
  ``Idempotency-Replayed: false``;
* a same-key/same-(method,target,normalized-body) retry does not re-execute,
  appends no audit event and returns the cached status/JSON with
  ``Idempotency-Replayed: true`` — JSON key order and whitespace do not matter;
* the same key with a different method, target or body is 409
  ``{"error": "idempotency key conflict"}`` with no success/replay headers;
* 4xx (and 401/403/404) failures never occupy the key;
* read-only POSTs and GETs ignore the header entirely (no record, no headers);
* the record and the mutation share one atomic snapshot, survive a restart,
  and concurrent same-key submissions produce exactly one first execution;
* a persistence failure answers 500 ``{"error": "persistence failed"}`` and
  leaves neither the change, an audit event nor the key behind;
* recovery rejects a snapshot whose idempotency section is structurally
  corrupt, duplicates a fingerprint or caches invalid JSON;
* genuinely business-idempotent successes under a second, fingerprint-equal
  key do not install a fingerprint-duplicate record and still recover.

Run: python3 tests/idempotency_test.py
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

KEY_A = "a" * 64
FUTURE = 2_000_000_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def make_block(genesis: Block, key, sender, recipient, amount, *, height=1, status="confirmed"):
    return Block.create(
        height,
        genesis.block_hash,
        [Transaction.from_dict(signed_tx(key, sender, recipient, amount))],
        status,
    )


def make_fork(blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class HttpFixture:
    """Start an in-process HTTP server over a fresh persisted service."""

    def setUp(self, *, history_config=None) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self._start(history_config)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def _start(self, history_config) -> None:
        self.store = LedgerStore(
            self.state_path,
            history_path=history_config[0] if history_config else None,
            history_trust_path=history_config[1] if history_config else None,
        )
        self.service = LedgerService(
            self.store,
            initial_balance=1000,
            history_config=history_config,
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.service))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def restart(self, *, history_config=None) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._start(history_config)

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def raw_request(
        self,
        method: str,
        target: str,
        body=None,
        *,
        key=None,
        raw_body=None,
        headers=None,
    ):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        data = None
        if raw_body is not None:
            data = raw_body.encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if key is not None:
            hdrs["Idempotency-Key"] = key
        conn.request(method, target, body=data, headers=hdrs)
        response = conn.getresponse()
        raw = response.read()
        result_headers = {name: value for name, value in response.getheaders()}
        conn.close()
        payload = json.loads(raw.decode("utf-8")) if raw else None
        return response.status, payload, result_headers, raw

    def request(self, method, target, body=None, *, key=None):
        status, payload, headers, _ = self.raw_request(
            method, target, body, key=key
        )
        return status, payload, headers

    def submit(self, amount=100, *, key=None, keyobj=None, sender=None, to=None):
        k = keyobj or self.ka
        return self.request(
            "POST",
            "/v1/transactions",
            signed_tx(k, sender or self.A, to or self.B, amount),
            key=key,
        )

    def mine(self, *, key=None):
        return self.request("POST", "/v1/blocks", key=key)

    def confirm(self, height, *, key=None):
        return self.request("POST", f"/v1/blocks/{height}/confirm", key=key)

    def rollback(self, height, *, key=None):
        return self.request("POST", f"/v1/blocks/{height}/rollback", key=key)


class IdempotencyHttpTests(HttpFixture, unittest.TestCase):
    def test_first_success_preserves_status_and_headers(self) -> None:
        # 202 transaction keeps 202 (not rewritten) with first-exec headers.
        status, body, headers = self.submit(key="tx-key")
        self.assertEqual(status, 202)
        self.assertEqual(set(body), {"tx_id"})
        self.assertEqual(headers["Idempotency-Key"], "tx-key")
        self.assertEqual(headers["Idempotency-Replayed"], "false")

        # 201 mining keeps 201 with its fixed body and first-exec headers.
        status, block, headers = self.mine(key="mine-key")
        self.assertEqual((status, block["status"]), (201, "pending"))
        self.assertEqual(headers["Idempotency-Replayed"], "false")

        # 200 confirm keeps 200.
        status, body, headers = self.confirm(block["height"], key="confirm-key")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"height": block["height"], "status": "confirmed"})
        self.assertEqual(headers["Idempotency-Replayed"], "false")

    def test_replay_returns_cached_status_body_and_no_new_effect(self) -> None:
        status, first, h1 = self.submit(key="k")
        self.assertEqual(status, 202)
        pending_after_first = set(self.store.pending)
        events_after_first = len(self.store.audit_events)
        status, second, h2 = self.submit(key="k")
        self.assertEqual(status, 202)
        self.assertEqual(second, first)
        self.assertEqual(h2["Idempotency-Key"], "k")
        self.assertEqual(h2["Idempotency-Replayed"], "true")
        self.assertEqual(set(self.store.pending), pending_after_first)
        self.assertEqual(len(self.store.audit_events), events_after_first)
        self.assertEqual(len(self.store.idempotency_records), 1)

    def test_replay_ignores_json_key_order_and_whitespace(self) -> None:
        tx = signed_tx(self.ka, self.A, self.B, 33)
        status, first, _ = self.request(
            "POST", "/v1/transactions", tx, key="fp"
        )
        self.assertEqual(status, 202, first)
        reordered = (
            '{ "amount": 33,\n "from": "%s", "signature": "%s", "to": "%s" }'
            % (tx["from"], tx["signature"], tx["to"])
        )
        status, second, headers = self.raw_request(
            "POST", "/v1/transactions", key="fp", raw_body=reordered
        )[:3]
        self.assertEqual(status, 202)
        self.assertEqual(second, first)
        self.assertEqual(headers["Idempotency-Replayed"], "true")

    def test_same_key_changed_body_is_409_without_headers(self) -> None:
        self.submit(10, key="k")
        status, body, headers = self.submit(11, key="k")
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "idempotency key conflict"})
        self.assertNotIn("Idempotency-Replayed", headers)
        self.assertNotIn("Idempotency-Key", headers)

    def test_same_key_changed_target_is_409(self) -> None:
        # Same key, same JSON body, different query string on the target.
        tx = signed_tx(self.ka, self.A, self.B, 10)
        status, _, _ = self.raw_request(
            "POST", "/v1/transactions?a=1", tx, key="k"
        )[:3]
        self.assertEqual(status, 202)
        status, body, _ = self.raw_request(
            "POST", "/v1/transactions?a=2", tx, key="k"
        )[:3]
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "idempotency key conflict"})

    def test_same_key_changed_method_is_409_and_not_executed(self) -> None:
        # First use mines a block via POST; the same key on DELETE conflicts
        # before the removal business logic runs.
        self.submit(10)
        status, _, _ = self.mine(key="m")
        self.assertEqual(status, 201)
        status, body, _ = self.request(
            "DELETE", "/v1/trust/allowlist/whatever", key="m"
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "idempotency key conflict"})

    def test_4xx_does_not_occupy_key(self) -> None:
        bad = signed_tx(self.ka, self.A, self.B, 10)
        bad["amount"] = -5
        status, _, headers = self.request(
            "POST", "/v1/transactions", bad, key="retry"
        )
        self.assertEqual(status, 400)
        self.assertNotIn("Idempotency-Replayed", headers)
        # The very same key then drives a valid first execution.
        status, _, headers = self.submit(10, key="retry")
        self.assertEqual(status, 202)
        self.assertEqual(headers["Idempotency-Replayed"], "false")

    def test_404_does_not_occupy_delete_key(self) -> None:
        status, _, _ = self.request(
            "DELETE", "/v1/trust/allowlist/missing", key="d"
        )
        self.assertEqual(status, 404)
        # Create then delete under the same key: the earlier 404 left it free.
        status, _, _ = self.request(
            "POST",
            "/v1/trust/allowlist",
            {"source": "missing", "expires_at": FUTURE},
            key="add",
        )
        self.assertEqual(status, 201)
        status, body, headers = self.request(
            "DELETE", "/v1/trust/allowlist/missing", key="d"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, {"source": "missing", "removed": True})
        self.assertEqual(headers["Idempotency-Replayed"], "false")
        status, body2, headers = self.request(
            "DELETE", "/v1/trust/allowlist/missing", key="d"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body2, body)
        self.assertEqual(headers["Idempotency-Replayed"], "true")

    def test_malformed_key_is_400_and_touches_nothing(self) -> None:
        tx = signed_tx(self.ka, self.A, self.B, 10)
        generation = self.store.generation
        for bad in ("", " ", "has space", "tab\there", "del\x7f", "x" * 129):
            status, _, _ = self.request(
                "POST", "/v1/transactions", tx, key=bad
            )
            self.assertEqual(status, 400, repr(bad))
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(self.store.idempotency_records, {})
        # Boundary: exactly 128 visible ASCII characters is accepted.
        status, _, headers = self.submit(10, key="~" * 128)
        self.assertEqual(status, 202)
        self.assertEqual(headers["Idempotency-Replayed"], "false")

    def test_invalid_json_with_key_is_400_and_key_reusable(self) -> None:
        status, _, _ = self.raw_request(
            "POST", "/v1/transactions", key="bad-json", raw_body="{not json"
        )[:3]
        self.assertEqual(status, 400)
        status, _, headers = self.submit(10, key="bad-json")
        self.assertEqual(status, 202)
        self.assertEqual(headers["Idempotency-Replayed"], "false")

    def test_bodyless_routes_fingerprint_null_body(self) -> None:
        self.submit(10)
        status, block, h1 = self.mine(key="bodyless")
        self.assertEqual(status, 201)
        # A replay with an explicit empty body still matches (absent body and
        # Content-Length:0 both canonicalize to JSON null).
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/v1/blocks",
            body=b"",
            headers={"Idempotency-Key": "bodyless", "Content-Type": "application/json"},
        )
        response = conn.getresponse()
        headers = dict(response.getheaders())
        payload = json.loads(response.read())
        conn.close()
        self.assertEqual(response.status, 201)
        self.assertEqual(payload, block)
        self.assertEqual(headers["Idempotency-Replayed"], "true")

    def test_no_key_is_verbatim_legacy(self) -> None:
        self.submit(10)
        status, block, headers = self.mine()
        self.assertEqual(status, 201)
        self.assertNotIn("Idempotency-Key", headers)
        self.assertNotIn("Idempotency-Replayed", headers)
        # Legacy re-mine conflict is unchanged.
        status, _, headers = self.mine()
        self.assertEqual(status, 409)
        self.assertNotIn("Idempotency-Replayed", headers)
        # GETs never carry the headers either.
        status, _, headers = self.request("GET", "/v1/trust")
        self.assertEqual(status, 200)
        self.assertNotIn("Idempotency-Replayed", headers)

    def test_read_only_post_ignores_key(self) -> None:
        _, tx_body, _ = self.submit(10)
        _, block, _ = self.mine()
        self.confirm(block["height"])
        # A successful read-only batch-proof POST must not cache anything.
        status, _, headers = self.raw_request(
            "POST",
            f"/v1/blocks/{block['height']}/proofs",
            {"tx_ids": [tx_body["tx_id"]]},
            key="ignored",
        )[:3]
        self.assertEqual(status, 200)
        self.assertNotIn("Idempotency-Replayed", headers)
        self.assertNotIn("Idempotency-Key", headers)
        self.assertEqual(self.store.idempotency_records, {})

    def test_get_with_key_is_untouched(self) -> None:
        status, _, headers = self.request("GET", "/v1/chain", key="gk")
        self.assertEqual(status, 200)
        self.assertNotIn("Idempotency-Replayed", headers)
        self.assertEqual(self.store.idempotency_records, {})

    def test_concurrent_same_key_single_execution(self) -> None:
        tx = signed_tx(self.ka, self.A, self.B, 10)
        barrier = threading.Barrier(2)
        results = []

        def fire() -> None:
            barrier.wait()
            results.append(
                self.request("POST", "/v1/transactions", tx, key="race")
            )

        threads = [threading.Thread(target=fire) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        markers = sorted(r[2].get("Idempotency-Replayed") for r in results)
        self.assertEqual(markers, ["false", "true"])
        self.assertEqual(len(self.store.pending), 1)
        self.assertEqual(len(self.store.idempotency_records), 1)

    def test_replay_survives_restart(self) -> None:
        # A mempool transaction stays pending across a restart; its cached
        # 202 response replays identically afterward.
        status, first, _ = self.submit(10, key="durable")
        self.assertEqual(status, 202)
        self.assertEqual(set(self.store.pending), {first["tx_id"]})
        self.restart()
        status, second, headers = self.submit(10, key="durable")
        self.assertEqual(status, 202)
        self.assertEqual(second, first)
        self.assertEqual(headers["Idempotency-Replayed"], "true")
        # No second mempool entry after the restarted replay.
        self.assertEqual(set(self.store.pending), {first["tx_id"]})

    def test_confirmed_confirm_replay_survives_restart(self) -> None:
        self.submit(10)
        _, block, _ = self.mine(key="durable-mine")
        self.confirm(block["height"], key="durable-confirm")
        self.restart()
        status, body, headers = self.confirm(block["height"], key="durable-confirm")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"height": block["height"], "status": "confirmed"})
        self.assertEqual(headers["Idempotency-Replayed"], "true")

    def test_fork_candidate_first_and_replay(self) -> None:
        genesis = self.store.chain[0]
        fork_doc = make_fork([genesis, make_block(genesis, self.ka, self.A, self.B, 10)])
        status, first, h1 = self.request(
            "POST", "/v1/forks/candidates", fork_doc, key="fork"
        )
        self.assertEqual(status, 201, first)
        self.assertEqual(h1["Idempotency-Replayed"], "false")
        status, second, h2 = self.request(
            "POST", "/v1/forks/candidates", fork_doc, key="fork"
        )
        self.assertEqual(status, 201)
        self.assertEqual(second, first)
        self.assertEqual(h2["Idempotency-Replayed"], "true")
        self.assertEqual(len(self.store.forks), 1)

    def test_sync_business_replay_is_cached_and_restarts(self) -> None:
        # Register a trusted source and deliver a fork through the sync route
        # WITHOUT an HTTP Idempotency-Key (so the 201 reception is the only
        # durable sync lifecycle). The next delivery is the sync layer's
        # business-level same-key replay (200, no write, no new audit event);
        # wrapping THAT request in an HTTP Idempotency-Key must cache its 200
        # so it replays identically after a restart.
        status, _ = self.service.register_trust_source(
            {"source": "node-1", "public_key": KEY_A, "expires_at": FUTURE}
        )
        self.assertEqual(status, 201)
        genesis = self.store.chain[0]
        fork_doc = make_fork([genesis, make_block(genesis, self.ka, self.A, self.B, 12)])
        sync_body = {
            "source": "node-1",
            "request_id": "req-1",
            "expires_at": FUTURE,
            "candidate": fork_doc,
        }
        status, first, headers = self.request(
            "POST", "/v1/forks/sync", sync_body
        )
        self.assertEqual(status, 201, first)
        self.assertNotIn("Idempotency-Replayed", headers)
        # The business-level 200 replay now carries the HTTP idempotency key.
        status, replay, headers = self.request(
            "POST", "/v1/forks/sync", sync_body, key="sync-replay"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Idempotency-Replayed"], "false")
        self.assertEqual(replay["tip_hash"], first["tip_hash"])
        received = [
            e for e in self.store.audit_events if e["kind"] == "sync_received"
        ]
        self.assertEqual(len(received), 1)
        self.restart()
        status, replay2, headers = self.request(
            "POST", "/v1/forks/sync", sync_body, key="sync-replay"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Idempotency-Replayed"], "true")
        self.assertEqual(replay2, replay)

    def test_side_effect_free_success_under_second_equal_key(self) -> None:
        # Key A turns height 1 confirmed (a real write). Key B repeats the
        # exact confirm: business-idempotent 200 with no write, and its
        # fingerprint already cached under A, so no duplicate record is made.
        self.submit(10)
        _, block, _ = self.mine()
        status, _, headers = self.confirm(block["height"], key="A")
        self.assertEqual(status, 200)
        records_before = len(self.store.idempotency_records)
        status, _, headers = self.confirm(block["height"], key="B")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Idempotency-Replayed"], "false")
        self.assertEqual(len(self.store.idempotency_records), records_before)
        self.assertNotIn("B", self.store.idempotency_records)
        # Such a snapshot still recovers cleanly and A keeps replaying.
        self.restart()
        status, body, headers = self.confirm(block["height"], key="A")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Idempotency-Replayed"], "true")
        self.assertEqual(body, {"height": block["height"], "status": "confirmed"})

    def test_audit_signer_rotate_is_idempotent(self) -> None:
        seed = crypto.generate_private_key()
        body = {"private_key": seed, "expected_version": 1}
        status, first, h1 = self.request(
            "POST", "/v1/audit/signer/rotate", body, key="signer"
        )
        self.assertEqual(status, 200, first)
        self.assertEqual(h1["Idempotency-Replayed"], "false")
        status, second, h2 = self.request(
            "POST", "/v1/audit/signer/rotate", body, key="signer"
        )
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        self.assertEqual(h2["Idempotency-Replayed"], "true")
        rotations = [
            e for e in self.store.audit_events
            if e["kind"] == "audit_signer_rotated"
        ]
        self.assertEqual(len(rotations), 1)


class IdempotencyPersistenceTests(HttpFixture, unittest.TestCase):
    def test_persistence_failure_returns_500_and_leaves_nothing(self) -> None:
        tx = signed_tx(self.ka, self.A, self.B, 10)

        def failing() -> None:
            raise OSError("disk full")

        self.store.save = failing  # type: ignore[method-assign]
        status, body, replayed = self.service.run_idempotent(
            "pf",
            "POST",
            "/v1/transactions",
            tx,
            lambda: self.service.submit_transaction(tx),
        )
        self.assertEqual((status, body, replayed), (500, {"error": "persistence failed"}, False))
        del self.store.save
        self.assertEqual(self.store.pending, {})
        self.assertNotIn("pf", self.store.idempotency_records)
        # The key is free: a retry is a genuine first execution.
        status, body, replayed = self.service.run_idempotent(
            "pf",
            "POST",
            "/v1/transactions",
            tx,
            lambda: self.service.submit_transaction(tx),
        )
        self.assertEqual((status, replayed), (202, False))
        self.assertIn("pf", self.store.idempotency_records)

    def _corrupt_main_snapshot(self, mutate) -> str:
        with open(self.state_path, encoding="utf-8") as fh:
            raw = json.load(fh)
        mutate(raw)
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        return self.state_path

    def test_recovery_rejects_duplicate_fingerprint(self) -> None:
        self.submit(10, key="one")
        self.submit(20, key="two")

        def duplicate(raw) -> None:
            clone = dict(raw["idempotency"][0])
            clone["key"] = "three"
            raw["idempotency"].append(clone)

        self._corrupt_main_snapshot(duplicate)
        with self.assertRaises(StateRecoveryError) as caught:
            LedgerStore(self.state_path)
        self.assertIn("fingerprint", caught.exception.reason)

    def test_recovery_rejects_invalid_cached_body(self) -> None:
        self.submit(10, key="one")

        def corrupt(raw) -> None:
            raw["idempotency"][0]["body"] = "not-json{"

        self._corrupt_main_snapshot(corrupt)
        with self.assertRaises(StateRecoveryError) as caught:
            LedgerStore(self.state_path)
        self.assertIn("body", caught.exception.reason)

    def test_recovery_rejects_duplicate_key(self) -> None:
        self.submit(10, key="one")

        def corrupt(raw) -> None:
            clone = dict(raw["idempotency"][0])
            clone["target"] = "/v1/blocks"
            raw["idempotency"].append(clone)

        self._corrupt_main_snapshot(corrupt)
        with self.assertRaises(StateRecoveryError) as caught:
            LedgerStore(self.state_path)
        self.assertIn("duplicate idempotency key", caught.exception.reason)

    def test_recovery_rejects_missing_field(self) -> None:
        self.submit(10, key="one")

        def corrupt(raw) -> None:
            del raw["idempotency"][0]["status"]

        self._corrupt_main_snapshot(corrupt)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_recovery_rejects_non_2xx_cached_status(self) -> None:
        self.submit(10, key="one")

        def corrupt(raw) -> None:
            raw["idempotency"][0]["status"] = 409

        self._corrupt_main_snapshot(corrupt)
        with self.assertRaises(StateRecoveryError) as caught:
            LedgerStore(self.state_path)
        self.assertIn("2xx", caught.exception.reason)


class HistoryIdempotencyTests(HttpFixture, unittest.TestCase):
    """The token-gated history management routes use ordered-error bodies."""

    def setUp(self) -> None:
        self.history_file = None
        self.trust_file = None
        super().setUp()  # type: ignore[call-arg]

    def _configure(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.history_file = os.path.join(self.tmp, "history.json")
        self.trust_file = os.path.join(self.tmp, "trust.json")
        self._start((self.history_file, self.trust_file, "tok"))
        self.root_seed = crypto.generate_private_key()
        self.key_seed = crypto.generate_private_key()

    def test_credential_rotate_replays_and_malformed_key_is_input(self) -> None:
        self._configure()
        body = {
            "action": "rotate",
            "token": "persisted-token",
            "permissions": ["read", "update", "export"],
            "expected_version": 0,
        }
        status, first, headers = self.raw_request(
            "POST",
            "/v1/history/access",
            body,
            key="cred",
            headers={"Authorization": "Bearer tok"},
        )[:3]
        self.assertEqual(status, 201, first)
        self.assertEqual(list(first), ["version", "token_hash", "permissions", "status"])
        self.assertEqual(headers["Idempotency-Replayed"], "false")
        status, second, headers = self.raw_request(
            "POST",
            "/v1/history/access",
            body,
            key="cred",
            headers={"Authorization": "Bearer tok"},
        )[:3]
        self.assertEqual(status, 201)
        self.assertEqual(second, first)
        self.assertEqual(headers["Idempotency-Replayed"], "true")
        credential_changes = [
            e for e in self.store.audit_events
            if e["kind"] == "history_credential_changed"
        ]
        self.assertEqual(len(credential_changes), 1)
        # A malformed key on an ordered-error route answers the input document.
        status, body400, _ = self.raw_request(
            "POST",
            "/v1/history/access",
            body,
            key="bad key",
            headers={"Authorization": "Bearer tok"},
        )[:3]
        self.assertEqual(status, 400)
        self.assertEqual(body400, {"ok": False, "error": "input"})

    def test_history_trust_append_is_idempotent(self) -> None:
        self._configure()
        body = {
            "root_seed": self.root_seed,
            "at": 100,
            "key": self.key_seed,
            "status": "active",
        }
        status, first, headers = self.raw_request(
            "POST",
            "/v1/history/trust",
            body,
            key="trust-append",
            headers={"Authorization": "Bearer tok"},
        )[:3]
        self.assertEqual(status, 201, first)
        self.assertEqual(list(first), ["root", "records", "head"])
        self.assertEqual(headers["Idempotency-Replayed"], "false")
        status, second, headers = self.raw_request(
            "POST",
            "/v1/history/trust",
            body,
            key="trust-append",
            headers={"Authorization": "Bearer tok"},
        )[:3]
        self.assertEqual(status, 201)
        self.assertEqual(second, first)
        self.assertEqual(headers["Idempotency-Replayed"], "true")


if __name__ == "__main__":
    unittest.main()

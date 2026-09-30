"""Tests for the uniform Idempotency-Key request protection.

Covers every state-changing POST/DELETE: first execution preserves the
original status/body/key order and echoes Idempotency-Key plus
Idempotency-Replayed: false; a same-key/same-fingerprint retry replays the
cached status and body with Idempotency-Replayed: true, executes nothing and
appends no audit event; a same-key different method/target/body conflicts 409;
4xx answers occupy no key; malformed keys and invalid JSON are 400 with no
state touched; keyless requests behave verbatim; the records survive a
restart; concurrency with one key serializes into one change + identical
replays; GET and read-only POSTs ignore the header.

Run: python3 tests/idempotency_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError
from ledger import crypto


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


class IdempotencyHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "idem.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.service = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

    def request(
        self,
        method: str,
        path: str,
        payload=None,
        idem_key: str | None = None,
        raw_body: bytes | None = None,
    ):
        url = f"{self.base}{path}"
        if raw_body is not None:
            data = raw_body
        elif payload is not None:
            data = json.dumps(payload).encode()
        else:
            data = None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        if idem_key is not None:
            headers["Idempotency-Key"] = idem_key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                body = resp.read().decode()
                return (
                    resp.status,
                    json.loads(body),
                    {k.lower(): v for k, v in resp.headers.items()},
                    body.encode(),
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            return (
                exc.code,
                parsed,
                {k.lower(): v for k, v in exc.headers.items()},
                body.encode(),
            )

    def test_transaction_first_then_replay_then_conflict(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 7)
        status, body, headers, raw = self.request(
            "POST", "/v1/transactions", payload, idem_key="tx-key-1"
        )
        self.assertEqual(status, 202)
        self.assertEqual(headers.get("idempotency-key"), "tx-key-1")
        self.assertEqual(headers.get("idempotency-replayed"), "false")
        tx_id = body["tx_id"]

        # Same key, same body: cached 202 replay, no second mempool entry.
        status2, body2, headers2, raw2 = self.request(
            "POST", "/v1/transactions", payload, idem_key="tx-key-1"
        )
        self.assertEqual(status2, 202)
        self.assertEqual(body2, body)
        self.assertEqual(raw2, raw)
        self.assertEqual(headers2.get("idempotency-replayed"), "true")
        self.assertEqual(list(self.service.store.pending), [tx_id])

        # Same key, different body: 409 conflict, no idempotency headers.
        other = make_tx(self.ka, self.A, self.B, 8)
        status3, body3, headers3, _ = self.request(
            "POST", "/v1/transactions", other, idem_key="tx-key-1"
        )
        self.assertEqual(status3, 409)
        self.assertEqual(body3, {"error": "idempotency key conflict"})
        self.assertNotIn("idempotency-replayed", headers3)
        # The conflicting attempt changed nothing.
        self.assertEqual(list(self.service.store.pending), [tx_id])

    def test_key_order_and_whitespace_ignored_in_fingerprint(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 3)
        status, body, _, raw = self.request(
            "POST",
            "/v1/transactions",
            raw_body=json.dumps(payload, separators=(",", ":")).encode(),
            idem_key="ws-key",
        )
        self.assertEqual(status, 202)
        reordered = {
            "signature": payload["signature"],
            "amount": payload["amount"],
            "to": payload["to"],
            "from": payload["from"],
        }
        status2, body2, _, raw2 = self.request(
            "POST",
            "/v1/transactions",
            raw_body=json.dumps(reordered, indent=2).encode(),
            idem_key="ws-key",
        )
        self.assertEqual(status2, 202)
        self.assertEqual(raw2, raw)
        self.assertEqual(body2, body)

    def test_4xx_does_not_occupy_key(self) -> None:
        bad = {"from": self.A, "to": self.B, "amount": -1, "signature": "00"}
        status, _, headers, _ = self.request(
            "POST", "/v1/transactions", bad, idem_key="failed-key"
        )
        self.assertEqual(status, 400)
        self.assertNotIn("idempotency-replayed", headers)
        # The key is reusable for a later successful request.
        good = make_tx(self.ka, self.A, self.B, 2)
        status2, _, headers2, _ = self.request(
            "POST", "/v1/transactions", good, idem_key="failed-key"
        )
        self.assertEqual(status2, 202)
        self.assertEqual(headers2.get("idempotency-replayed"), "false")

    def test_business_409_does_not_occupy_key(self) -> None:
        # A duplicate transaction is a business 409; the key stays free.
        payload = make_tx(self.ka, self.A, self.B, 5)
        self.request("POST", "/v1/transactions", payload)
        status = self.request(
            "POST", "/v1/transactions", payload, idem_key="dup-key"
        )[0]
        self.assertEqual(status, 409)
        # Reusing the key for a distinct, valid request is a fresh first run.
        other = make_tx(self.ka, self.A, self.B, 6)
        status2, _, headers2, _ = self.request(
            "POST", "/v1/transactions", other, idem_key="dup-key"
        )
        self.assertEqual(status2, 202)
        self.assertEqual(headers2.get("idempotency-replayed"), "false")

    def test_malformed_key_and_bad_json_are_400(self) -> None:
        # Space inside the key is not visible ASCII.
        status, body, _, _ = self.request(
            "POST",
            "/v1/transactions",
            make_tx(self.ka, self.A, self.B, 1),
            idem_key="has space",
        )
        self.assertEqual(status, 400)
        self.assertIn("Idempotency-Key", body["error"])
        # Empty value.
        status, _, _, _ = self.request(
            "POST", "/v1/blocks", payload={}, idem_key=""
        )
        self.assertEqual(status, 400)
        # 129 characters.
        status, _, _, _ = self.request(
            "POST", "/v1/blocks", payload={}, idem_key="x" * 129
        )
        self.assertEqual(status, 400)
        # Tab is a control character.
        status, _, _, _ = self.request(
            "POST", "/v1/blocks", payload={}, idem_key="a\tb"
        )
        self.assertEqual(status, 400)
        # Valid key with invalid JSON body.
        status, _, _, _ = self.request(
            "POST",
            "/v1/transactions",
            raw_body=b"{not json",
            idem_key="bad-json-key",
        )
        self.assertEqual(status, 400)
        # A 400 key error touches no state (mempool is still empty).
        self.assertEqual(self.service.store.pending, {})

    def test_keyless_request_is_verbatim_legacy(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 4)
        status, _, headers, _ = self.request(
            "POST", "/v1/transactions", payload
        )
        self.assertEqual(status, 202)
        self.assertNotIn("idempotency-key", headers)
        self.assertNotIn("idempotency-replayed", headers)

    def test_mine_confirm_idempotency_and_no_reexecution(self) -> None:
        self.request(
            "POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 11)
        )
        status, block, headers, raw = self.request(
            "POST", "/v1/blocks", idem_key="mine-key"
        )
        self.assertEqual(status, 201)
        self.assertEqual(headers.get("idempotency-replayed"), "false")
        height = block["height"]
        status2, block2, headers2, raw2 = self.request(
            "POST", "/v1/blocks", idem_key="mine-key"
        )
        self.assertEqual(status2, 201)
        self.assertEqual(headers2.get("idempotency-replayed"), "true")
        self.assertEqual(raw2, raw)
        # Only one block was mined: the next height does not exist.
        self.assertEqual(
            self.request("GET", f"/v1/blocks/{height + 1}")[0], 404
        )

        status3, body3, _, raw3 = self.request(
            "POST", f"/v1/blocks/{height}/confirm", idem_key="confirm-key"
        )
        self.assertEqual(status3, 200)
        self.assertEqual(body3, {"height": height, "status": "confirmed"})
        status4, body4, headers4, raw4 = self.request(
            "POST", f"/v1/blocks/{height}/confirm", idem_key="confirm-key"
        )
        self.assertEqual(status4, 200)
        self.assertEqual(headers4.get("idempotency-replayed"), "true")
        self.assertEqual(raw4, raw3)
        self.assertEqual(body4, body3)

    def test_rollback_replay_after_state_moved(self) -> None:
        self.request(
            "POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 9)
        )
        _, block, _, _ = self.request("POST", "/v1/blocks")
        height = block["height"]
        status, body, _, _ = self.request(
            "POST", f"/v1/blocks/{height}/rollback", idem_key="rb-key"
        )
        self.assertEqual(status, 200)
        # Mine a fresh block so a fresh rollback would now be 404; the cached
        # 200 must still replay.
        self.request("POST", "/v1/blocks")
        status2, body2, headers2, _ = self.request(
            "POST", f"/v1/blocks/{height}/rollback", idem_key="rb-key"
        )
        self.assertEqual(status2, 200)
        self.assertEqual(headers2.get("idempotency-replayed"), "true")
        self.assertEqual(body2, body)

    def test_target_change_is_conflict(self) -> None:
        # The key must first have a successful record: mine block 1 and
        # confirm it with the key.
        self.request(
            "POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 1)
        )
        self.request("POST", "/v1/blocks")
        self.request("POST", "/v1/blocks/1/confirm", idem_key="target-key")
        # Same key, different request target conflicts before executing.
        status, body, _, _ = self.request(
            "POST", "/v1/blocks/2/confirm", idem_key="target-key"
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "idempotency key conflict"})

    def test_method_change_is_conflict(self) -> None:
        payload = {"source": "m-del", "expires_at": 1_900_000_000}
        self.request(
            "POST", "/v1/trust/allowlist", payload, idem_key="method-key"
        )
        # Same key on a DELETE (different method) conflicts.
        status, body, _, _ = self.request(
            "DELETE", "/v1/trust/allowlist/m-del", idem_key="method-key"
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "idempotency key conflict"})

    def test_query_string_participates_in_fingerprint(self) -> None:
        # Two confirm POSTs cannot differ by query on the same route today, so
        # exercise the target component via the library directly.
        from ledger.store import request_fingerprint

        fp1 = request_fingerprint("POST", "/v1/x?a=1", '{"v":1}')
        fp2 = request_fingerprint("POST", "/v1/x?a=2", '{"v":1}')
        self.assertNotEqual(fp1, fp2)

    def test_audit_events_not_duplicated_by_replay(self) -> None:
        payload = {
            "source": "idem-source",
            "public_key": self.A,
            "expires_at": 2_000_000_000,
        }
        _, before, _, _ = self.request("GET", "/v1/audit/events?limit=200")
        status, _, _, _ = self.request(
            "POST", "/v1/trust/sources", payload, idem_key="trust-key"
        )
        self.assertEqual(status, 201)
        _, mid, _, _ = self.request("GET", "/v1/audit/events?limit=200")
        self.assertEqual(mid["total"], before["total"] + 1)
        # Replay keeps the ORIGINAL 201 status and appends no audit event.
        status2, _, headers2, _ = self.request(
            "POST", "/v1/trust/sources", payload, idem_key="trust-key"
        )
        self.assertEqual(status2, 201)
        self.assertEqual(headers2.get("idempotency-replayed"), "true")
        _, after, _, _ = self.request("GET", "/v1/audit/events?limit=200")
        self.assertEqual(after["total"], mid["total"])

    def test_allowlist_post_and_delete(self) -> None:
        payload = {"source": "keyless-idem", "expires_at": 1_900_000_000}
        status, _, _, _ = self.request(
            "POST", "/v1/trust/allowlist", payload, idem_key="al-key"
        )
        self.assertEqual(status, 201)
        status2, _, headers2, _ = self.request(
            "POST", "/v1/trust/allowlist", payload, idem_key="al-key"
        )
        # The first response status (201) is frozen for replays.
        self.assertEqual(status2, 201)
        self.assertEqual(headers2.get("idempotency-replayed"), "true")
        status3, body3, _, _ = self.request(
            "DELETE", "/v1/trust/allowlist/keyless-idem", idem_key="al-del-key"
        )
        self.assertEqual(status3, 200)
        self.assertEqual(body3, {"source": "keyless-idem", "removed": True})
        status4, body4, headers4, _ = self.request(
            "DELETE", "/v1/trust/allowlist/keyless-idem", idem_key="al-del-key"
        )
        # Replay keeps the original 200 even though a fresh DELETE is now 404.
        self.assertEqual(status4, 200)
        self.assertEqual(headers4.get("idempotency-replayed"), "true")
        self.assertEqual(body4, body3)
        self.assertEqual(
            self.request("DELETE", "/v1/trust/allowlist/keyless-idem")[0],
            404,
        )

    def test_read_only_post_ignores_header(self) -> None:
        tx = make_tx(self.kb, self.B, self.A, 1)
        self.request("POST", "/v1/transactions", tx)
        self.request("POST", "/v1/blocks")
        self.request("POST", "/v1/blocks/1/confirm")
        tx_id = self.service.store.chain[1].transactions[0].tx_id
        body = {"tx_ids": [tx_id]}
        status, _, headers, _ = self.request(
            "POST", "/v1/blocks/1/proofs", body, idem_key="ignored-ro"
        )
        self.assertEqual(status, 200)
        self.assertNotIn("idempotency-replayed", headers)

    def test_get_ignores_header(self) -> None:
        # Even with the header, a GET never emits idempotency headers.
        status, _, headers, _ = self.request(
            "GET", "/v1/blocks/0", idem_key="get-key"
        )
        self.assertEqual(status, 200)
        self.assertNotIn("idempotency-replayed", headers)

    def test_records_survive_restart(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 6)
        status, body, _, raw = self.request(
            "POST", "/v1/transactions", payload, idem_key="restart-key"
        )
        self.assertEqual(status, 202)
        tx_id = body["tx_id"]
        # Restart against the same snapshot.
        self.tearDown()
        self.service = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", self.port), build_handler(self.service)
        )
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        status2, body2, headers2, raw2 = self.request(
            "POST", "/v1/transactions", payload, idem_key="restart-key"
        )
        self.assertEqual(status2, 202)
        self.assertEqual(headers2.get("idempotency-replayed"), "true")
        self.assertEqual(raw2, raw)
        self.assertEqual(body2["tx_id"], tx_id)
        self.assertEqual(list(self.service.store.pending), [tx_id])

    def test_concurrent_same_key_single_execution(self) -> None:
        payload = {
            "source": "concurrent-source",
            "public_key": self.A,
            "expires_at": 2_000_000_001,
        }

        def fire():
            return self.request(
                "POST", "/v1/trust/sources", payload, idem_key="concurrent-key"
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fire) for _ in range(8)]
            results = [future.result() for future in futures]
        # All responses are the frozen first status (201); one first execution.
        self.assertTrue(all(item[0] == 201 for item in results), results)
        firsts = [
            item for item in results
            if item[2].get("idempotency-replayed") == "false"
        ]
        replays = [
            item for item in results
            if item[2].get("idempotency-replayed") == "true"
        ]
        self.assertEqual(len(firsts), 1)
        self.assertEqual(len(replays), 7)
        self.assertEqual(len({item[3] for item in results}), 1)
        _, events, _, _ = self.request(
            "GET", "/v1/audit/events?kind=source_registered&limit=200"
        )
        matches = [
            event
            for event in events["items"]
            if event.get("source") == "concurrent-source"
        ]
        self.assertEqual(len(matches), 1)

    def test_4xx_rolls_back_incidental_mutation_and_generation(self) -> None:
        # A callback that mutates state (an audit event) and then answers 4xx
        # must have that incidental mutation rolled back: the rejected
        # request occupies no key, appends no event and advances no
        # generation. This mirrors an expired-sync sweep inside a request that
        # ultimately fails authorization/validation.
        from ledger.service import EVENT_ALLOWLIST_ADDED

        def callback():
            self.service.store.append_audit_event(
                EVENT_ALLOWLIST_ADDED,
                {"source": "incidental", "expires_at": 1},
            )
            return 403, {"error": "source is not an active trusted source"}

        before_events = len(self.service.store.audit_events)
        before_generation = self.service.store.generation
        with self.service.store.lock:
            status, body, replayed, cached = self.service.execute_idempotent(
                "POST", "/v1/forks/sync", "sweep-4xx-key", {"source": 123},
                callback,
            )
        self.assertEqual(status, 403)
        self.assertFalse(replayed)
        self.assertIsNone(cached)
        self.assertEqual(len(self.service.store.audit_events), before_events)
        self.assertEqual(self.service.store.generation, before_generation)
        # The key is not occupied: a later same-key successful run is a first.
        def success_callback():
            return 200, {"ok": True}

        status2, _, replayed2, _ = self.service.execute_idempotent(
            "POST", "/v1/forks/sync", "sweep-4xx-key", {"source": 123},
            success_callback,
        )
        self.assertEqual(status2, 200)
        self.assertFalse(replayed2)


class IdempotencyRecoveryTests(unittest.TestCase):
    """Snapshot recovery rejects corrupt idempotency sections."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "corrupt.json")
        self.key, self.A = keypair()
        self.kb, self.B = keypair()
        self.service = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )

    def _one_record(self) -> None:
        payload = make_tx(self.key, self.A, self.B, 1)
        self.service.submit_transaction.__self__  # service exists
        # Drive one keyed write through the gateway to populate the section.
        from ledger.store import (
            canonical_request_body,
            request_fingerprint,
        )

        status, result = self.service.submit_transaction(payload)
        assert status == 202
        canonical = canonical_request_body(payload)
        fingerprint = request_fingerprint("POST", "/v1/transactions", canonical)
        with self.service.store.lock:
            self.service.store.begin_persistence()
            self.service.store.commit_persistence(
                {
                    "key": "recover-key",
                    "method": "POST",
                    "target": "/v1/transactions",
                    "request": canonical,
                    "fingerprint": fingerprint,
                    "status": 202,
                    "body": json.dumps(result, sort_keys=True),
                }
            )

    def _reload_section(self):
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data

    def test_tampered_fingerprint_rejected(self) -> None:
        self._one_record()
        data = self._reload_section()
        data["idempotency"][0]["fingerprint"] = "f" * 64
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_duplicate_fingerprint_rejected(self) -> None:
        self._one_record()
        data = self._reload_section()
        clone = dict(data["idempotency"][0])
        clone["key"] = "other-key"
        data["idempotency"].append(clone)
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_dangling_record_rejected(self) -> None:
        self._one_record()
        data = self._reload_section()
        data["idempotency"][0]["target"] = "/v1/transactions?x=1"
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_consistency_accepts_section(self) -> None:
        from ledger.consistency import verify_snapshot

        self._one_record()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        result = verify_snapshot(data)
        self.assertTrue(result["ok"], result)

    def test_consistency_rejects_tampered_section(self) -> None:
        from ledger.consistency import verify_snapshot

        self._one_record()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["idempotency"][0]["status"] = 400
        result = verify_snapshot(data)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "input")


if __name__ == "__main__":
    unittest.main()

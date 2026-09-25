"""Tests for the persistent permissioned history credential.

The token-gated node-managed history endpoints gain a durable, scoped
credential managed exclusively by the configured static token through
``POST /v1/history/access``.

Covers:

* rotate: first create 201 at version 0, later rotates 200 bumping the
  version; ``token_hash`` is SHA-256 of the UTF-8 token; the response key
  order is fixed ``version, token_hash, permissions, status`` and permissions
  are normalized to the read/update/export order; revoke is 200 and keeps the
  version, hash and permissions while flipping status to revoked; an
  idempotent re-revoke is 200 with no new event or write;
* format errors are 400/input (closed body keys, non-empty token, non-empty
  duplicate-free permission subset, non-bool non-negative
  expected_version, revoke carries null token/permissions); a version
  mismatch is 409/state; both have no side effects;
* bearer gate: the static token is full-power; an active credential token
  authorizes only the routes covered by read/update/export; a wrong/missing/
  revoked token is 401/unauthorized and an authenticated-but-unscoped
  credential is 403/forbidden, both before the body is read and with no audit
  event or state change; the credential-management route is static-only;
* the change is persisted atomically: snapshot stores the response-shaped
  ``history_credential`` section without the plaintext token and appends one
  ``history_credential_changed`` event (action followed by the response) in
  the same generation as the audit log; a forced save failure rolls the
  in-memory credential and event back (500/io);
* restart reloads the credential and tampering with the section or the event
  raises StateRecoveryError(path, reason);
* with the feature disabled the new route is 404 like the other history
  routes.

Run: python3 tests/history_credential_test.py
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from history_http_test import HttpHistoryFixture  # noqa: E402

from ledger import crypto  # noqa: E402
from ledger import audit, consistency  # noqa: E402
from ledger.light_client import advance  # noqa: E402
from ledger.server import build_handler  # noqa: E402
from ledger.service import LedgerService  # noqa: E402
from ledger.store import LedgerStore, StateRecoveryError  # noqa: E402

UNAUTHORIZED = {"ok": False, "error": "unauthorized"}
FORBIDDEN = {"ok": False, "error": "forbidden"}
INPUT = {"ok": False, "error": "input"}
STATE = {"ok": False, "error": "state"}
RESPONSE_KEYS = ["version", "token_hash", "permissions", "status"]
CHANGE_PAYLOAD_KEYS = ["action", "version", "token_hash", "permissions", "status"]


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CredentialFixture(HttpHistoryFixture):
    """Adds credential-oriented request helpers and event accessors."""

    def credential_events(self):
        return [
            event
            for event in self.store.audit_events
            if event["kind"] == "history_credential_changed"
        ]

    def access(self, body, *, token="test-token", raw_body=None):
        if raw_body is None:
            return self.request(
                "POST", "/v1/history/access", body, auth=f"Bearer {token}"
            )
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        conn.request("POST", "/v1/history/access", body=raw_body, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        payload = json.loads(raw.decode("utf-8")) if raw else None
        conn.close()
        return response.status, payload

    def rotate(self, token, permissions, expected_version, *, auth="test-token"):
        return self.access(
            {
                "action": "rotate",
                "token": token,
                "permissions": permissions,
                "expected_version": expected_version,
            },
            token=auth,
        )

    def revoke(self, expected_version, *, auth="test-token"):
        return self.access(
            {
                "action": "revoke",
                "token": None,
                "permissions": None,
                "expected_version": expected_version,
            },
            token=auth,
        )


class RotateRevokeTests(CredentialFixture):
    def test_first_rotate_creates_version_zero(self) -> None:
        status, body = self.rotate("token-A", ["read"], 0)
        self.assertEqual(status, 201)
        self.assertEqual(list(body.keys()), RESPONSE_KEYS)
        self.assertEqual(
            body,
            {
                "version": 0,
                "token_hash": sha256("token-A"),
                "permissions": ["read"],
                "status": "active",
            },
        )
        # Only the hash is persisted; the plaintext token never is.
        with open(self.state_path, encoding="utf-8") as fh:
            raw_text = fh.read()
        on_disk = json.loads(raw_text)
        self.assertEqual(set(on_disk["history_credential"]), set(RESPONSE_KEYS))
        self.assertEqual(
            on_disk["history_credential"]["token_hash"], sha256("token-A")
        )
        self.assertNotIn("token-A", raw_text)

    def test_permissions_normalized_to_fixed_order(self) -> None:
        status, body = self.rotate(
            "token-A", ["export", "update", "read"], 0
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["permissions"], ["read", "update", "export"])

    def test_rotate_bumps_version_and_hash(self) -> None:
        self.assertEqual(self.rotate("token-A", ["read"], 0)[0], 201)
        status, body = self.rotate("token-B", ["read", "export"], 0)
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], 1)
        self.assertEqual(body["token_hash"], sha256("token-B"))
        self.assertEqual(body["permissions"], ["read", "export"])
        self.assertEqual(body["status"], "active")

    def test_version_mismatch_is_409_without_side_effects(self) -> None:
        generation = self.store.generation
        status, body = self.rotate("token-A", ["read"], 7)
        self.assertEqual((status, body), (409, STATE))
        self.assertIsNone(self.store.history_credential)
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(self.credential_events(), [])

    def test_revoke_preserves_hash_and_permissions(self) -> None:
        self.rotate("token-A", ["read", "export"], 0)
        status, body = self.revoke(0)
        self.assertEqual(status, 200)
        self.assertEqual(list(body.keys()), RESPONSE_KEYS)
        self.assertEqual(body["version"], 0)
        self.assertEqual(body["token_hash"], sha256("token-A"))
        self.assertEqual(body["permissions"], ["read", "export"])
        self.assertEqual(body["status"], "revoked")

    def test_idempotent_re_revoke_is_200_without_event_or_write(self) -> None:
        self.rotate("token-A", ["read"], 0)
        self.assertEqual(self.revoke(0)[0], 200)
        events = len(self.store.audit_events)
        generation = self.store.generation
        with open(self.state_path, "rb") as fh:
            snapshot_bytes = fh.read()
        status, body = self.revoke(0)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "revoked")
        self.assertEqual(len(self.store.audit_events), events)
        self.assertEqual(self.store.generation, generation)
        with open(self.state_path, "rb") as fh:
            self.assertEqual(fh.read(), snapshot_bytes)
        # Exactly one change event (the revoke), no duplicate.
        self.assertEqual(len(self.credential_events()), 2)

    def test_revoke_with_wrong_version_is_409(self) -> None:
        self.rotate("token-A", ["read"], 0)
        self.rotate("token-B", ["read"], 0)
        status, body = self.revoke(0)
        self.assertEqual((status, body), (409, STATE))
        self.assertEqual(self.store.history_credential["version"], 1)
        self.assertEqual(
            self.store.history_credential["status"], "active"
        )

    def test_revoke_before_create_is_409(self) -> None:
        status, body = self.revoke(0)
        self.assertEqual((status, body), (409, STATE))

    def test_rotate_after_revoke_revives_as_new_version(self) -> None:
        # A revoke does not permanently retire the credential slot: a rotate
        # at the revoked version issues a fresh active token at version+1.
        self.rotate("token-A", ["read"], 0)
        self.revoke(0)
        status, body = self.rotate("token-B", ["update"], 0)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "version": 1,
                "token_hash": sha256("token-B"),
                "permissions": ["update"],
                "status": "active",
            },
        )


class CredentialValidationTests(CredentialFixture):
    BAD_BODIES = [
        ["not", "an", "object"],
        "string",
        42,
        {},
        {"action": "rotate", "token": "x", "permissions": ["read"]},
        {"action": "rotate", "token": "x", "permissions": ["read"],
         "expected_version": 0, "extra": True},
        {"action": "frobnicate", "token": "x", "permissions": ["read"],
         "expected_version": 0},
        {"action": "revoke", "token": "x", "permissions": ["read"],
         "expected_version": 0},
        # rotate requires a non-empty token
        {"action": "rotate", "token": "", "permissions": ["read"],
         "expected_version": 0},
        {"action": "rotate", "token": 42, "permissions": ["read"],
         "expected_version": 0},
        {"action": "rotate", "token": None, "permissions": None,
         "expected_version": 0},
        # permissions: non-empty, no duplicates, subset
        {"action": "rotate", "token": "x", "permissions": [],
         "expected_version": 0},
        {"action": "rotate", "token": "x", "permissions": ["read", "read"],
         "expected_version": 0},
        {"action": "rotate", "token": "x", "permissions": ["admin"],
         "expected_version": 0},
        {"action": "rotate", "token": "x", "permissions": [["read"]],
         "expected_version": 0},
        {"action": "rotate", "token": "x", "permissions": [{"read": True}],
         "expected_version": 0},
        {"action": "rotate", "token": "x", "permissions": "read",
         "expected_version": 0},
        # expected_version: non-bool non-negative integer
        {"action": "rotate", "token": "x", "permissions": ["read"],
         "expected_version": -1},
        {"action": "rotate", "token": "x", "permissions": ["read"],
         "expected_version": True},
        {"action": "rotate", "token": "x", "permissions": ["read"],
         "expected_version": "0"},
        {"action": "rotate", "token": "x", "permissions": ["read"],
         "expected_version": 1.5},
        # revoke requires both token and permissions null
        {"action": "revoke", "token": "x", "permissions": None,
         "expected_version": 0},
        {"action": "revoke", "token": None, "permissions": [],
         "expected_version": 0},
    ]

    def test_bad_bodies_are_400_input_without_side_effects(self) -> None:
        generation = self.store.generation
        for body in self.BAD_BODIES:
            status, payload = self.access(body)
            self.assertEqual((status, payload), (400, INPUT), body)
        self.assertIsNone(self.store.history_credential)
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(self.credential_events(), [])

    def test_invalid_json_is_400_input(self) -> None:
        status, payload = self.access(None, raw_body=b"{not json")
        self.assertEqual((status, payload), (400, INPUT))

    def test_first_create_against_nonzero_version_is_409(self) -> None:
        # Well-formed rotate, but no credential exists yet and expected_version
        # is not the initial 0: a state conflict, not a format error.
        status, payload = self.rotate("token-A", ["read"], 1)
        self.assertEqual((status, payload), (409, STATE))


class BearerGateTests(CredentialFixture):
    def setUp(self) -> None:
        super().setUp()
        # A signer log so GET /v1/history/trust can succeed once authorized.
        self.assertEqual(self.activate(1)[0], 201)

    def test_static_token_is_full_power(self) -> None:
        self.assertEqual(self.request("GET", "/v1/history/trust")[0], 200)

    def test_read_credential_scoping(self) -> None:
        self.rotate("read-token", ["read"], 0)
        # read can GET the signer log (200)...
        status, _ = self.request(
            "GET", "/v1/history/trust", auth="Bearer read-token"
        )
        self.assertEqual(status, 200)
        # ...but cannot update or export.
        status, body = self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": self.root_seed, "at": 2,
             "key": self.key_pub, "status": "active"},
            auth="Bearer read-token",
        )
        self.assertEqual((status, body), (403, FORBIDDEN))
        status, body = self.request(
            "POST",
            "/v1/history/export",
            {"key": self.key_seed},
            auth="Bearer read-token",
        )
        self.assertEqual((status, body), (403, FORBIDDEN))

    def test_credential_cannot_manage_credential(self) -> None:
        self.rotate("read-token", ["read", "update", "export"], 0)
        status, body = self.rotate(
            "another", ["read"], 0, auth="read-token"
        )
        self.assertEqual((status, body), (401, UNAUTHORIZED))

    def test_unknown_missing_and_malformed_bearer_are_401(self) -> None:
        self.rotate("read-token", ["read"], 0)
        for auth in (None, "Bearer wrong", "Bearer", "Basic read-token",
                     "read-token"):
            status, body = self.request(
                "GET", "/v1/history/trust", auth=auth
            )
            self.assertEqual((status, body), (401, UNAUTHORIZED), auth)

    def test_old_and_revoked_tokens_stop_working(self) -> None:
        self.rotate("token-A", ["read"], 0)
        self.assertEqual(
            self.request(
                "GET", "/v1/history/trust", auth="Bearer token-A"
            )[0],
            200,
        )
        self.rotate("token-B", ["read"], 0)
        self.assertEqual(
            self.request(
                "GET", "/v1/history/trust", auth="Bearer token-A"
            ),
            (401, UNAUTHORIZED),
        )
        self.assertEqual(
            self.request(
                "GET", "/v1/history/trust", auth="Bearer token-B"
            )[0],
            200,
        )
        self.revoke(1)
        self.assertEqual(
            self.request(
                "GET", "/v1/history/trust", auth="Bearer token-B"
            ),
            (401, UNAUTHORIZED),
        )

    def test_update_credential_can_post_trust_only(self) -> None:
        self.rotate("up-token", ["update"], 0)
        status, _ = self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": self.root_seed, "at": 2,
             "key": self.key_pub, "status": "revoked"},
            auth="Bearer up-token",
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            self.request(
                "GET", "/v1/history/trust", auth="Bearer up-token"
            )[0],
            403,
        )

    def test_export_credential_can_export(self) -> None:
        # Build an offline checkpoint + sidecar so an export page exists.
        result = advance(
            self.history_file,
            [self.continuation_page(0)],
            self.trust,
            self.anchor,
            100,
        )
        self.assertTrue(result["ok"], result)
        self.rotate("ex-token", ["export"], 0)
        status, page = self.request(
            "POST",
            "/v1/history/export",
            {"key": self.key_seed},
            auth="Bearer ex-token",
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            list(page.keys()),
            ["base", "records", "next", "head", "checkpoint", "auth"],
        )
        # export alone cannot read or update.
        self.assertEqual(
            self.request(
                "GET", "/v1/history/trust", auth="Bearer ex-token"
            )[0],
            403,
        )

    def test_401_and_403_have_no_side_effects(self) -> None:
        self.rotate("read-token", ["read"], 0)
        with open(self.state_path, "rb") as fh:
            before = fh.read()
        events_before = len(self.store.audit_events)
        # 401: wrong token. 403: authenticated read credential trying update.
        self.request("GET", "/v1/history/trust", auth="Bearer nope")
        self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": self.root_seed, "at": 2,
             "key": self.key_pub, "status": "active"},
            auth="Bearer read-token",
        )
        with open(self.state_path, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual(len(self.store.audit_events), events_before)


class AuditAndPersistenceTests(CredentialFixture):
    def test_change_event_payload_and_generation(self) -> None:
        generation = self.store.generation
        self.assertEqual(self.rotate("token-A", ["export", "read"], 0)[0], 201)
        self.rotate("token-B", ["read"], 0)
        self.revoke(1)
        events = self.credential_events()
        self.assertEqual(len(events), 3)
        actions = [event["action"] for event in events]
        self.assertEqual(actions, ["rotate", "rotate", "revoke"])
        for event in events:
            self.assertEqual(
                [
                    key
                    for key in event
                    if key in CHANGE_PAYLOAD_KEYS
                ],
                CHANGE_PAYLOAD_KEYS,
            )
        # The last event pins the revoked response exactly.
        last = events[-1]
        self.assertEqual(last["version"], 1)
        self.assertEqual(last["token_hash"], sha256("token-B"))
        self.assertEqual(last["permissions"], ["read"])
        self.assertEqual(last["status"], "revoked")
        # Each successful change consumed exactly one generation.
        self.assertEqual(self.store.generation, generation + 3)
        # The hash chain stays continuous and the checkpoint pins the head.
        self.assertEqual(
            self.store.audit_checkpoint["event_id"],
            len(self.store.audit_events),
        )

    def test_failed_save_rolls_back_credential_and_event(self) -> None:
        original_save = LedgerStore.save
        LedgerStore.save = lambda instance: (_ for _ in ()).throw(
            OSError("disk full")
        )
        try:
            status, body = self.rotate("token-A", ["read"], 0)
        finally:
            LedgerStore.save = original_save
        self.assertEqual((status, body), (500, {"ok": False, "error": "io"}))
        self.assertIsNone(self.store.history_credential)
        self.assertEqual(self.credential_events(), [])
        # The failed write consumed no generation and a retry succeeds.
        generation = self.store.generation
        self.assertEqual(self.rotate("token-A", ["read"], 0)[0], 201)
        self.assertEqual(self.store.generation, generation + 1)

    def test_restart_preserves_credential_and_token_still_works(self) -> None:
        self.activate(1)
        self.rotate("token-A", ["read"], 0)
        self.restart_service()
        self.assertEqual(
            self.store.history_credential,
            {
                "version": 0,
                "token_hash": sha256("token-A"),
                "permissions": ["read"],
                "status": "active",
            },
        )
        status, _ = self.request(
            "GET", "/v1/history/trust", auth="Bearer token-A"
        )
        self.assertEqual(status, 200)

    def test_restart_with_tampered_section_fails(self) -> None:
        self.rotate("token-A", ["read"], 0)
        self.httpd.shutdown()
        with open(self.state_path, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        snapshot["history_credential"]["status"] = "revoked"
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        with self.assertRaises(StateRecoveryError) as context:
            LedgerStore(
                self.state_path,
                initial_balance=1000,
                history_path=self.history_file,
                history_trust_path=self.trust_file,
            )
        self.assertEqual(context.exception.path, self.state_path)
        self.assertTrue(context.exception.reason)

    def test_restart_with_tampered_event_fails(self) -> None:
        self.rotate("token-A", ["read"], 0)
        self.httpd.shutdown()
        with open(self.state_path, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        for event in snapshot["audit_events"]:
            if event["kind"] == "history_credential_changed":
                event["version"] = 9
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(
                self.state_path,
                initial_balance=1000,
                history_path=self.history_file,
                history_trust_path=self.trust_file,
            )

    def test_credential_audit_event_visible_in_audit_listing(self) -> None:
        self.rotate("token-A", ["read"], 0)
        status, body = self.request(
            "GET", "/v1/audit/events?kind=history_credential_changed"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["action"], "rotate")


class OfflineConsistencyTests(CredentialFixture):
    def _snapshot(self):
        with open(self.state_path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_valid_credential_snapshot_verifies(self) -> None:
        self.rotate("token-A", ["export", "read"], 0)
        result = consistency.verify_snapshot(self._snapshot())
        self.assertTrue(result["ok"], result)

    def test_section_without_event_is_integrity(self) -> None:
        self.rotate("token-A", ["read"], 0)
        document = self._snapshot()
        del document["audit_events"]
        self.assertEqual(
            consistency.verify_snapshot(document)["error"], "integrity"
        )

    def test_semantic_version_jump_is_integrity(self) -> None:
        self.rotate("token-A", ["read"], 0)
        document = self._snapshot()
        for event in document["audit_events"]:
            if event["kind"] == "history_credential_changed":
                event["version"] = 5
        # Re-link the chain so the only remaining defect is the credential
        # replay (first rotate must create version 0).
        document["audit_events"] = audit.link_events(document["audit_events"])
        document["audit_checkpoint"] = audit.make_checkpoint(
            document["audit_events"]
        )
        document["history_credential"]["version"] = 5
        self.assertEqual(
            consistency.verify_snapshot(document)["error"], "integrity"
        )

    def test_wrong_primitive_and_unknown_key_are_input(self) -> None:
        self.rotate("token-A", ["read"], 0)
        document = self._snapshot()
        document["history_credential"]["version"] = True
        self.assertEqual(
            consistency.verify_snapshot(document)["error"], "input"
        )
        document = self._snapshot()
        document["bogus_section"] = 1
        self.assertEqual(
            consistency.verify_snapshot(document)["error"], "input"
        )


class FeatureDisabledTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.store = LedgerStore(self.state_path, initial_balance=1000)
        self.service = LedgerService(self.store, initial_balance=1000)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_access_route_is_404_when_history_disabled(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/v1/history/access",
            body=json.dumps(
                {"action": "rotate", "token": "x",
                 "permissions": ["read"], "expected_version": 0}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        body = json.loads(response.read().decode("utf-8"))
        conn.close()
        self.assertEqual(response.status, 404)
        self.assertEqual(body, {"ok": False, "error": "not found"})


if __name__ == "__main__":
    unittest.main()

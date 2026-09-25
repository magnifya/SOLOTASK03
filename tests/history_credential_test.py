"""Tests for the persistent scoped history-access credential.

Covers POST /v1/history/access and the scoped bearer tokens it issues:

* the static --history-token is full-power and exclusively owns
  /v1/history/access; a scoped token there is 403 forbidden, a
  missing/malformed/wrong Authorization header is 401 unauthorized, both
  before the body is read and with no side effects;
* rotate: body keys are exactly action,token,permissions,expected_version;
  the token must be a non-empty string, permissions a non-empty
  duplicate-free subsequence of read/update/export and expected_version a
  non-boolean non-negative integer equal to the current version (0 before
  the first rotation) — shape defects are 400/input, a version mismatch is
  409/state; the first rotation is 201, later ones 200 with version+1;
* revoke: token and permissions must both be null; the recorded hash and
  permissions are retained, only the status flips to revoked; revoking
  without an active credential is 409/state;
* the success document has the contract key order
  version,token_hash,permissions,status with token_hash = SHA256(token
  UTF-8); the plaintext token is never persisted;
* scoped bearer tokens authenticate only while active and only for their
  recorded permissions (trust read/update and export map to
  read/update/export); a missing permission is 403 forbidden with no side
  effects, a revoked or unknown token is 401;
* every change appends exactly one history_credential_changed audit event
  (payload: the action followed by the response document) persisted
  atomically with the history_credential snapshot section and the
  generation; a forced snapshot failure rolls all three back (500/io);
* restart recovers the credential (an active token keeps working, a revoked
  one stays 401); a malformed history_credential section or a malformed
  persisted event raises StateRecoveryError(path, reason);
* startup binding errors are attributed to the offending file: a trust_head
  drift names the signer log, a history_head drift names the checkpoint
  file.

Run: python3 tests/history_credential_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from history_http_test import ERROR_BODY, HttpHistoryFixture  # noqa: E402

from ledger.light_client import advance, history_trust  # noqa: E402
from ledger.store import LedgerStore, StateRecoveryError  # noqa: E402

FORBIDDEN_BODY = {"ok": False, "error": "forbidden"}
INPUT_BODY = {"ok": False, "error": "input"}
STATE_BODY = {"ok": False, "error": "state"}

SCOPED = "scoped-token-1"
SCOPED_HASH = hashlib.sha256(SCOPED.encode("utf-8")).hexdigest()


def rotate(token=SCOPED, permissions=("read", "update", "export"), version=0):
    return {
        "action": "rotate",
        "token": token,
        "permissions": list(permissions),
        "expected_version": version,
    }


def revoke(version):
    return {
        "action": "revoke",
        "token": None,
        "permissions": None,
        "expected_version": version,
    }


class AccessGateTests(HttpHistoryFixture):
    def test_access_requires_the_static_token(self) -> None:
        self.assertEqual(
            self.request("POST", "/v1/history/access", rotate())[0], 201
        )
        before = open(self.state_path, "rb").read()
        # A scoped token — even a full-power one — may not manage credentials.
        status, body = self.request(
            "POST",
            "/v1/history/access",
            rotate("other", ["read"], 1),
            auth=f"Bearer {SCOPED}",
        )
        self.assertEqual((status, body), (403, FORBIDDEN_BODY))
        # Missing, wrong and malformed headers are 401.
        for auth in (None, "Bearer wrong", "Bearer", "Basic test-token"):
            status, body = self.request(
                "POST", "/v1/history/access", rotate("x", ["read"], 1), auth=auth
            )
            self.assertEqual((status, body), (401, ERROR_BODY), auth)
        # No side effects: the snapshot is byte-identical and no extra event.
        self.assertEqual(open(self.state_path, "rb").read(), before)
        self.assertEqual(
            len(
                [
                    e
                    for e in self.store.audit_events
                    if e["kind"] == "history_credential_changed"
                ]
            ),
            1,
        )

    def test_disabled_history_is_404(self) -> None:
        from ledger.service import LedgerService

        service = LedgerService(self.store)
        status, body = service.update_history_credential(rotate())
        self.assertEqual((status, body), (404, {"ok": False, "error": "not found"}))


class RotateValidationTests(HttpHistoryFixture):
    def test_shape_defects_are_400(self) -> None:
        valid = rotate()
        bad_bodies = [
            {},
            [],
            "rotate",
            {**valid, "extra": 1},
            {key: value for key, value in list(valid.items())[:-1]},
            {**valid, "action": "create"},
            {**valid, "action": None},
            {**valid, "token": ""},
            {**valid, "token": None},
            {**valid, "token": 7},
            {**valid, "permissions": []},
            {**valid, "permissions": "read"},
            {**valid, "permissions": ["read", "read"]},
            {**valid, "permissions": ["update", "read"]},
            {**valid, "permissions": ["read", "bogus"]},
            {**valid, "permissions": [None]},
            {**valid, "expected_version": -1},
            {**valid, "expected_version": True},
            {**valid, "expected_version": 1.5},
            {**valid, "expected_version": "0"},
            revoke(0) | {"token": "x"},
            revoke(0) | {"permissions": ["read"]},
        ]
        for body in bad_bodies:
            status, payload = self.request("POST", "/v1/history/access", body)
            self.assertEqual((status, payload), (400, INPUT_BODY), body)
        # Nothing was persisted and no event was appended.
        self.assertIsNone(self.store.history_credential)
        self.assertEqual(
            [
                e
                for e in self.store.audit_events
                if e["kind"] == "history_credential_changed"
            ],
            [],
        )

    def test_rotate_201_then_200_with_version_increment(self) -> None:
        status, body = self.request("POST", "/v1/history/access", rotate())
        self.assertEqual(status, 201)
        self.assertEqual(
            list(body.keys()), ["version", "token_hash", "permissions", "status"]
        )
        self.assertEqual(
            body,
            {
                "version": 1,
                "token_hash": SCOPED_HASH,
                "permissions": ["read", "update", "export"],
                "status": "active",
            },
        )
        # A stale expected_version conflicts 409/state and changes nothing.
        status, payload = self.request(
            "POST", "/v1/history/access", rotate("other", ["read"], 0)
        )
        self.assertEqual((status, payload), (409, STATE_BODY))
        self.assertEqual(self.store.history_credential, body)
        # The matching version rotates: 200, version+1, new hash/permissions.
        status, body2 = self.request(
            "POST", "/v1/history/access", rotate("second", ["export"], 1)
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            body2,
            {
                "version": 2,
                "token_hash": hashlib.sha256(b"second").hexdigest(),
                "permissions": ["export"],
                "status": "active",
            },
        )


class RevokeTests(HttpHistoryFixture):
    def test_revoke_keeps_hash_and_permissions(self) -> None:
        self.assertEqual(
            self.request("POST", "/v1/history/access", rotate())[0], 201
        )
        status, body = self.request("POST", "/v1/history/access", revoke(1))
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "version": 2,
                "token_hash": SCOPED_HASH,
                "permissions": ["read", "update", "export"],
                "status": "revoked",
            },
        )
        # A second revoke has nothing active to revoke: 409/state.
        status, payload = self.request("POST", "/v1/history/access", revoke(2))
        self.assertEqual((status, payload), (409, STATE_BODY))
        # Rotation is still possible after a revoke (200, version+1).
        status, body = self.request(
            "POST", "/v1/history/access", rotate("third", ["read"], 2)
        )
        self.assertEqual((status, body["version"], body["status"]), (200, 3, "active"))

    def test_revoke_without_credential_is_409(self) -> None:
        status, payload = self.request("POST", "/v1/history/access", revoke(0))
        self.assertEqual((status, payload), (409, STATE_BODY))
        self.assertIsNone(self.store.history_credential)


class ScopedBearerTests(HttpHistoryFixture):
    def setUp(self) -> None:
        super().setUp()
        self.assertEqual(self.activate(1)[0], 201)
        result = advance(
            self.history_file,
            [self.continuation_page(0)],
            self.trust,
            self.anchor,
            100,
        )
        self.assertTrue(result["ok"], result)
        # Baseline: the fixture setup already recorded one update event.
        self.events_before = len(self.store.audit_events)

    def scoped(self, permissions, token=SCOPED, version=0):
        status, _ = self.request(
            "POST", "/v1/history/access", rotate(token, permissions, version)
        )
        self.assertEqual(status, 201)

    def test_read_permission_only(self) -> None:
        self.scoped(["read"])
        auth = f"Bearer {SCOPED}"
        self.assertEqual(
            self.request("GET", "/v1/history/trust", auth=auth)[0], 200
        )
        before = open(self.state_path, "rb").read()
        # Update and export are beyond the recorded permission: 403, and the
        # gate runs before the body is read or any state is touched.
        status, body = self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": self.root_seed, "at": 2,
             "key": self.key_pub, "status": "active"},
            auth=auth,
        )
        self.assertEqual((status, body), (403, FORBIDDEN_BODY))
        status, body = self.request(
            "POST", "/v1/history/export", {"key": self.key_seed}, auth=auth
        )
        self.assertEqual((status, body), (403, FORBIDDEN_BODY))
        self.assertEqual(open(self.state_path, "rb").read(), before)
        self.assertEqual(len(self.store.audit_events), self.events_before + 2)

    def test_update_and_export_permissions(self) -> None:
        self.scoped(["update", "export"])
        auth = f"Bearer {SCOPED}"
        status, _ = self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": self.root_seed, "at": 2,
             "key": self.key_pub, "status": "revoked"},
            auth=auth,
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            self.request(
                "POST", "/v1/history/export", {"key": self.key_seed}, auth=auth
            )[0],
            200,
        )
        # ... but reading the log is not covered: 403.
        status, body = self.request("GET", "/v1/history/trust", auth=auth)
        self.assertEqual((status, body), (403, FORBIDDEN_BODY))

    def test_unknown_and_revoked_tokens_are_401(self) -> None:
        self.scoped(["read", "update", "export"])
        status, body = self.request(
            "GET", "/v1/history/trust", auth="Bearer no-such-token"
        )
        self.assertEqual((status, body), (401, ERROR_BODY))
        self.assertEqual(
            self.request("POST", "/v1/history/access", revoke(1))[0], 200
        )
        # Only the active version authenticates: a revoked token is 401 on
        # every route (the gate fires before the body is even read).
        tail = {"root_seed": self.root_seed, "at": 2,
                "key": self.key_pub, "status": "active"}
        for method, target, body_arg in (
            ("GET", "/v1/history/trust", None),
            ("POST", "/v1/history/trust", tail),
            ("POST", "/v1/history/export", {"key": self.key_seed}),
            ("POST", "/v1/history/access", rotate("x", ["read"], 2)),
        ):
            status, body = self.request(
                method, target, body_arg, auth=f"Bearer {SCOPED}"
            )
            self.assertEqual((status, body), (401, ERROR_BODY), (method, target))

    def test_static_token_stays_full_power(self) -> None:
        self.scoped(["read"])
        self.assertEqual(
            self.request("POST", "/v1/history/export", {"key": self.key_seed})[0],
            200,
        )
        self.assertEqual(self.request("GET", "/v1/history/trust")[0], 200)


class CredentialPersistenceTests(HttpHistoryFixture):
    def credential_events(self):
        return [
            event
            for event in self.store.audit_events
            if event["kind"] == "history_credential_changed"
        ]

    def test_event_payload_and_snapshot_section(self) -> None:
        status, body = self.request(
            "POST", "/v1/history/access", rotate(SCOPED, ["read", "export"])
        )
        self.assertEqual(status, 201)
        events = self.credential_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        # Payload: the action followed by the exact response document.
        keys = [
            key
            for key in event
            if key in ("action", "version", "token_hash", "permissions", "status")
        ]
        self.assertEqual(
            keys, ["action", "version", "token_hash", "permissions", "status"]
        )
        self.assertEqual(event["action"], "rotate")
        self.assertEqual({key: event[key] for key in keys[1:]}, body)
        # The snapshot section is exactly the response document — and the
        # plaintext token appears nowhere in the snapshot bytes.
        snapshot = json.loads(open(self.state_path, encoding="utf-8").read())
        self.assertEqual(snapshot["history_credential"], body)
        self.assertNotIn(SCOPED, open(self.state_path, encoding="utf-8").read())

    def test_restart_recovers_credential(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        self.assertEqual(
            self.request("POST", "/v1/history/access", rotate())[0], 201
        )
        self.assertEqual(
            self.request("POST", "/v1/history/access", revoke(1))[0], 200
        )
        self.restart_service()
        # The revoked token stays 401 and the recorded version survives.
        status, body = self.request(
            "GET", "/v1/history/trust", auth=f"Bearer {SCOPED}"
        )
        self.assertEqual((status, body), (401, ERROR_BODY))
        status, body = self.request(
            "POST", "/v1/history/access", rotate("new-token", ["read"], 2)
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], 3)
        # A further restart keeps the new active token working.
        self.restart_service()
        self.assertEqual(
            self.request("GET", "/v1/history/trust", auth="Bearer new-token")[0],
            200,
        )

    def test_snapshot_failure_rolls_back(self) -> None:
        events_before = len(self.store.audit_events)
        generation_before = self.store.generation
        from ledger.store import LedgerStore as StoreClass

        original_save = StoreClass.save
        StoreClass.save = lambda instance: (_ for _ in ()).throw(
            OSError("disk full")
        )
        try:
            status, body = self.request("POST", "/v1/history/access", rotate())
        finally:
            StoreClass.save = original_save
        self.assertEqual((status, body), (500, {"ok": False, "error": "io"}))
        self.assertIsNone(self.store.history_credential)
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)
        # The node still works afterwards.
        self.assertEqual(
            self.request("POST", "/v1/history/access", rotate())[0], 201
        )

    def test_corrupt_credential_section_fails_recovery(self) -> None:
        self.assertEqual(
            self.request("POST", "/v1/history/access", rotate())[0], 201
        )
        self.httpd.shutdown()
        for mutate in (
            lambda section: section.update(status="bogus"),
            lambda section: section.update(version=0),
            lambda section: section.update(token_hash="z" * 64),
            lambda section: section.update(permissions=["read", "read"]),
            lambda section: section.pop("status"),
        ):
            with open(self.state_path, encoding="utf-8") as fh:
                snapshot = json.load(fh)
            mutate(snapshot["history_credential"])
            with open(self.state_path, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh)
            with self.assertRaises(StateRecoveryError) as context:
                LedgerStore(self.state_path, initial_balance=1000)
            self.assertEqual(context.exception.path, self.state_path)
            self.assertTrue(context.exception.reason)

    def test_malformed_persisted_event_fails_recovery(self) -> None:
        self.assertEqual(
            self.request("POST", "/v1/history/access", rotate())[0], 201
        )
        self.httpd.shutdown()
        with open(self.state_path, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        for event in snapshot["audit_events"]:
            if event.get("kind") == "history_credential_changed":
                event["permissions"] = []
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)


class BindingPathTests(HttpHistoryFixture):
    def test_trust_head_drift_names_the_trust_file(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        self.httpd.shutdown()
        # Advance the signer log offline: the last history_access event still
        # names the previous trust head.
        result = history_trust(
            self.trust_file, self.root_seed, 2, self.key_pub, "revoked"
        )
        self.assertIn("head", result, result)
        with self.assertRaises(StateRecoveryError) as context:
            LedgerStore(
                self.state_path,
                initial_balance=1000,
                history_path=self.history_file,
                history_trust_path=self.trust_file,
            )
        self.assertEqual(context.exception.path, self.trust_file)
        self.assertTrue(context.exception.reason)

    def test_history_head_drift_names_the_history_file(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        self.assertEqual(
            self.request(
                "POST", "/v1/history/export", {"key": self.key_seed}
            )[0],
            500,  # no checkpoint yet: io
        )
        result = advance(
            self.history_file,
            [self.continuation_page(0)],
            self.trust,
            self.anchor,
            100,
        )
        self.assertTrue(result["ok"], result)
        # Record the current heads with a read, then advance offline again.
        self.assertEqual(self.request("GET", "/v1/history/trust")[0], 200)
        self.httpd.shutdown()
        result = advance(
            self.history_file,
            [self.continuation_page(1)],
            self.trust,
            None,
            101,
        )
        self.assertTrue(result["ok"], result)
        with self.assertRaises(StateRecoveryError) as context:
            LedgerStore(
                self.state_path,
                initial_balance=1000,
                history_path=self.history_file,
                history_trust_path=self.trust_file,
            )
        self.assertEqual(context.exception.path, self.history_file)
        self.assertTrue(context.exception.reason)


if __name__ == "__main__":
    unittest.main()

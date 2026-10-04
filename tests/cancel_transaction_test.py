"""Tests for sender-signed transaction cancellation.

Covers POST /v1/transactions/{tx_id}/cancel end to end at the service layer
and over HTTP:

* the fixed signed-message format ``ledger-cancel-v1\\n<tx_id>``;
* 400 {"error": "input"} for a malformed tx_id, body or signature and for any
  query parameter;
* 404 {"error": "not_found"} when the id is on neither the canonical chain
  (confirmed blocks plus the pending tip) nor the mempool — candidate forks
  never participate;
* 403 {"error": "unauthorized"} for a signature that does not verify under
  the located transaction's sender;
* 409 {"error": "not_cancellable"} for a packed/confirmed transaction;
* 409 {"error": "sequence_conflict"} for a sequenced transfer that is not the
  sender's highest pending-tip/mempool reservation;
* 200 {"tx_id", "status": "cancelled"} removes the transaction, releases its
  spend reservation (and nonce for a sequenced transfer), leaves everything
  else untouched, and appends exactly one transaction_cancelled audit event
  carrying tx_id, from, to, amount and the cancellation signature (plus nonce
  for sequenced transfers);
* cancelled transactions read as not found from single and batch receipts,
  the identical transfer can be resubmitted and the nonce reused, while a
  legal fork may still contain the cancelled transaction;
* the cancellation follows the uniform Idempotency-Key rules and advances the
  generation exactly once per successful cancellation;
* persistence failures roll the whole request back; restarts retain the
  cancellation and its idempotent replay; snapshots carrying a malformed
  cancel event fail recovery while older snapshots still load.

Run: python3 tests/cancel_transaction_test.py
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

from ledger import crypto
from ledger.models import STATUS_CONFIRMED, Block, Transaction
from ledger.server import build_handler
from ledger.service import (
    EVENT_TRANSACTION_CANCELLED,
    EVENT_TRANSACTION_SUBMITTED,
    LedgerService,
)
from ledger.store import LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def legacy_payload(key, sender, to, amount) -> dict:
    message = crypto.canonical_message(sender, to, amount)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(message).hex(),
    }


def sequenced_payload(key, sender, to, amount, nonce) -> dict:
    message = crypto.sequenced_message(sender, to, amount, nonce)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(message).hex(),
    }


def cancel_signature(key, tx_id: str) -> str:
    return key.sign(crypto.cancel_message(tx_id)).hex()


class CancelMessageTests(unittest.TestCase):
    def test_message_format_is_fixed(self) -> None:
        tx_id = "a" * 64
        self.assertEqual(
            crypto.cancel_message(tx_id),
            b"ledger-cancel-v1\n" + b"a" * 64,
        )

    def test_message_is_utf8_prefix_line_plus_tx_id(self) -> None:
        message = crypto.cancel_message("0123456789abcdef" * 4)
        self.assertTrue(message.startswith(b"ledger-cancel-v1\n"))
        self.assertEqual(len(message), len("ledger-cancel-v1") + 1 + 64)


class CancelServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )

    def submit_legacy(self, amount=10, key=None, sender=None, to=None):
        return self.svc.submit_transaction(
            legacy_payload(
                key or self.ka, sender or self.A, to or self.B, amount
            )
        )

    def submit_seq(self, nonce, amount=10, key=None, sender=None, to=None):
        return self.svc.submit_sequenced_transaction(
            sequenced_payload(
                key or self.ka, sender or self.A, to or self.B, amount, nonce
            )
        )

    def cancel(self, tx_id, key=None, signature=None):
        signature = signature or cancel_signature(key or self.ka, tx_id)
        return self.svc.cancel_transaction(tx_id, {"signature": signature})

    def cancel_events(self):
        return [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_CANCELLED
        ]

    # -- input validation ---------------------------------------------------

    def test_bad_tx_id_is_400_input(self) -> None:
        for bad in ("", "zz", "a" * 63, "A" * 64, "a" * 65, 123, None):
            status, body = self.svc.cancel_transaction(
                bad, {"signature": "b" * 128}
            )
            self.assertEqual((status, body), (400, {"error": "input"}), bad)

    def test_bad_body_is_400_input(self) -> None:
        tx_id = "f" * 64
        for bad_body in (
            None,
            "nope",
            [],
            {},
            {"signature": "b" * 128, "extra": 1},
            {"sig": "b" * 128},
        ):
            status, body = self.svc.cancel_transaction(tx_id, bad_body)
            self.assertEqual((status, body), (400, {"error": "input"}), bad_body)

    def test_bad_signature_format_is_400_input(self) -> None:
        tx_id = "f" * 64
        for bad_signature in (
            "",
            "zz",
            "a" * 127,
            "A" * 128,
            "a" * 129,
            128,
            None,
        ):
            status, body = self.svc.cancel_transaction(
                tx_id, {"signature": bad_signature}
            )
            self.assertEqual((status, body), (400, {"error": "input"}), bad_signature)

    # -- lookup -------------------------------------------------------------

    def test_unknown_tx_is_404_not_found(self) -> None:
        unknown = "f" * 64
        status, body = self.cancel(unknown)
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_candidate_fork_only_tx_is_404(self) -> None:
        # A transaction existing solely in a stored candidate fork is never a
        # match: cancel searches the canonical chain and mempool only.
        genesis = self.svc.store.chain[0]
        fork_tx = Transaction(
            self.A,
            self.B,
            10,
            self.ka.sign(
                crypto.canonical_message(self.A, self.B, 10)
            ).hex(),
        )
        block = Block.create(
            1, genesis.block_hash, [fork_tx], STATUS_CONFIRMED
        )
        fork = [genesis, block]
        self.svc.store.forks[block.block_hash] = fork
        self.svc.store.save()
        status, body = self.cancel(fork_tx.tx_id)
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    # -- authorization ------------------------------------------------------

    def test_wrong_signer_is_403_unauthorized(self) -> None:
        _, tx = self.submit_legacy()
        status, body = self.cancel(tx["tx_id"], key=self.kb)
        self.assertEqual((status, body), (403, {"error": "unauthorized"}))
        # Nothing was removed.
        self.assertIn(tx["tx_id"], self.svc.store.pending)

    def test_malformed_signature_bytes_is_403_when_format_valid(self) -> None:
        _, tx = self.submit_legacy()
        # 128 lowercase hex that is not a valid Ed25519 signature.
        status, body = self.cancel(
            tx["tx_id"], signature="0" * 128
        )
        self.assertEqual((status, body), (403, {"error": "unauthorized"}))

    def test_signature_checked_before_cancellability(self) -> None:
        # A packed transaction with a bad signature answers 403, not 409.
        _, tx = self.submit_legacy()
        block = self.svc.mine_block()[1]
        status, body = self.cancel(tx["tx_id"], key=self.kb)
        self.assertEqual((status, body), (403, {"error": "unauthorized"}))
        self.svc.confirm_block(block["height"])
        status, body = self.cancel(tx["tx_id"], key=self.kb)
        self.assertEqual((status, body), (403, {"error": "unauthorized"}))

    # -- not cancellable ----------------------------------------------------

    def test_pending_tip_tx_is_409_not_cancellable(self) -> None:
        _, tx = self.submit_legacy()
        self.svc.mine_block()
        status, body = self.cancel(tx["tx_id"])
        self.assertEqual((status, body), (409, {"error": "not_cancellable"}))
        # It stays packed in the pending block.
        status, receipt = self.svc.get_transaction(tx["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNotNone(receipt["height"])

    def test_confirmed_tx_is_409_not_cancellable(self) -> None:
        _, tx = self.submit_legacy()
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        status, body = self.cancel(tx["tx_id"])
        self.assertEqual((status, body), (409, {"error": "not_cancellable"}))
        self.assertEqual(self.cancel_events(), [])

    # -- legacy cancellation ------------------------------------------------

    def test_legacy_cancel_success(self) -> None:
        _, other = self.submit_legacy(amount=3)
        _, tx = self.submit_legacy(amount=10)
        generation_before = self.svc.store.generation
        status, body = self.cancel(tx["tx_id"])
        self.assertEqual(
            (status, body), (200, {"tx_id": tx["tx_id"], "status": "cancelled"})
        )
        # Generation advanced exactly once.
        self.assertEqual(self.svc.store.generation, generation_before + 1)
        # The transaction is gone, other mempool transactions untouched.
        self.assertNotIn(tx["tx_id"], self.svc.store.pending)
        self.assertIn(other["tx_id"], self.svc.store.pending)
        # Single and batch receipts read as not found.
        self.assertEqual(self.svc.get_transaction(tx["tx_id"])[0], 404)
        status, batch = self.svc.get_transaction_receipts(
            {"tx_ids": [tx["tx_id"], other["tx_id"]]}
        )
        self.assertEqual(status, 200)
        items = {item["tx_id"]: item for item in batch["items"]}
        self.assertIsNone(items[tx["tx_id"]]["receipt"])
        self.assertEqual(items[tx["tx_id"]]["error"], "not_found")
        self.assertIsNotNone(items[other["tx_id"]]["receipt"])

    def test_legacy_cancel_releases_spend_reservation(self) -> None:
        # Fill the spendable balance with one queued transaction (a distinct
        # recipient keeps its tx_id different from the replacement submitted
        # after cancellation); a same-size transfer is rejected for balance
        # while it is queued and becomes acceptable once it is cancelled.
        _, tx1 = self.submit_legacy(amount=950)
        status, body = self.submit_legacy(amount=950, to=self.A)
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "insufficient balance"})
        queued = next(iter(self.svc.store.pending))
        self.assertEqual(queued, tx1["tx_id"])
        self.assertEqual(self.cancel(queued)[0], 200)
        _, tx2 = self.submit_legacy(amount=950, to=self.A)
        self.assertEqual(self.svc.get_transaction(tx2["tx_id"])[0], 200)

    def test_legacy_cancel_event_payload(self) -> None:
        _, tx = self.submit_legacy(amount=42)
        signature = cancel_signature(self.ka, tx["tx_id"])
        self.assertEqual(
            self.svc.cancel_transaction(
                tx["tx_id"], {"signature": signature}
            )[0],
            200,
        )
        events = self.cancel_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(
            {
                key: event[key]
                for key in ("tx_id", "from", "to", "amount", "signature")
            },
            {
                "tx_id": tx["tx_id"],
                "from": self.A,
                "to": self.B,
                "amount": 42,
                "signature": signature,
            },
        )
        self.assertNotIn("nonce", event)
        # Hash links stay intact.
        from ledger import audit

        audit.validate_event_chain(self.svc.store.audit_events)
        audit.validate_checkpoint(
            self.svc.store.audit_checkpoint, self.svc.store.audit_events
        )

    def test_resubmit_same_legacy_transfer_after_cancel(self) -> None:
        payload = legacy_payload(self.ka, self.A, self.B, 10)
        _, tx = self.svc.submit_transaction(payload)
        self.assertEqual(self.cancel(tx["tx_id"])[0], 200)
        # The exact original request is accepted again.
        status, again = self.svc.submit_transaction(dict(payload))
        self.assertEqual(status, 202)
        self.assertEqual(again["tx_id"], tx["tx_id"])
        # Only one cancel event (the new submission does not cancel anything
        # on its own).
        self.assertEqual(len(self.cancel_events()), 1)
        self.assertEqual(
            len(
                [
                    e
                    for e in self.svc.store.audit_events
                    if e["kind"] == EVENT_TRANSACTION_SUBMITTED
                ]
            ),
            2,
        )

    def test_confirmed_balances_unchanged_by_cancel(self) -> None:
        # Confirm a transfer first, then cancel a different queued one:
        # confirmed balances and the confirmed tx set must be unaffected.
        _, confirmed_tx = self.submit_legacy(amount=20)
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        balance_before = self.svc.confirmed_balance(self.A)
        _, queued = self.submit_legacy(amount=5)
        self.assertEqual(self.cancel(queued["tx_id"])[0], 200)
        self.assertEqual(self.svc.confirmed_balance(self.A), balance_before)
        status, receipt = self.svc.get_transaction(confirmed_tx["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")

    # -- sequenced cancellation ---------------------------------------------

    def test_sequenced_cancel_tail_releases_nonce(self) -> None:
        _, s0 = self.submit_seq(0)
        _, s1 = self.submit_seq(1, amount=7)
        status, body = self.cancel(s1["tx_id"])
        self.assertEqual(
            (status, body), (200, {"tx_id": s1["tx_id"], "status": "cancelled"})
        )
        sequence = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(sequence["next_sequence"], 1)
        self.assertEqual(
            [p["nonce"] for p in sequence["pending_sequences"]], [0]
        )
        self.assertEqual(sequence["confirmed_sequences"], [])
        # The nonce is reusable for a fresh (even different) transfer.
        _, reused = self.submit_seq(1, amount=99)
        self.assertIn(reused["tx_id"], self.svc.store.pending)
        # The cancelled id itself reads as not found.
        self.assertEqual(self.svc.get_transaction(s1["tx_id"])[0], 404)

    def test_sequenced_cancel_event_carries_nonce_and_cancel_signature(self) -> None:
        _, s1 = self.submit_seq(0)
        _, s2 = self.submit_seq(1)
        signature = cancel_signature(self.ka, s2["tx_id"])
        self.assertEqual(
            self.svc.cancel_transaction(
                s2["tx_id"], {"signature": signature}
            )[0],
            200,
        )
        events = self.cancel_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["tx_id"], s2["tx_id"])
        self.assertEqual(event["from"], self.A)
        self.assertEqual(event["to"], self.B)
        self.assertEqual(event["nonce"], 1)
        self.assertEqual(event["signature"], signature)

    def test_sequenced_non_tail_in_mempool_is_sequence_conflict(self) -> None:
        _, s0 = self.submit_seq(0)
        _, s1 = self.submit_seq(1)
        # Both queued: only nonce 1 (the highest reservation) may be cancelled.
        status, body = self.cancel(s0["tx_id"])
        self.assertEqual((status, body), (409, {"error": "sequence_conflict"}))
        self.assertIn(s0["tx_id"], self.svc.store.pending)
        self.assertEqual(self.cancel_events(), [])
        # The tail still cancels cleanly.
        self.assertEqual(self.cancel(s1["tx_id"])[0], 200)
        # Now nonce 0 is the (new) tail and cancellable.
        self.assertEqual(self.cancel(s0["tx_id"])[0], 200)

    def test_packed_sequenced_reservations_are_not_cancellable(self) -> None:
        _, s0 = self.submit_seq(0)
        _, s1 = self.submit_seq(1)
        # Pack both into the pending tip; the reservation range now spans the
        # tip (nonces 0, 1). Nothing packed is cancellable: not_cancellable
        # wins over the nonce rule.
        self.svc.mine_block()
        for tx_id in (s0["tx_id"], s1["tx_id"]):
            status, body = self.cancel(tx_id)
            self.assertEqual((status, body), (409, {"error": "not_cancellable"}))
        # A fresh mempool tail (nonce 2) is the only cancellable reservation
        # while the tip packs nonces 0 and 1.
        _, s2 = self.submit_seq(2)
        status, body = self.cancel(s0["tx_id"])
        self.assertEqual((status, body), (409, {"error": "not_cancellable"}))
        status, body = self.cancel(s1["tx_id"])
        self.assertEqual((status, body), (409, {"error": "not_cancellable"}))
        self.assertEqual(self.cancel(s2["tx_id"])[0], 200)

    def test_legacy_cancel_does_not_touch_sequences(self) -> None:
        _, s0 = self.submit_seq(0)
        _, legacy = self.submit_legacy(amount=4)
        self.assertEqual(self.cancel(legacy["tx_id"])[0], 200)
        sequence = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(sequence["next_sequence"], 1)
        self.assertEqual(
            [p["nonce"] for p in sequence["pending_sequences"]], [0]
        )

    # -- persistence failure ------------------------------------------------

    def test_keyless_persistence_failure_is_500_and_rolls_back(self) -> None:
        _, other = self.submit_legacy(amount=3)
        _, tx = self.submit_legacy(amount=10)
        pending_before = dict(self.svc.store.pending)
        generation_before = self.svc.store.generation

        def fail():
            raise OSError("disk full")

        self.svc.store.save = fail  # type: ignore[method-assign]
        status, body = self.cancel(tx["tx_id"])
        self.assertEqual((status, body), (500, {"error": "persistence failed"}))
        # Restore a working save (the failing attribute shadowed the method).
        del self.svc.store.save
        self.assertEqual(self.svc.store.pending, pending_before)
        self.assertEqual(
            list(self.svc.store.pending), list(pending_before)
        )
        self.assertEqual(self.svc.store.generation, generation_before)
        self.assertEqual(self.cancel_events(), [])
        # The request never happened: the cancel now succeeds normally.
        self.assertEqual(self.cancel(tx["tx_id"])[0], 200)
        self.assertIn(other["tx_id"], self.svc.store.pending)

    def test_idempotent_persistence_failure_is_500_and_rolls_back(self) -> None:
        _, tx = self.submit_legacy()

        def fail():
            raise OSError("disk full")

        payload = {"signature": cancel_signature(self.ka, tx["tx_id"])}

        def action():
            return self.svc.cancel_transaction(tx["tx_id"], payload)

        self.svc.store.save = fail  # type: ignore[method-assign]
        status, body, replayed, cached = self.svc.execute_idempotent(
            "POST",
            f"/v1/transactions/{tx['tx_id']}/cancel",
            "cancel-key-fail",
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            action,
            sort_keys=False,
        )
        self.assertEqual(status, 500)
        self.assertFalse(replayed)
        self.assertIsNone(cached)
        del self.svc.store.save
        self.assertIn(tx["tx_id"], self.svc.store.pending)
        self.assertEqual(self.cancel_events(), [])
        self.assertNotIn("cancel-key-fail", self.svc.store.idempotency)

    # -- restart ------------------------------------------------------------

    def test_restart_preserves_cancel_and_replay(self) -> None:
        _, legacy = self.submit_legacy(amount=6)
        _, s0 = self.submit_seq(0)
        _, s1 = self.submit_seq(1)
        legacy_sig = cancel_signature(self.ka, legacy["tx_id"])
        self.assertEqual(self.cancel(legacy["tx_id"])[0], 200)
        self.assertEqual(self.cancel(s1["tx_id"])[0], 200)

        reopened = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        self.assertNotIn(legacy["tx_id"], reopened.store.pending)
        self.assertNotIn(s1["tx_id"], reopened.store.pending)
        self.assertIn(s0["tx_id"], reopened.store.pending)
        sequence = reopened.get_account_sequence(self.A)[1]
        self.assertEqual(sequence["next_sequence"], 1)
        self.assertEqual(reopened.get_transaction(legacy["tx_id"])[0], 404)
        self.assertEqual(reopened.get_transaction(s1["tx_id"])[0], 404)
        # Both cancel events survived and chain-validate.
        cancel_events = [
            e
            for e in reopened.store.audit_events
            if e["kind"] == EVENT_TRANSACTION_CANCELLED
        ]
        self.assertEqual(len(cancel_events), 2)
        self.assertEqual(cancel_events[0]["signature"], legacy_sig)
        self.assertEqual(cancel_events[1]["nonce"], 1)
        from ledger import audit

        audit.validate_event_chain(reopened.store.audit_events)

    def test_corrupt_cancel_snapshot_fails_recovery(self) -> None:
        _, tx = self.submit_legacy()
        # Forge a transaction_cancelled event without removing the
        # transaction from the mempool: the final-state reconciliation must
        # reject the snapshot.
        self.svc.store.append_audit_event(
            EVENT_TRANSACTION_CANCELLED,
            {
                "tx_id": tx["tx_id"],
                "from": self.A,
                "to": self.B,
                "amount": 10,
                "signature": cancel_signature(self.ka, tx["tx_id"]),
            },
        )
        self.svc.store.save()
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_cancel_snapshot_with_bad_signature_fails_recovery(self) -> None:
        _, tx = self.submit_legacy()
        self.svc.store.pending.pop(tx["tx_id"])
        self.svc.store.append_audit_event(
            EVENT_TRANSACTION_CANCELLED,
            {
                "tx_id": tx["tx_id"],
                "from": self.A,
                "to": self.B,
                "amount": 10,
                "signature": cancel_signature(self.kb, tx["tx_id"]),
            },
        )
        self.svc.store.save()
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_cancel_snapshot_with_mismatched_payload_fails_recovery(self) -> None:
        _, tx = self.submit_legacy()
        self.svc.store.pending.pop(tx["tx_id"])
        self.svc.store.append_audit_event(
            EVENT_TRANSACTION_CANCELLED,
            {
                "tx_id": tx["tx_id"],
                "from": self.A,
                "to": self.B,
                "amount": 99,
                "signature": cancel_signature(self.ka, tx["tx_id"]),
            },
        )
        with self.assertRaises(StateRecoveryError):
            self.svc.store.save()
            # save() itself accepts the raw event; recovery recomputes the
            # tx_id from the payload and must reject the mismatch.
            LedgerStore(self.state_path)

    # -- forks may still contain a cancelled transaction --------------------

    def test_fork_with_cancelled_transaction_is_still_legal(self) -> None:
        _, tx = self.submit_legacy(amount=10)
        self.assertEqual(self.cancel(tx["tx_id"])[0], 200)
        # A candidate fork that includes the cancelled transaction is legal:
        # cancellation never bans the id.
        genesis = self.svc.store.chain[0]
        cancelled_tx = Transaction(
            self.A,
            self.B,
            10,
            self.ka.sign(
                crypto.canonical_message(self.A, self.B, 10)
            ).hex(),
        )
        block = Block.create(
            1, genesis.block_hash, [cancelled_tx], STATUS_CONFIRMED
        )
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [b.to_dict() for b in (genesis, block)]}
        )
        self.assertEqual(status, 201, body)
        # The candidate is still not exposed through receipts.
        self.assertEqual(self.svc.get_transaction(tx["tx_id"])[0], 404)
        # Such a snapshot (chain without the tx, fork carrying it, plus the
        # cancel event) must recover cleanly across a restart.
        LedgerStore(self.state_path)


class CancelHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "http.json")), initial_balance=1000
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

    def raw_request(
        self,
        method: str,
        path: str,
        data: bytes | None = None,
        headers: dict | None = None,
    ):
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=data,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(request) as resp:
                body = resp.read().decode()
                return (
                    resp.status,
                    body,
                    {k.lower(): v for k, v in resp.headers.items()},
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            return (
                exc.code,
                body,
                {k.lower(): v for k, v in exc.headers.items()},
            )

    def request(self, method: str, path: str, payload=None, key: str | None = None):
        data = json.dumps(payload).encode() if payload is not None else b""
        headers = {"Content-Type": "application/json"}
        if key is not None:
            headers["Idempotency-Key"] = key
        status, body, _ = self.raw_request(method, path, data, headers)
        return status, json.loads(body)

    def submit_legacy(self):
        payload = legacy_payload(self.ka, self.A, self.B, 10)
        status, body = self.request("POST", "/v1/transactions", payload)
        self.assertEqual(status, 202)
        return body["tx_id"]

    def cancel_path(self, tx_id: str) -> str:
        return f"/v1/transactions/{tx_id}/cancel"

    def test_cancel_over_http(self) -> None:
        tx_id = self.submit_legacy()
        payload = {"signature": cancel_signature(self.ka, tx_id)}
        status, body = self.request(
            "POST", self.cancel_path(tx_id), payload
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, {"tx_id": tx_id, "status": "cancelled"})
        # The receipt is gone.
        status, _ = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 404)

    def test_query_parameters_rejected(self) -> None:
        tx_id = self.submit_legacy()
        payload = {"signature": cancel_signature(self.ka, tx_id)}
        for suffix in ("?unused=1", "?unused=", "?a=1&b=2"):
            status, body, _ = self.raw_request(
                "POST",
                self.cancel_path(tx_id) + suffix,
                json.dumps(payload).encode(),
                {"Content-Type": "application/json"},
            )
            self.assertEqual((status, json.loads(body)), (400, {"error": "input"}))
        # A bare trailing "?" is accepted (carries no parameters).
        status, body, _ = self.raw_request(
            "POST",
            self.cancel_path(tx_id) + "?",
            json.dumps(payload).encode(),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200, body)

    def test_malformed_json_and_bad_shapes_are_400(self) -> None:
        tx_id = self.submit_legacy()
        for raw in (b"{", b"[]", b"null", b'{"signature": "zz"}', b'{"x":1}'):
            status, body, _ = self.raw_request(
                "POST",
                self.cancel_path(tx_id),
                raw,
                {"Content-Type": "application/json"},
            )
            self.assertEqual((status, json.loads(body)), (400, {"error": "input"}), raw)

    def test_malformed_path_tx_id_is_400_over_http(self) -> None:
        payload = {"signature": "a" * 128}
        for bad_path in ("zz", "A" * 64, "f" * 63, "f" * 65):
            status, body, _ = self.raw_request(
                "POST",
                f"/v1/transactions/{bad_path}/cancel",
                json.dumps(payload).encode(),
                {"Content-Type": "application/json"},
            )
            self.assertEqual((status, json.loads(body)), (400, {"error": "input"}))

    def test_status_codes_over_http(self) -> None:
        tx_id = self.submit_legacy()
        # Unknown id.
        unknown = "f" * 64
        status, body = self.request(
            "POST", self.cancel_path(unknown),
            {"signature": cancel_signature(self.ka, unknown)},
        )
        self.assertEqual((status, body), (404, {"error": "not_found"}))
        # Bad signature.
        status, body = self.request(
            "POST", self.cancel_path(tx_id),
            {"signature": cancel_signature(self.kb, tx_id)},
        )
        self.assertEqual((status, body), (403, {"error": "unauthorized"}))
        # Success.
        status, _ = self.request(
            "POST", self.cancel_path(tx_id),
            {"signature": cancel_signature(self.ka, tx_id)},
        )
        self.assertEqual(status, 200)
        # Keyless repeat after the fact: the transaction no longer exists.
        status, body = self.request(
            "POST", self.cancel_path(tx_id),
            {"signature": cancel_signature(self.ka, tx_id)},
        )
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_idempotency_key_replays_cached_cancel(self) -> None:
        tx_id = self.submit_legacy()
        payload = {"signature": cancel_signature(self.ka, tx_id)}
        status, body, headers = self.raw_request(
            "POST",
            self.cancel_path(tx_id),
            json.dumps(payload).encode(),
            {
                "Content-Type": "application/json",
                "Idempotency-Key": "cancel-key-1",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["idempotency-key"], "cancel-key-1")
        self.assertEqual(headers["idempotency-replayed"], "false")
        first_body = body
        # Same key, same request: cached replay, byte-identical, even though
        # the transaction is now gone.
        status, body, headers = self.raw_request(
            "POST",
            self.cancel_path(tx_id),
            json.dumps(payload).encode(),
            {
                "Content-Type": "application/json",
                "Idempotency-Key": "cancel-key-1",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["idempotency-replayed"], "true")
        self.assertEqual(body, first_body)
        cancel_events = [
            e
            for e in self.service.store.audit_events
            if e["kind"] == EVENT_TRANSACTION_CANCELLED
        ]
        self.assertEqual(len(cancel_events), 1)
        # Same key, different body: conflict.
        other_payload = {"signature": cancel_signature(self.kb, tx_id)}
        status, body, _ = self.raw_request(
            "POST",
            self.cancel_path(tx_id),
            json.dumps(other_payload).encode(),
            {
                "Content-Type": "application/json",
                "Idempotency-Key": "cancel-key-1",
            },
        )
        self.assertEqual(status, 409)

    def test_failed_cancel_occupies_no_idempotency_key(self) -> None:
        tx_id = self.submit_legacy()
        bad = {"signature": cancel_signature(self.kb, tx_id)}
        status, _, _ = self.raw_request(
            "POST",
            self.cancel_path(tx_id),
            json.dumps(bad).encode(),
            {
                "Content-Type": "application/json",
                "Idempotency-Key": "cancel-key-failed",
            },
        )
        self.assertEqual(status, 403)
        self.assertNotIn("cancel-key-failed", self.service.store.idempotency)
        # The key is still free for the successful request.
        good = {"signature": cancel_signature(self.ka, tx_id)}
        status, body, _ = self.raw_request(
            "POST",
            self.cancel_path(tx_id),
            json.dumps(good).encode(),
            {
                "Content-Type": "application/json",
                "Idempotency-Key": "cancel-key-failed",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "cancelled")


class CancelConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "c.json")), initial_balance=1000
        )

    def test_concurrent_cancel_and_mine_take_effect_in_order(self) -> None:
        payload = legacy_payload(self.ka, self.A, self.B, 10)
        _, tx = self.service.submit_transaction(payload)
        signature = cancel_signature(self.ka, tx["tx_id"])
        outcomes = []

        def cancel():
            outcomes.append(
                self.service.cancel_transaction(
                    tx["tx_id"], {"signature": signature}
                )[0]
            )

        def mine():
            outcomes.append(self.service.mine_block()[0])

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(cancel), pool.submit(mine)]
            for future in futures:
                future.result()
        # Serialized under one lock, the two operations take effect in some
        # order: cancel first -> {200, 409 (empty mempool for mine)}; mine
        # first -> {201, 409 (packed tx not cancellable)}. Exactly one 409 is
        # always reported and the transaction ends in exactly one terminal
        # state: packed, still queued never happens, or fully cancelled.
        self.assertEqual(outcomes.count(409), 1)
        self.assertTrue(outcomes[0] in (200, 201) or outcomes[1] in (200, 201))
        in_chain = any(
            candidate.tx_id == tx["tx_id"]
            for block in self.service.store.chain
            for candidate in block.transactions
        )
        in_pool = tx["tx_id"] in self.service.store.pending
        self.assertFalse(in_chain and in_pool)
        cancel_events = [
            e
            for e in self.service.store.audit_events
            if e["kind"] == EVENT_TRANSACTION_CANCELLED
        ]
        cancelled = 200 in outcomes
        self.assertEqual(len(cancel_events), 1 if cancelled else 0)
        self.assertEqual(in_chain, 201 in outcomes)
        self.assertFalse(in_pool)


if __name__ == "__main__":
    unittest.main()

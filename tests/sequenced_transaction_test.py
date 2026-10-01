"""Tests for retryable sequenced (nonce-ordered) transfers.

Covers POST /v1/transactions/sequenced and
GET /v1/accounts/{account}/sequence end to end at the service layer and over
HTTP:

* the fixed signed-message format and tx_id derivation;
* 202 on the first valid request and an idempotent 200 on an identical retry
  (queued, packed unconfirmed or confirmed), with exactly one
  transaction_submitted audit event;
* 400 {"error": "input"} for every field/type/signature/balance defect;
* 409 {"error": "sequence_conflict", "next_sequence": N} for a stale nonce, a
  gap and a different transaction on a reserved nonce;
* dense reservations that survive mining and rollback (returned in original
  order) and advance only on confirmation;
* old and new transactions mixing into one block using the existing tx_id
  ordering, block hash, Merkle root/proof and balance semantics;
* atomic snapshot persistence, restart recovery, legacy (section-less)
  snapshots and fork/sync adoption never skipping or rewinding a nonce.

Run: python3 tests/sequenced_transaction_test.py
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
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.models import Transaction
from ledger.server import build_handler
from ledger.service import (
    EVENT_TRANSACTION_SUBMITTED,
    LedgerService,
)
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def sequenced_payload(key, sender, to, amount, nonce) -> dict:
    message = crypto.sequenced_message(sender, to, amount, nonce)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(message).hex(),
    }


def legacy_payload(key, sender, to, amount) -> dict:
    message = crypto.canonical_message(sender, to, amount)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(message).hex(),
    }


class SequencedMessageTests(unittest.TestCase):
    def test_message_format_is_fixed(self) -> None:
        message = crypto.sequenced_message("alice", "bob", 12, 3)
        self.assertEqual(
            message,
            b'ledger-sequenced-transfer-v1\n{"amount":12,"from":"alice",'
            b'"nonce":3,"to":"bob"}',
        )

    def test_message_keys_sorted_amount_from_nonce_to(self) -> None:
        # The JSON document always uses the amount,from,nonce,to key order
        # regardless of insertion order, with compact separators.
        message = crypto.sequenced_message("F", "T", 1, 0)
        self.assertTrue(
            message.endswith(
                b'{"amount":1,"from":"F","nonce":0,"to":"T"}'
            )
        )
        self.assertTrue(message.startswith(b"ledger-sequenced-transfer-v1\n"))

    def test_tx_id_sha256_of_message_and_distinct_from_legacy(self) -> None:
        message = crypto.sequenced_message("alice", "bob", 12, 3)
        self.assertEqual(crypto.compute_tx_id(message), crypto.sha256_hex(message))
        legacy = crypto.canonical_message("alice", "bob", 12)
        self.assertNotEqual(crypto.compute_tx_id(message), crypto.compute_tx_id(legacy))
        # Different nonce -> different id even for the same transfer fields.
        other = crypto.sequenced_message("alice", "bob", 12, 4)
        self.assertNotEqual(
            crypto.compute_tx_id(message), crypto.compute_tx_id(other)
        )


class SequencedServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )

    def submit(self, nonce: int, amount: int = 10, key=None, sender=None, to=None):
        key = key or self.ka
        sender = sender or self.A
        to = to or self.B
        return self.svc.submit_sequenced_transaction(
            sequenced_payload(key, sender, to, amount, nonce)
        )

    def test_stranger_account_sequence_is_zero(self) -> None:
        status, body = self.svc.get_account_sequence("nobody")
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "account": "nobody",
                "next_sequence": 0,
                "pending_sequences": [],
                "confirmed_sequences": [],
            },
        )
        # Even a sender key that exists but has never sequenced starts at 0.
        status, body = self.svc.get_account_sequence(self.A)
        self.assertEqual(status, 200)
        self.assertEqual(body["next_sequence"], 0)

    def test_first_valid_returns_202_and_retry_returns_200_same_result(self) -> None:
        payload = sequenced_payload(self.ka, self.A, self.B, 10, 0)
        status, body = self.svc.submit_sequenced_transaction(payload)
        self.assertEqual(status, 202)
        self.assertEqual(set(body), {"tx_id", "nonce"})
        self.assertEqual(body["nonce"], 0)
        expected_id = crypto.compute_tx_id(
            crypto.sequenced_message(self.A, self.B, 10, 0)
        )
        self.assertEqual(body["tx_id"], expected_id)
        tx_id = body["tx_id"]

        # Identical retry: 200 with the same tx_id/nonce and no new state.
        status2, body2 = self.svc.submit_sequenced_transaction(dict(payload))
        self.assertEqual(status2, 200)
        self.assertEqual(body2, {"tx_id": tx_id, "nonce": 0})
        # Exactly one mempool entry and one audit event.
        self.assertEqual(set(self.svc.store.pending), {tx_id})
        submitted = [
            e for e in self.svc.store.audit_events
            if e["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(submitted), 1)
        self.assertEqual(submitted[0]["nonce"], 0)

    def test_retry_while_packed_in_pending_block_is_200(self) -> None:
        _, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10, 0)
        )
        tx_id = body["tx_id"]
        block = self.svc.mine_block()[1]
        # The reservation is still pending (in the unconfirmed tip).
        seq = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(seq["next_sequence"], 1)
        self.assertEqual([p["nonce"] for p in seq["pending_sequences"]], [0])
        # Retry is idempotent 200 even though it is no longer in the mempool.
        status, retry = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10, 0)
        )
        self.assertEqual(status, 200)
        self.assertEqual(retry["tx_id"], tx_id)
        # Confirm and retry again.
        self.svc.confirm_block(block["height"])
        status, retry = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10, 0)
        )
        self.assertEqual(status, 200)
        self.assertEqual(retry["tx_id"], tx_id)
        # Still exactly one submission event.
        self.assertEqual(
            len([
                e for e in self.svc.store.audit_events
                if e["kind"] == EVENT_TRANSACTION_SUBMITTED
            ]),
            1,
        )

    def test_input_validation_is_400_input(self) -> None:
        good = sequenced_payload(self.ka, self.A, self.B, 10, 0)

        def code(payload):
            return self.svc.submit_sequenced_transaction(payload)[0]

        # Not an object / missing fields.
        self.assertEqual(code("nope"), 400)
        for field in ("from", "to", "amount", "nonce", "signature"):
            broken = dict(good)
            del broken[field]
            self.assertEqual(code(broken), 400, field)
        # Empty from/to.
        broken = dict(good); broken["from"] = ""
        self.assertEqual(code(broken), 400)
        broken = dict(good); broken["to"] = ""
        self.assertEqual(code(broken), 400)
        # Amount: zero, negative, bool, float, string.
        for bad_amount in (0, -1, True, 1.5, "10"):
            broken = dict(good); broken["amount"] = bad_amount
            self.assertEqual(code(broken), 400, bad_amount)
        # Nonce: negative, bool, float, string.
        for bad_nonce in (-1, True, False, 0.0, "0"):
            broken = dict(good); broken["nonce"] = bad_nonce
            self.assertEqual(code(broken), 400, bad_nonce)
        # Empty/non-string signature.
        broken = dict(good); broken["signature"] = ""
        self.assertEqual(code(broken), 400)
        # Wrong signer and a malformed signature.
        self.assertEqual(
            code(sequenced_payload(self.kb, self.A, self.B, 10, 0)), 400
        )
        broken = dict(good); broken["signature"] = "zz"
        self.assertEqual(code(broken), 400)
        # Every error body is exactly {"error": "input"}.
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                {**good, "amount": 0}
            ),
            (400, {"error": "input"}),
        )
        # Nothing was reserved.
        self.assertEqual(self.svc.get_account_sequence(self.A)[1]["next_sequence"], 0)

    def test_insufficient_balance_is_400_input(self) -> None:
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10_000, 0)
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # A reservation that consumes most of the available balance blocks the
        # next sequenced transfer even before mining.
        self.assertEqual(self.submit(0, amount=900)[0], 202)
        self.assertEqual(self.submit(1, amount=200)[0], 400)
        # The rejected transfer occupied no nonce; nonce 1 is still next.
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 1
        )

    def test_gap_is_409_with_next_sequence(self) -> None:
        self.assertEqual(self.submit(0)[0], 202)
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 5, 2)
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body, {"error": "sequence_conflict", "next_sequence": 1}
        )
        # The gap reserved nothing; nonce 1 is accepted afterwards.
        self.assertEqual(self.submit(1)[0], 202)

    def test_stale_nonce_with_different_tx_is_409(self) -> None:
        # Confirm nonce 0, then a different transfer claiming nonce 0 is a
        # stale-nonce conflict naming the new next_sequence (1).
        self.assertEqual(self.submit(0, amount=10)[0], 202)
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 99, 0)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["next_sequence"], 1)

    def test_conflicting_different_tx_on_reserved_nonce_is_409(self) -> None:
        self.assertEqual(self.submit(0, amount=10)[0], 202)
        # Same (from, nonce) but a different amount -> different tx_id, and
        # nonce 0 is still the only reservation, so next is 1.
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 11, 0)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["next_sequence"], 1)

    def test_sequence_lists_are_ascending(self) -> None:
        for nonce in range(3):
            self.assertEqual(self.submit(nonce)[0], 202)
        body = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(
            [p["nonce"] for p in body["pending_sequences"]], [0, 1, 2]
        )
        self.assertEqual(body["confirmed_sequences"], [])
        self.assertEqual(body["next_sequence"], 3)
        # Every pending pair carries the matching tx_id.
        for pair in body["pending_sequences"]:
            self.assertEqual(set(pair), {"nonce", "tx_id"})

    def test_mining_mixes_old_and_new_and_preserves_ordering(self) -> None:
        # Two sequenced and one legacy transfer; the block must order all
        # three by tx_id exactly as before.
        _, s0 = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10, 0)
        )
        _, legacy = self.svc.submit_transaction(
            legacy_payload(self.kb, self.B, self.A, 7)
        )
        _, s1 = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 5, 1)
        )
        block = self.svc.mine_block()[1]
        expected_ids = sorted([s0["tx_id"], legacy["tx_id"], s1["tx_id"]])
        status, summary = self.svc.get_block(block["height"])
        self.assertEqual(summary["transaction_ids"], expected_ids)
        # The legacy proof behavior is unchanged: the Merkle root is computed
        # over the same ascending leaf list and, once confirmed, a proof
        # verifies against it exactly like a legacy-only block.
        self.assertEqual(summary["merkle_root"], crypto.merkle_root(expected_ids))
        self.assertEqual(self.svc.get_proof(block["height"], s0["tx_id"])[0], 409)
        self.svc.confirm_block(block["height"])
        status, proof = self.svc.get_proof(block["height"], s0["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(proof["merkle_root"], summary["merkle_root"])
        self.assertTrue(
            crypto.verify_merkle_proof(
                s0["tx_id"],
                proof["siblings"],
                proof["merkle_root"],
                proof["block_hash"],
                proof["block_hash"],
            )
        )

    def test_rollback_returns_sequenced_in_original_order_and_keeps_reservation(
        self,
    ) -> None:
        _, s0 = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10, 0)
        )
        _, s1 = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 5, 1)
        )
        block = self.svc.mine_block()[1]
        # Roll back; both sequenced transfers return to the mempool and their
        # nonces stay reserved.
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 200)
        self.assertEqual({s0["tx_id"], s1["tx_id"]}, set(self.svc.store.pending))
        body = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(body["next_sequence"], 2)
        self.assertEqual(
            [p["nonce"] for p in body["pending_sequences"]], [0, 1]
        )
        # Jumping over the still-empty nonce 2 (nonce 3) is a gap conflict;
        # next_sequence is unchanged and re-mining stays deterministic.
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                sequenced_payload(self.ka, self.A, self.B, 1, 3)
            )[0],
            409,
        )
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 2
        )
        # Re-mining is deterministic (same block hash/Merkle root).
        second = self.svc.mine_block()[1]
        self.assertEqual(second["block_hash"], block["block_hash"])
        self.assertEqual(second["merkle_root"], block["merkle_root"])

    def test_confirmation_advances_sequence(self) -> None:
        self.submit(0)
        self.submit(1)
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        body = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(body["next_sequence"], 2)
        self.assertEqual(body["pending_sequences"], [])
        self.assertEqual(
            [c["nonce"] for c in body["confirmed_sequences"]], [0, 1]
        )
        # Nonce 2 is now the only acceptable value: a different transaction
        # reusing nonce 1 conflicts (the identical nonce-1 request would be
        # an idempotent 200 replay instead).
        self.assertEqual(self.submit(2)[0], 202)
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 99, 1)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["next_sequence"], 3)

    def test_receipt_carries_nonce_for_sequenced_only(self) -> None:
        _, s0 = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10, 0)
        )
        _, legacy = self.svc.submit_transaction(
            legacy_payload(self.kb, self.B, self.A, 7)
        )
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        _, seq_receipt = self.svc.get_transaction(s0["tx_id"])
        self.assertEqual(seq_receipt["nonce"], 0)
        _, leg_receipt = self.svc.get_transaction(legacy["tx_id"])
        self.assertNotIn("nonce", leg_receipt)
        self.assertEqual(len(leg_receipt), 9)

    def test_snapshot_persists_and_restarts(self) -> None:
        self.submit(0)
        self.submit(1)
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        self.submit(2)  # left pending across restart

        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("sequences", data)

        svc2 = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        body = svc2.get_account_sequence(self.A)[1]
        self.assertEqual(body["next_sequence"], 3)
        self.assertEqual(
            [c["nonce"] for c in body["confirmed_sequences"]], [0, 1]
        )
        self.assertEqual(
            [p["nonce"] for p in body["pending_sequences"]], [2]
        )
        # Restart keeps idempotent retry semantics.
        status, _ = svc2.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 10, 0)
        )
        self.assertEqual(status, 200)

    def test_legacy_snapshot_without_section_recovers_empty_sequences(self) -> None:
        # A normal ledger with only legacy transactions never writes a
        # sequences section; restart must recover an empty sequence view.
        self.svc.submit_transaction(legacy_payload(self.kb, self.B, self.A, 7))
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertNotIn("sequences", data)
        svc2 = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        self.assertEqual(svc2.store.sequences, {})
        self.assertEqual(
            svc2.get_account_sequence(self.B)[1]["next_sequence"], 0
        )

    def test_legacy_manual_snapshot_with_sequenced_tx_but_no_section_fails(
        self,
    ) -> None:
        from ledger.models import STATUS_CONFIRMED, Block

        tx = Transaction(
            self.A,
            self.B,
            10,
            self.ka.sign(
                crypto.sequenced_message(self.A, self.B, 10, 0)
            ).hex(),
            0,
        )
        block = Block.create(
            1,
            self.svc.store.chain[0].block_hash,
            [tx],
            STATUS_CONFIRMED,
        )
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["chain"].append(block.to_dict())
        data["state"]["height"] = 1
        data["state"]["tip_hash"] = block.block_hash
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(ValueError):
            LedgerStore(self.state_path)

    def test_candidate_chain_with_nonce_gap_is_rejected(self) -> None:
        from ledger.models import STATUS_CONFIRMED, Block

        # A valid nonce 0 on the canonical chain ...
        self.submit(0)
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])

        # ... then a candidate that jumps straight to nonce 5 must be refused.
        g = self.svc.store.chain[0]
        tx = Transaction(
            self.A,
            self.B,
            1,
            self.ka.sign(
                crypto.sequenced_message(self.A, self.B, 1, 5)
            ).hex(),
            5,
        )
        bad = Block.create(1, g.block_hash, [tx], STATUS_CONFIRMED)
        with self.assertRaises(ValueError):
            self.svc.store.validate_fork_blocks(
                [b.to_dict() for b in (g, bad)]
            )

    def test_fork_adoption_never_skips_or_rewinds_sequence(self) -> None:
        from ledger.models import STATUS_CONFIRMED, Block

        def confirmed_seq(nonce, amount):
            tx = Transaction(
                self.A,
                self.B,
                amount,
                self.ka.sign(
                    crypto.sequenced_message(self.A, self.B, amount, nonce)
                ).hex(),
                nonce,
            )
            self.svc.store.pending[tx.tx_id] = tx
            self.svc.store.append_audit_event(
                EVENT_TRANSACTION_SUBMITTED,
                {
                    "tx_id": tx.tx_id,
                    "from": self.A,
                    "to": self.B,
                    "amount": amount,
                    "nonce": nonce,
                },
            )
            self.svc.store.save()
            blk = self.svc.mine_block()[1]
            self.svc.confirm_block(blk["height"])
            return tx

        t0 = confirmed_seq(0, 1)
        t1 = confirmed_seq(1, 1)
        t2 = confirmed_seq(2, 1)
        self.assertEqual(self.svc.get_account_sequence(self.A)[1]["next_sequence"], 3)

        # Build a strictly longer competing fork: a different nonce-0 transfer
        # at height 1 then legacy filler blocks.
        genesis = self.svc.store.chain[0]

        def legacy_block(prev, height, amount):
            tx = Transaction(
                self.B,
                self.A,
                amount,
                self.kb.sign(
                    crypto.canonical_message(self.B, self.A, amount)
                ).hex(),
            )
            return Block.create(height, prev, [tx], STATUS_CONFIRMED)

        t0f = Transaction(
            self.A,
            self.B,
            2,
            self.ka.sign(
                crypto.sequenced_message(self.A, self.B, 2, 0)
            ).hex(),
            0,
        )
        b1 = Block.create(1, genesis.block_hash, [t0f], STATUS_CONFIRMED)
        b2 = legacy_block(b1.block_hash, 2, 1)
        b3 = legacy_block(b2.block_hash, 3, 2)
        b4 = legacy_block(b3.block_hash, 4, 3)
        fork = [genesis, b1, b2, b3, b4]
        self.svc.store.validate_fork_blocks([b.to_dict() for b in fork])
        tip = fork[-1].block_hash
        self.svc.store.forks[tip] = fork
        self.svc.store.save()
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)

        body = self.svc.get_account_sequence(self.A)[1]
        # The adopted fork confirms nonce 0 (under a different tx); the
        # superseded nonces 1 and 2 return to the mempool still reserved, so
        # next_sequence never moves backwards (it stays 3) and never skips.
        self.assertEqual(body["next_sequence"], 3)
        self.assertEqual(
            [c["tx_id"] for c in body["confirmed_sequences"]], [t0f.tx_id]
        )
        self.assertEqual(
            sorted(p["tx_id"] for p in body["pending_sequences"]),
            sorted([t1.tx_id, t2.tx_id]),
        )
        self.assertNotIn(t0.tx_id, self.svc.store.pending)
        # The stale nonce-0 transfer is a conflict; nonce 3 is the next legal
        # value, and retries of t1/t2 replay as 200.
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                sequenced_payload(self.ka, self.A, self.B, 1, 0)
            )[0],
            409,
        )
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                sequenced_payload(self.ka, self.A, self.B, 1, 1)
            )[0],
            200,
        )
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                sequenced_payload(self.ka, self.A, self.B, 1, 3)
            )[0],
            202,
        )

    def test_get_sequence_rejects_non_string_account(self) -> None:
        self.assertEqual(self.svc.get_account_sequence("")[0], 400)
        self.assertEqual(self.svc.get_account_sequence(7)[0], 400)


class SequencedHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method: str, path: str, payload=None):
        url = f"{self.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_endpoints_over_http(self) -> None:
        # Stranger.
        status, body = self.request("GET", f"/v1/accounts/{self.A}/sequence")
        self.assertEqual(status, 200)
        self.assertEqual(body["next_sequence"], 0)

        # First 202 then 200.
        payload = sequenced_payload(self.ka, self.A, self.B, 10, 0)
        status, first = self.request(
            "POST", "/v1/transactions/sequenced", payload
        )
        self.assertEqual(status, 202)
        status, retry = self.request(
            "POST", "/v1/transactions/sequenced", payload
        )
        self.assertEqual(status, 200)
        self.assertEqual(retry, first)

        # Gap 409 carries next_sequence.
        status, body = self.request(
            "POST",
            "/v1/transactions/sequenced",
            sequenced_payload(self.ka, self.A, self.B, 5, 9),
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body, {"error": "sequence_conflict", "next_sequence": 1}
        )

        # Bad input.
        status, body = self.request(
            "POST",
            "/v1/transactions/sequenced",
            {**payload, "nonce": True},
        )
        self.assertEqual((status, body), (400, {"error": "input"}))

        # Query parameters are rejected on the sequence endpoint.
        status, _ = self.request(
            "GET", f"/v1/accounts/{self.A}/sequence?unused=1"
        )
        self.assertEqual(status, 400)

    def test_legacy_endpoint_unchanged(self) -> None:
        # A legacy transfer still submits and lands on the old endpoint with
        # no nonce handling.
        payload = legacy_payload(self.kb, self.B, self.A, 3)
        status, body = self.request("POST", "/v1/transactions", payload)
        self.assertEqual(status, 202)
        self.assertNotIn("nonce", body)


if __name__ == "__main__":
    unittest.main()

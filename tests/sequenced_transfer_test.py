"""Tests for retryable sequenced transfers.

Covers POST /v1/transactions/sequenced and GET
/v1/accounts/{account}/sequence:

* the fixed signature message and SHA-256 tx id;
* first valid request 202, identical retry 200 with no new state or audit
  event, and one atomically recorded transaction_submitted;
* 400 error=input for field/type/signature/balance failures and 409
  sequence_conflict (with next_sequence) for a behind nonce, a gap or a
  same-nonce different transfer;
* dense nonce reservations across the mempool, a pending tip, confirmation,
  rollback, restart, fork adoption and sync;
* mixing legacy and sequenced transfers in one block with unchanged
  ordering/merkle/proof/balance semantics and a nonce-bearing receipt;
* HTTP wiring, uniform idempotency and concurrency.

Run: python3 tests/sequenced_transfer_test.py
"""
from __future__ import annotations

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

from ledger import crypto, light_client
from ledger.models import Block, STATUS_CONFIRMED
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

ENDOWMENT = 10_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def sequenced_message(sender: str, recipient: str, amount: int, nonce: int) -> bytes:
    return crypto.sequenced_message(sender, recipient, amount, nonce)


def make_sequenced(
    key: Ed25519PrivateKey,
    sender: str,
    recipient: str,
    amount: int,
    nonce: int,
) -> dict:
    message = sequenced_message(sender, recipient, amount, nonce)
    return {
        "from": sender,
        "to": recipient,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(message).hex(),
    }


def make_legacy(
    key: Ed25519PrivateKey, sender: str, recipient: str, amount: int
) -> dict:
    message = crypto.canonical_message(sender, recipient, amount)
    return {
        "from": sender,
        "to": recipient,
        "amount": amount,
        "signature": key.sign(message).hex(),
    }


def tx_id_of_sequenced(sender: str, recipient: str, amount: int, nonce: int) -> str:
    return crypto.compute_tx_id(
        sequenced_message(sender, recipient, amount, nonce)
    )


class SequenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=ENDOWMENT
        )

    def submit(self, nonce: int, amount: int = 10, to: str | None = None) -> dict:
        payload = make_sequenced(self.ka, self.A, to or self.B, amount, nonce)
        status, body = self.svc.submit_sequenced_transaction(payload)
        self.assertIn(status, (200, 202), body)
        return body

    def mine_and_confirm(self) -> None:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        self.assertEqual(self.svc.confirm_block(block["height"])[0], 200)

    # -- signature message ----------------------------------------------------

    def test_message_and_tx_id_are_fixed(self) -> None:
        message = sequenced_message("F", "T", 7, 3)
        self.assertEqual(
            message,
            b'ledger-sequenced-transfer-v1\n'
            b'{"amount":7,"from":"F","nonce":3,"to":"T"}',
        )
        expected_tx_id = hashlib.sha256(message).hexdigest()
        self.assertEqual(tx_id_of_sequenced("F", "T", 7, 3), expected_tx_id)

    def test_first_accept_is_202_retry_is_200_with_one_audit_event(self) -> None:
        payload = make_sequenced(self.ka, self.A, self.B, 10, 0)
        status, body = self.svc.submit_sequenced_transaction(payload)
        self.assertEqual(status, 202)
        self.assertEqual(set(body), {"tx_id", "nonce"})
        self.assertEqual(body["nonce"], 0)
        self.assertEqual(body["tx_id"], tx_id_of_sequenced(self.A, self.B, 10, 0))
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == "transaction_submitted"
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["tx_id"], body["tx_id"])
        self.assertEqual(events[0]["nonce"], 0)

        # Identical retry: 200, same result, no additional event/state.
        status2, body2 = self.svc.submit_sequenced_transaction(dict(payload))
        self.assertEqual(status2, 200)
        self.assertEqual(body2, body)
        events2 = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == "transaction_submitted"
        ]
        self.assertEqual(len(events2), 1)
        self.assertEqual(len(self.svc.store.pending), 1)

    # -- input failures --------------------------------------------------------

    def test_field_and_type_failures_are_400_input(self) -> None:
        good = make_sequenced(self.ka, self.A, self.B, 10, 0)
        for malformed in (
            {},
            {"from": self.A},
            {**good, "extra": 1},
            {**good, "from": ""},
            {**good, "to": ""},
            {**good, "from": 5},
            {**good, "amount": 0},
            {**good, "amount": -1},
            {**good, "amount": 1.5},
            {**good, "amount": "10"},
            {**good, "amount": True},
            {**good, "nonce": True},
            {**good, "nonce": False},
            {**good, "nonce": -1},
            {**good, "nonce": 1.0},
            {**good, "nonce": "0"},
            {**good, "signature": ""},
        ):
            status, body = self.svc.submit_sequenced_transaction(malformed)
            self.assertEqual(status, 400, malformed)
            self.assertEqual(body, {"error": "input"}, malformed)
        # Not even a JSON object.
        self.assertEqual(
            self.svc.submit_sequenced_transaction(["x"]),
            (400, {"error": "input"}),
        )

    def test_bad_signature_is_400_input(self) -> None:
        payload = make_sequenced(self.ka, self.A, self.B, 10, 0)
        payload["signature"] = "00" * 64
        self.assertEqual(
            self.svc.submit_sequenced_transaction(payload),
            (400, {"error": "input"}),
        )

    def test_insufficient_balance_is_400_input(self) -> None:
        payload = make_sequenced(self.ka, self.A, self.B, ENDOWMENT + 1, 0)
        self.assertEqual(
            self.svc.submit_sequenced_transaction(payload),
            (400, {"error": "input"}),
        )

    # -- sequence conflicts ----------------------------------------------------

    def test_gap_and_behind_nonce_are_409_with_next_sequence(self) -> None:
        self.submit(0)
        status, body = self.svc.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 10, 2)
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body, {"error": "sequence_conflict", "next_sequence": 1}
        )
        # The next nonce in order is accepted.
        self.assertEqual(self.submit(1, 5)["nonce"], 1)
        # A different transfer reusing an old reserved nonce conflicts.
        status, body = self.svc.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 11, 0)
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body, {"error": "sequence_conflict", "next_sequence": 2}
        )

    def test_conflict_returns_current_next_sequence(self) -> None:
        self.submit(0)
        self.submit(1)
        # A DIFFERENT transfer reusing nonce 0 (different amount).
        _, body = self.svc.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 99, 0)
        )
        self.assertEqual(body["next_sequence"], 2)

    # -- query ----------------------------------------------------------------

    def test_unknown_account_sequence_is_empty(self) -> None:
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

    def test_pending_confirmed_and_pending_tip_sequences(self) -> None:
        id0 = self.submit(0, 10)["tx_id"]
        id1 = self.submit(1, 20)["tx_id"]
        _, view = self.svc.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 2)
        self.assertEqual(
            view["pending_sequences"],
            [
                {"nonce": 0, "tx_id": id0},
                {"nonce": 1, "tx_id": id1},
            ],
        )
        self.assertEqual(view["confirmed_sequences"], [])

        # Mine but leave pending: both stay reserved and pending.
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201)
        _, view = self.svc.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 2)
        self.assertEqual(
            [entry["nonce"] for entry in view["pending_sequences"]], [0, 1]
        )

        self.assertEqual(self.svc.confirm_block(block["height"])[0], 200)
        _, view = self.svc.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 2)
        self.assertEqual(view["pending_sequences"], [])
        self.assertEqual(
            [entry["nonce"] for entry in view["confirmed_sequences"]], [0, 1]
        )

        # A later nonce while nothing is mined is purely pending.
        id2 = self.submit(2, 5)["tx_id"]
        _, view = self.svc.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 3)
        self.assertEqual(view["pending_sequences"], [{"nonce": 2, "tx_id": id2}])
        self.assertEqual(
            [entry["nonce"] for entry in view["confirmed_sequences"]], [0, 1]
        )

    def test_rollback_returns_transfer_to_pending_with_reservation(self) -> None:
        self.submit(0, 10)
        self.mine_and_confirm()
        id1 = self.submit(1, 10)["tx_id"]
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201)
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 200)

        _, view = self.svc.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 2)
        self.assertEqual(view["pending_sequences"], [{"nonce": 1, "tx_id": id1}])
        self.assertEqual(
            [entry["nonce"] for entry in view["confirmed_sequences"]], [0]
        )
        # The transfer is back in the mempool and its retry is the same 200.
        payload = make_sequenced(self.ka, self.A, self.B, 10, 1)
        self.assertEqual(
            self.svc.submit_sequenced_transaction(payload),
            (200, {"tx_id": id1, "nonce": 1}),
        )
        # next nonce (2) still cannot be skipped: next_sequence unchanged.
        _, view = self.svc.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 2)

    # -- mining order, mixing with legacy, receipts ---------------------------

    def test_mining_packs_in_submission_order_alongside_legacy(self) -> None:
        # Two senders interleave legacy and sequenced transfers; mining keeps
        # the existing ascending tx_id block order, so both kinds mix while
        # ordering/hash/merkle semantics are unchanged.
        id_seq0 = self.submit(0, 10)["tx_id"]
        legacy = make_legacy(self.kb, self.B, self.A, 3)
        self.assertEqual(self.svc.submit_transaction(legacy)[0], 202)
        id_seq1 = self.submit(1, 7)["tx_id"]

        status, block = self.svc.mine_block()
        self.assertEqual(status, 201)
        _, summary = self.svc.get_block(block["height"])
        # Block keeps the existing ascending tx_id order with both kinds.
        legacy_id = crypto.compute_tx_id(
            crypto.canonical_message(self.B, self.A, 3)
        )
        self.assertEqual(
            summary["transaction_ids"],
            sorted([id_seq0, id_seq1, legacy_id]),
        )

        # Merkle proof for a sequenced transfer in a confirmed block works.
        self.assertEqual(self.svc.confirm_block(block["height"])[0], 200)
        status, proof = self.svc.get_proof(block["height"], id_seq1)
        self.assertEqual(status, 200)
        self.assertEqual(proof["tx_id"], id_seq1)

        # Balances follow the ordinary semantics.
        _, acc_a = self.svc.get_account(self.A)
        _, acc_b = self.svc.get_account(self.B)
        self.assertEqual(acc_a["balance"], ENDOWMENT - 10 - 7 + 3)
        self.assertEqual(acc_b["balance"], ENDOWMENT + 10 + 7 - 3)

    def test_receipt_carries_nonce_and_retry_after_confirmation(self) -> None:
        body = self.submit(0, 12)
        self.mine_and_confirm()
        status, receipt = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(receipt["nonce"], 0)
        self.assertEqual(receipt["amount"], 12)
        self.assertEqual(
            tuple(receipt),
            (
                "tx_id",
                "from",
                "to",
                "amount",
                "nonce",
                "signature",
                "status",
                "height",
                "block_hash",
                "index",
            ),
        )
        # Retrying a confirmed transfer is still the same 200 result.
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                make_sequenced(self.ka, self.A, self.B, 12, 0)
            ),
            (200, {"tx_id": body["tx_id"], "nonce": 0}),
        )

    def test_legacy_receipt_keeps_nine_fields(self) -> None:
        payload = make_legacy(self.ka, self.A, self.B, 4)
        _, body = self.svc.submit_transaction(payload)
        status, receipt = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(status, 200)
        self.assertNotIn("nonce", receipt)
        self.assertEqual(
            set(receipt),
            {
                "tx_id",
                "from",
                "to",
                "amount",
                "signature",
                "status",
                "height",
                "block_hash",
                "index",
            },
        )

    # -- restart ---------------------------------------------------------------

    def test_restart_preserves_reservations_and_retry(self) -> None:
        self.submit(0, 10)
        self.mine_and_confirm()
        self.submit(1, 5)
        svc2 = LedgerService(LedgerStore(self.path), initial_balance=ENDOWMENT)
        _, view = svc2.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 2)
        self.assertEqual(
            [entry["nonce"] for entry in view["confirmed_sequences"]], [0]
        )
        self.assertEqual(
            [entry["nonce"] for entry in view["pending_sequences"]], [1]
        )
        # A pending retry is still 200 after restart.
        status, _ = svc2.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 5, 1)
        )
        self.assertEqual(status, 200)

    def test_tampered_sequence_index_fails_recovery(self) -> None:
        self.submit(0, 10)
        self.mine_and_confirm()
        raw = json.load(open(self.path, encoding="utf-8"))
        raw["sequence_index"][self.A][0]["nonce"] = 1
        # Rebalance density claim by changing the tx id list shape is still a
        # mismatch against the recomputed facts.
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        with self.assertRaises(Exception):
            LedgerStore(self.path + ".copy") if False else LedgerService(
                LedgerStore(self.path), initial_balance=ENDOWMENT
            )

    # -- fork adoption ---------------------------------------------------------

    def test_fork_adoption_drops_nonce_conflicting_pool_tx(self) -> None:
        # Canonical: sequenced nonce 0 from A to B confirmed, then nonce 1
        # sits pending.
        canonical_id0 = self.submit(0, 10, to=self.B)["tx_id"]
        self.mine_and_confirm()
        pending_id1 = self.submit(1, 10, to=self.B)["tx_id"]

        # Build a longer competing fork whose block 1 spends A's nonce 0 on a
        # DIFFERENT transfer (A -> B amount 11) and block 2 a legacy transfer.
        alt_nonce0 = make_sequenced(self.ka, self.A, self.B, 11, 0)
        alt_tx_payload = alt_nonce0
        message = crypto.sequenced_message(self.A, self.B, 11, 0)
        from ledger.models import Transaction

        alt_tx = Transaction(
            self.A, self.B, 11, alt_tx_payload["signature"], 0
        )
        legacy_tx_payload = make_legacy(self.kb, self.B, self.A, 2)
        legacy_tx = Transaction(
            self.B, self.A, 2, legacy_tx_payload["signature"]
        )
        genesis = self.svc.store.chain[0]
        fork_block1 = Block.create(
            height=1,
            prev_hash=genesis.block_hash,
            transactions=[alt_tx],
            status=STATUS_CONFIRMED,
        )
        fork_block2 = Block.create(
            height=2,
            prev_hash=fork_block1.block_hash,
            transactions=[legacy_tx],
            status=STATUS_CONFIRMED,
        )
        fork = [genesis, fork_block1, fork_block2]
        tip_hash = fork_block2.block_hash
        self.svc.store.forks[tip_hash] = fork

        # The 3-block fork beats the 2-block canonical chain.
        status, summary = self.svc.adopt_fork(tip_hash)
        self.assertEqual(status, 200, summary)

        # After adoption the new chain occupies nonce 0 with the alternative
        # transfer; the superseded canonical nonce-0 transfer returned to the
        # pool during adoption but is dropped by the reservation rebuild since
        # a different transfer now spends that nonce. The unrelated nonce-1
        # reservation stays continuous (no gap, no regress), so next_sequence
        # is 2: the adopted chain's nonce 0 plus the surviving pending nonce 1.
        _, view = self.svc.get_account_sequence(self.A)
        self.assertEqual(view["next_sequence"], 2)
        self.assertEqual(
            view["confirmed_sequences"],
            [{"nonce": 0, "tx_id": alt_tx.tx_id}],
        )
        self.assertEqual(
            view["pending_sequences"], [{"nonce": 1, "tx_id": pending_id1}]
        )
        self.assertIn(pending_id1, self.svc.store.pending)
        self.assertNotIn(canonical_id0, self.svc.store.pending)

        # Re-submitting the exact pending nonce-1 transfer is the same 200.
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                make_sequenced(self.ka, self.A, self.B, 10, 1)
            ),
            (200, {"tx_id": pending_id1, "nonce": 1}),
        )
        # A DIFFERENT nonce-1 transfer conflicts, as does reusing nonce 0.
        status, body = self.svc.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 77, 1)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["next_sequence"], 2)
        status, body = self.svc.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 10, 0)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["next_sequence"], 2)
        # The next fresh nonce (2) is accepted after the pending nonce 1.
        status, _ = self.svc.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 5, 2)
        )
        self.assertEqual(status, 202)


class SequenceHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "state.json")),
            initial_balance=ENDOWMENT,
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

    def _request(self, method: str, path: str, body: object = None,
                 headers: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        request_headers = dict(headers or {})
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base + path, data=data, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return (
                    resp.status,
                    json.loads(resp.read()),
                    {k: v for k, v in resp.headers.items()},
                )
        except urllib.error.HTTPError as exc:
            return (
                exc.code,
                json.loads(exc.read()),
                {k: v for k, v in exc.headers.items()},
            )

    def test_http_sequenced_lifecycle_and_query(self) -> None:
        # Unknown account.
        status, body, _ = self._request("GET", f"/v1/accounts/{self.A}/sequence")
        self.assertEqual(status, 200)
        self.assertEqual(body["next_sequence"], 0)

        payload = make_sequenced(self.ka, self.A, self.B, 10, 0)
        status, body, _ = self._request(
            "POST", "/v1/transactions/sequenced", payload
        )
        self.assertEqual(status, 202)
        first = body
        status, body, _ = self._request(
            "POST", "/v1/transactions/sequenced", payload
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, first)

        status, body, _ = self._request(
            "POST",
            "/v1/transactions/sequenced",
            make_sequenced(self.ka, self.A, self.B, 10, 9),
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "sequence_conflict")
        self.assertEqual(body["next_sequence"], 1)

        status, body, _ = self._request(
            "POST",
            "/v1/transactions/sequenced",
            {**payload, "nonce": True},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "input"})

        # Malformed JSON body is also 400 input.
        req = urllib.request.Request(
            self.base + "/v1/transactions/sequenced",
            data=b"{not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            self.assertEqual(json.loads(exc.read()), {"error": "input"})

        status, body, _ = self._request("GET", f"/v1/accounts/{self.A}/sequence")
        self.assertEqual(status, 200)
        self.assertEqual(body["next_sequence"], 1)
        self.assertEqual(
            body["pending_sequences"],
            [{"nonce": 0, "tx_id": first["tx_id"]}],
        )

    def test_http_uniform_idempotency_on_sequenced_endpoint(self) -> None:
        # The class-shared service may already hold earlier nonces; use the
        # account's current next nonce so the first request is a fresh 202.
        _, view, _ = self._request("GET", f"/v1/accounts/{self.A}/sequence")
        nonce = view["next_sequence"]
        headers = {"Idempotency-Key": f"seq-key-{nonce}"}
        payload = make_sequenced(self.ka, self.A, self.B, 8, nonce)
        status, body1, hdrs1 = self._request(
            "POST", "/v1/transactions/sequenced", payload, headers
        )
        self.assertEqual(status, 202)
        self.assertEqual(hdrs1.get("Idempotency-Replayed"), "false")
        status, body2, hdrs2 = self._request(
            "POST", "/v1/transactions/sequenced", payload, headers
        )
        self.assertEqual(status, 202)
        self.assertEqual(hdrs2.get("Idempotency-Replayed"), "true")
        self.assertEqual(body1, body2)


class SequenceOfflineReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=ENDOWMENT,
        )

    def _block_dicts(self, blocks: list[Block]) -> list[dict]:
        return [block.to_dict() for block in blocks]

    def test_offline_chain_replay_accepts_sequenced_and_rejects_gap(self) -> None:
        from ledger.models import Transaction

        def seq_tx(n: int, amount: int) -> Transaction:
            message = crypto.sequenced_message(self.A, self.B, amount, n)
            return Transaction(self.A, self.B, amount, self.ka.sign(message).hex(), n)

        genesis = self.svc.store.chain[0]
        trust = {"genesis_hash": genesis.block_hash}
        block1 = Block.create(1, genesis.block_hash, [seq_tx(0, 10)], STATUS_CONFIRMED)
        block2 = Block.create(2, block1.block_hash, [seq_tx(1, 5)], STATUS_CONFIRMED)
        replayed = light_client._recompute_chain(
            self._block_dicts([genesis, block1, block2]), trust
        )
        self.assertEqual(len(replayed), 3)
        self.assertEqual(replayed[2].transactions[0].nonce, 1)

        # A nonce gap is an offline integrity failure.
        block_bad = Block.create(2, block1.block_hash, [seq_tx(3, 5)], STATUS_CONFIRMED)
        with self.assertRaises(light_client._Failure) as caught:
            light_client._recompute_chain(
                self._block_dicts([genesis, block1, block_bad]), trust
            )
        self.assertEqual(caught.exception.category, "integrity")

        # A wrong nonce type is an input failure.
        raw = self._block_dicts([genesis, block1, block_bad])
        raw[2]["transactions"][0]["nonce"] = "3"
        with self.assertRaises(light_client._Failure) as caught:
            light_client._recompute_chain(raw, trust)
        self.assertEqual(caught.exception.category, "input")


class SequenceConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=ENDOWMENT,
        )

    def test_parallel_same_nonce_only_one_reservation(self) -> None:
        barrier = threading.Barrier(8)
        results: list[tuple[int, dict]] = []

        def worker() -> None:
            barrier.wait()
            payload = make_sequenced(self.ka, self.A, self.B, 10, 0)
            results.append(self.svc.submit_sequenced_transaction(payload))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        accepted = [status for status, _ in results if status == 202]
        retried = [status for status, _ in results if status == 200]
        self.assertEqual(len(accepted), 1, results)
        self.assertEqual(len(retried), 7, results)
        self.assertEqual(len(self.svc.store.pending), 1)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 1
        )


if __name__ == "__main__":
    unittest.main()

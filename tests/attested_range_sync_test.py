"""Tests for the signature-attested incremental range sync.

Covers POST /v1/forks/sync/range/attested: envelope strict validation (400,
including the closed four-field tip and the 128-lowercase-hex signature),
new-request precedence 400 structure -> 403 authorization -> 410 expiry ->
403 signature verification -> 409 stale anchor -> 400 assembled whole-chain /
tip re-validation -> 409 duplicate tip; 201 returning S plus expires_at, the
frozen public key/version/signature/signed-range record and a mode="attested"
sync_received event in one atomic write; same-key retries bypassing
authorization/expiry and re-verifying against the FROZEN key (wrong signature
403, malformed body 400, different validly-signed content 409, identical
content 200 with the original expires_at, surviving rotation/revocation);
attested idempotency namespace independent of the plain range endpoint;
adoption/expiry lifecycle (mode="attested" events), save-failure rollback,
restart persistence with standalone signature/fingerprint re-verification and
silent tamper pruning; inclusion in the attested/all syncs and history
listings; plus the HTTP surface and the sync-range-attested CLI subcommand
(64-hex seed, JSON document or -, canonical signing, single-line JSON, exit 1
on non-2xx).

Run: python3 tests/attested_range_sync_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import STATUS_PENDING, Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import (
    LedgerStore,
    attested_range_fingerprint,
    attested_range_message,
)


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def seed_of(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(signed_tx(key, sender, to, amount))


def make_tail(
    prev_hash: str, start_height: int, specs, pending_last: bool = False
) -> list[Block]:
    """Build a linked list of blocks from (key, sender, recipient, amount) specs."""
    blocks: list[Block] = []
    prev = prev_hash
    for i, group in enumerate(specs):
        txs = [tx_obj(k, s, r, a) for (k, s, r, a) in group]
        status = STATUS_PENDING if pending_last and i == len(specs) - 1 else "confirmed"
        block = Block.create(start_height + i, prev, txs, status)
        blocks.append(block)
        prev = block.block_hash
    return blocks


class AttestedRangeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "arange.json")
        self.store = LedgerStore(self.path, initial_balance=1_000_000)
        self.service = LedgerService(self.store, initial_balance=1_000_000)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.exp = int(time.time()) + 10_000_000
        # A confirmed chain 0..3 on the receiver.
        for amount in (10, 20, 30):
            self.assertEqual(
                self.service.submit_transaction(
                    signed_tx(self.ka, self.A, self.B, amount)
                )[0],
                202,
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0], 200
            )
        self.assertEqual(
            self.service.register_trust_source(
                {"source": "node-x", "public_key": self.A, "expires_at": self.exp}
            )[0],
            201,
        )

    def _tail(self, anchor_height: int = 1, n: int = 1) -> list[Block]:
        amounts = [40, 5, 7]
        specs = [
            [(self.ka, self.A, self.B, amounts[i % len(amounts)] + i)]
            for i in range(n)
        ]
        return make_tail(
            self.store.chain[anchor_height].block_hash,
            anchor_height + 1,
            specs,
        )

    def _payload(
        self,
        anchor_height: int,
        tail: list[Block],
        seed: str,
        *,
        request_id: str = "r1",
        source: str = "node-x",
        expires_at: int | None = None,
        sign: bool = True,
    ) -> dict:
        end = tail[-1]
        blocks = [b.to_dict() for b in tail]
        anchor = {
            "height": anchor_height,
            "block_hash": self.store.chain[anchor_height].block_hash,
        }
        tip = {
            "tip_hash": end.block_hash,
            "height": end.height,
            "length": anchor_height + 1 + len(tail),
            "status": end.status,
        }
        deadline = self.exp if expires_at is None else expires_at
        signature = "0" * 128
        if sign:
            message = attested_range_message(
                source, request_id, deadline, anchor, blocks, tip
            )
            signature = crypto.sign_message(
                seed, hashlib.sha256(message).digest()
            )
            self.assertIsNotNone(signature)
        return {
            "source": source,
            "request_id": request_id,
            "expires_at": deadline,
            "anchor": anchor,
            "blocks": blocks,
            "tip": tip,
            "signature": signature,
        }

    def _submit(self, anchor_height: int = 1, n: int = 1, **kw) -> tuple[int, dict]:
        seed = kw.pop("seed", seed_of(self.ka))
        tail = kw.pop("tail", None) or self._tail(anchor_height, n)
        payload = self._payload(anchor_height, tail, seed, **kw)
        return self.service.submit_fork_sync_range_attested(payload)

    # -- acceptance -----------------------------------------------------------

    def test_valid_attested_range_returns_201_and_persists(self) -> None:
        tail = self._tail(1, 2)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="ok")
        status, body = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["height"], 3)
        self.assertEqual(body["length"], 4)
        self.assertEqual(body["status"], "confirmed")
        self.assertEqual(body["expires_at"], self.exp)
        self.assertEqual(body["tip_hash"], tail[-1].block_hash)
        # The assembled candidate (genesis..tip) is stored for adoption.
        self.assertIn(body["tip_hash"], self.store.forks)
        self.assertEqual(len(self.store.forks[body["tip_hash"]]), 4)
        # The attested record freezes key/version/signature and the signed
        # range in its delivered original form.
        key = ("node-x", "ok")
        self.assertIn(key, self.store.attested_syncs)
        self.assertNotIn(key, self.store.syncs)
        rec = self.store.attested_syncs[key]
        self.assertEqual(rec["tip_hash"], body["tip_hash"])
        att = rec["attested"]
        self.assertEqual(att["public_key"], self.A)
        self.assertEqual(att["version"], 1)
        self.assertEqual(att["signature"], payload["signature"])
        self.assertEqual(att["range"]["anchor"], payload["anchor"])
        self.assertEqual(att["range"]["blocks"], payload["blocks"])
        self.assertEqual(att["range"]["tip"], payload["tip"])
        self.assertNotIn("candidate", att)
        self.assertEqual(
            rec["fingerprint"],
            attested_range_fingerprint(
                "node-x", "ok", self.exp, payload["anchor"], payload["blocks"],
                payload["tip"], payload["signature"],
            ),
        )
        # A mode="attested" sync_received event landed in the same write.
        event = self.store.audit_events[-1]
        self.assertEqual(event["kind"], "sync_received")
        self.assertEqual(event["mode"], "attested")
        self.assertEqual(event["request_id"], "ok")

    def test_assembled_candidate_adopts_with_attested_event(self) -> None:
        # Strictly longer alternative anchored at block 1: 2',3',4'.
        tail = make_tail(
            self.store.chain[1].block_hash,
            2,
            [
                [(self.ka, self.A, self.B, 40)],
                [(self.kb, self.B, self.A, 5)],
                [(self.ka, self.A, self.B, 7)],
            ],
        )
        payload = self._payload(1, tail, seed_of(self.ka), request_id="long")
        status, body = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["height"], 4)
        status, adopted = self.service.adopt_fork(body["tip_hash"])
        self.assertEqual(status, 200, adopted)
        self.assertEqual(self.store.tip().block_hash, body["tip_hash"])
        event = self.store.audit_events[-1]
        self.assertEqual(event["kind"], "sync_adopted")
        self.assertEqual(event["mode"], "attested")
        self.assertEqual(event["tip_hash"], body["tip_hash"])

    def test_pending_tip_attested_range(self) -> None:
        tail = make_tail(
            self.store.chain[0].block_hash,
            1,
            [[(self.ka, self.A, self.B, 3)]],
            pending_last=True,
        )
        payload = self._payload(0, tail, seed_of(self.ka), request_id="pend")
        status, body = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], STATUS_PENDING)
        self.assertEqual(
            self.store.forks[body["tip_hash"]][-1].status, STATUS_PENDING
        )

    # -- status precedence ----------------------------------------------------

    def test_structural_errors_are_400(self) -> None:
        tail = self._tail(1)
        good = self._payload(1, tail, seed_of(self.ka), request_id="g")
        n = {"v": 0}

        def variant(**changes) -> dict:
            n["v"] += 1
            body = json.loads(json.dumps(good))
            body["request_id"] = f"g{n['v']}"
            body.update(changes)
            return body

        self.assertEqual(
            self.service.submit_fork_sync_range_attested({"source": "node-x"})[0],
            400,
        )
        for field in (
            "source", "request_id", "expires_at", "anchor", "blocks", "tip",
            "signature",
        ):
            body = json.loads(json.dumps(good))
            body["request_id"] = f"miss-{field}"
            del body[field]
            self.assertEqual(
                self.service.submit_fork_sync_range_attested(body)[0], 400, field
            )
        # Field types.
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(source=""))[0], 400
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(request_id=""))[0], 400
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(expires_at="123"))[0],
            400,
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(expires_at=True))[0],
            400,
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(
                variant(anchor={"height": "1", "block_hash": good["anchor"]["block_hash"]})
            )[0],
            400,
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(
                variant(anchor={"height": 1, "block_hash": "z" * 64})
            )[0],
            400,
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(blocks=[]))[0], 400
        )
        # Closed tip: missing/extra field and per-field types.
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(
                variant(tip={"tip_hash": "0" * 64})
            )[0],
            400,
        )
        tip_extra = json.loads(json.dumps(good["tip"]))
        tip_extra["extra"] = 1
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(tip=tip_extra))[0],
            400,
        )
        tip_bad = json.loads(json.dumps(good["tip"]))
        tip_bad["tip_hash"] = "ZZ"
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(tip=tip_bad))[0], 400
        )
        tip_bad = json.loads(json.dumps(good["tip"]))
        tip_bad["height"] = True
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(tip=tip_bad))[0], 400
        )
        tip_bad = json.loads(json.dumps(good["tip"]))
        tip_bad["length"] = 0
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(tip=tip_bad))[0], 400
        )
        tip_bad = json.loads(json.dumps(good["tip"]))
        tip_bad["status"] = "PENDING"
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(tip=tip_bad))[0], 400
        )
        # Signature must be 128 lowercase hex; structure is decided before any
        # authorization, so even an unknown source gets 400 on a bad signature.
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(
                variant(signature="0" * 64, source="ghost")
            )[0],
            400,
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(
                variant(signature="Z" * 128)
            )[0],
            400,
        )

    def test_new_request_precedence(self) -> None:
        tail = self._tail(1)
        good = self._payload(1, tail, seed_of(self.ka), request_id="p")
        n = {"v": 0}

        def variant(**changes) -> dict:
            n["v"] += 1
            body = json.loads(json.dumps(good))
            body["request_id"] = f"p{n['v']}"
            body.update(changes)
            return body

        # Authorization 403 beats expiry/anchor/signature/chain.
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(variant(source="ghost"))[0],
            403,
        )
        # Expiry 410 beats signature verification, anchor and chain checks.
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(
                variant(expires_at=int(time.time()) - 1)
            )[0],
            410,
        )
        # A well-formed but non-verifying signature is 403, after auth/expiry
        # but before the anchor is examined.
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(
                variant(
                    signature="1" * 128,
                    anchor={"height": 99, "block_hash": "0" * 64},
                )
            )[0],
            403,
        )
        # A valid signature with a stale anchor is 409, beating chain 400.
        stale = variant(anchor={"height": 1, "block_hash": "0" * 64})
        stale_msg = attested_range_message(
            stale["source"], stale["request_id"], stale["expires_at"],
            stale["anchor"], stale["blocks"], stale["tip"],
        )
        stale["signature"] = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(stale_msg).digest()
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(stale)[0], 409
        )
        # A signed-but-invalid assembled chain is 400 (replayed canonical tx).
        dup_tail = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 10)]]
        )
        dup = self._payload(1, dup_tail, seed_of(self.ka), request_id="dup")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(dup)[0], 400
        )
        # A signed but overspending tail is 400 too.
        over_tail = make_tail(
            self.store.chain[1].block_hash,
            2,
            [[(self.ka, self.A, self.B, 10_000_000)]],
        )
        over = self._payload(1, over_tail, seed_of(self.ka), request_id="over")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(over)[0], 400
        )
        # A valid signature over a body whose tip value does not recompute is
        # 400 (tip signed with a tampered length).
        bad_tip_tail = self._tail(1)
        bad = self._payload(1, bad_tip_tail, seed_of(self.ka), request_id="badtip")
        bad["tip"]["length"] += 1
        msg = attested_range_message(
            bad["source"], bad["request_id"], bad["expires_at"], bad["anchor"],
            bad["blocks"], bad["tip"],
        )
        bad["signature"] = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(msg).digest()
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(bad)[0], 400
        )

    def test_duplicate_tip_is_409(self) -> None:
        tail = self._tail(1)
        first = self._payload(1, tail, seed_of(self.ka), request_id="d1")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(first)[0], 201
        )
        second = self._payload(1, tail, seed_of(self.ka), request_id="d2")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(second)[0], 409
        )

    def test_signature_is_over_sha256_of_canonical_message(self) -> None:
        # Signing the canonical bytes directly (instead of their SHA-256
        # digest) must fail; signing the digest with the wrong key must fail.
        tail = self._tail(1)
        body = self._payload(1, tail, seed_of(self.ka), request_id="canon", sign=False)
        raw = attested_range_message(
            body["source"], body["request_id"], body["expires_at"], body["anchor"],
            body["blocks"], body["tip"],
        )
        body["signature"] = crypto.sign_message(seed_of(self.ka), raw)
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(body)[0], 403
        )
        body = self._payload(1, tail, seed_of(self.kb), request_id="canon2")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(body)[0], 403
        )

    def test_non_ascii_source_signed_compactly(self) -> None:
        # ensure_ascii=False canonicalization: a non-ASCII source signed with
        # the documented canonical JSON verifies end to end.
        source = "node-Ω-节点"
        self.assertEqual(
            self.service.register_trust_source(
                {"source": source, "public_key": self.C, "expires_at": self.exp}
            )[0],
            201,
        )
        tail = self._tail(1)
        payload = self._payload(
            1, tail, seed_of(self.kc), request_id="u1", source=source
        )
        status, body = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201, body)

    # -- retry / idempotency ---------------------------------------------------

    def test_identical_retry_replays_after_revocation(self) -> None:
        tail = make_tail(
            self.store.chain[1].block_hash,
            2,
            [
                [(self.ka, self.A, self.B, 40)],
                [(self.kb, self.B, self.A, 5)],
                [(self.ka, self.A, self.B, 7)],
            ],
        )
        payload = self._payload(1, tail, seed_of(self.ka))
        status, first = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201)
        # Adopt, advance canonical, then revoke the source: the frozen-key
        # replay still returns the first result and skips auth/expiry.
        self.assertEqual(self.service.adopt_fork(first["tip_hash"])[0], 200)
        self.service.submit_transaction(signed_tx(self.kb, self.B, self.A, 9))
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("5")[0], 200)
        self.assertEqual(
            self.service.revoke_trust_source("node-x", {"expected_version": 1})[0],
            200,
        )
        status, replay = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)

    def test_retry_wrong_signature_is_403(self) -> None:
        tail = self._tail(1)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="ws")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(payload)[0], 201
        )
        bad = json.loads(json.dumps(payload))
        bad["signature"] = "f" * 128  # syntactically valid, cryptographically wrong
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(bad)[0], 403
        )

    def test_retry_malformed_body_is_400(self) -> None:
        tail = self._tail(1)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="mb")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(payload)[0], 201
        )
        # A syntactically-valid envelope carrying a structurally malformed
        # tail, RE-SIGNED so the (frozen-key) signature still verifies: once
        # signature verification passes, standalone tail validation fails 400
        # rather than replaying the cached 200.
        bad = json.loads(json.dumps(payload))
        bad["blocks"] = [{"height": 5}]
        msg = attested_range_message(
            bad["source"], bad["request_id"], bad["expires_at"], bad["anchor"],
            bad["blocks"], bad["tip"],
        )
        bad["signature"] = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(msg).digest()
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(bad)[0], 400
        )
        # Likewise, a validly signed but non-recomputing tip is 400.
        bad = json.loads(json.dumps(payload))
        bad["tip"]["status"] = "pending"
        msg = attested_range_message(
            bad["source"], bad["request_id"], bad["expires_at"], bad["anchor"],
            bad["blocks"], bad["tip"],
        )
        bad["signature"] = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(msg).digest()
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(bad)[0], 400
        )

    def test_retry_different_valid_content_is_409(self) -> None:
        tail = self._tail(1)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="dc")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(payload)[0], 201
        )
        other_tail = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 41)]]
        )
        changed = self._payload(
            1, other_tail, seed_of(self.ka), request_id="dc"
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(changed)[0], 409
        )

    def test_retry_uses_frozen_key_across_rotation(self) -> None:
        tail = self._tail(1)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="rot")
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(payload)[0], 201
        )
        _, new_pub = keypair()
        self.assertEqual(
            self.service.rotate_trust_source(
                "node-x",
                {"public_key": new_pub, "expires_at": self.exp,
                 "expected_version": 1},
            )[0],
            200,
        )
        # The original signature, under the now-old key, still replays 200.
        status, first = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 200)
        self.assertEqual(first["expires_at"], payload["expires_at"])
        # Re-signing the same content with the NEW key fails against the
        # frozen key: 403, even though the new key is current in the registry.
        resigned = json.loads(json.dumps(payload))
        new_seed = None
        # Derive a seed for new_pub: generate a fresh pair and rotate again so
        # we hold the private seed, to prove current-key signatures don't pass.
        kn, pn = keypair()
        self.assertEqual(
            self.service.rotate_trust_source(
                "node-x",
                {"public_key": pn, "expires_at": self.exp,
                 "expected_version": 2},
            )[0],
            200,
        )
        msg = attested_range_message(
            resigned["source"], resigned["request_id"], resigned["expires_at"],
            resigned["anchor"], resigned["blocks"], resigned["tip"],
        )
        resigned["signature"] = crypto.sign_message(
            seed_of(kn), hashlib.sha256(msg).digest()
        )
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(resigned)[0], 403
        )

    def test_attested_range_namespace_independent_of_plain(self) -> None:
        # The same source + request_id is accepted by both range endpoints:
        # separate idempotency namespaces. (The deliveries carry different
        # content — a different tail amount — so they describe distinct tips;
        # an identical tip under any key is still a 409 duplicate.)
        plain_tail = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 40)]]
        )
        att_tail = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 42)]]
        )
        end = plain_tail[-1]
        blocks = [b.to_dict() for b in plain_tail]
        anchor = {
            "height": 1,
            "block_hash": self.store.chain[1].block_hash,
        }
        tip = {
            "tip_hash": end.block_hash,
            "height": end.height,
            "length": 1 + 1 + len(plain_tail),
            "status": end.status,
        }
        plain = {
            "source": "node-x", "request_id": "shared", "expires_at": self.exp,
            "anchor": anchor, "blocks": blocks, "tip": tip,
        }
        self.assertEqual(
            self.service.submit_fork_sync_range(plain)[0], 201
        )
        attested = self._payload(
            1, att_tail, seed_of(self.ka), request_id="shared"
        )
        status, body = self.service.submit_fork_sync_range_attested(attested)
        self.assertEqual(status, 201, body)
        self.assertIn(("node-x", "shared"), self.store.syncs)
        self.assertIn(("node-x", "shared"), self.store.attested_syncs)
        # Both replay independently at 200.
        self.assertEqual(self.service.submit_fork_sync_range(plain)[0], 200)
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(attested)[0], 200
        )

    # -- lifecycle -------------------------------------------------------------

    def test_expiry_removes_record_candidate_and_emits_event(self) -> None:
        tail = self._tail(1)
        payload = self._payload(
            1, tail, seed_of(self.ka), request_id="ex",
            expires_at=int(time.time()) + 1,
        )
        status, body = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201)
        tip_hash = body["tip_hash"]
        time.sleep(1.1)
        status, listing = self.service.list_fork_syncs({"mode": "attested"})
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 0)
        self.assertNotIn(("node-x", "ex"), self.store.attested_syncs)
        self.assertNotIn(tip_hash, self.store.forks)
        expired = [
            e for e in self.store.audit_events
            if e["kind"] == "sync_expired" and e.get("request_id") == "ex"
        ]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["mode"], "attested")
        self.assertEqual(expired[0]["tip_hash"], tip_hash)

    def test_listed_in_attested_and_all_modes(self) -> None:
        tail = self._tail(1)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="q")
        status, body = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201)
        for mode in ("attested", "all"):
            status, listing = self.service.list_fork_syncs({"mode": mode})
            self.assertEqual(status, 200)
            self.assertEqual(listing["total"], 1)
            item = listing["items"][0]
            self.assertEqual(set(item), {
                "source", "request_id", "tip_hash", "height", "length",
                "status", "expires_at",
            })
            self.assertEqual(item["request_id"], "q")
        # Plain mode excludes it.
        status, listing = self.service.list_fork_syncs({"mode": "plain"})
        self.assertEqual(listing["total"], 0)
        # History shows the mode="attested" received event.
        status, history = self.service.list_fork_sync_history(
            {"mode": "attested", "kind": "sync_received"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["items"][0]["request_id"], "q")

    def test_save_failure_changes_nothing(self) -> None:
        tail = self._tail(1)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="atom")
        gen = self.store.generation
        n_forks = len(self.store.forks)
        n_attested = len(self.store.attested_syncs)
        n_events = len(self.store.audit_events)

        def failing() -> None:
            raise OSError("disk full")

        self.store.save = failing  # type: ignore[method-assign]
        with self.assertRaises(OSError):
            self.service.submit_fork_sync_range_attested(payload)
        del self.store.save
        self.assertEqual(self.store.generation, gen)
        self.assertEqual(len(self.store.forks), n_forks)
        self.assertEqual(len(self.store.attested_syncs), n_attested)
        self.assertEqual(len(self.store.audit_events), n_events)
        self.assertEqual(
            self.service.submit_fork_sync_range_attested(payload)[0], 201
        )

    def test_restart_persists_reverifies_and_replays(self) -> None:
        tail = self._tail(1, 2)
        payload = self._payload(1, tail, seed_of(self.ka))
        status, first = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201)
        # Canonical advances while down; the stored range is independent of it.
        self.service.submit_transaction(signed_tx(self.kb, self.B, self.A, 2))
        self.service.mine_block()
        self.service.confirm_block("4")
        del self.store
        self.store = LedgerStore(self.path)
        self.service = LedgerService(self.store)
        key = ("node-x", "r1")
        self.assertIn(key, self.store.attested_syncs)
        rec = self.store.attested_syncs[key]
        self.assertIn("range", rec["attested"])
        status, replay = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)

    def test_restart_silently_drops_tampered_record(self) -> None:
        tail = self._tail(1, 2)
        payload = self._payload(1, tail, seed_of(self.ka))
        status, first = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201)
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        for rec in raw["attested_syncs"]:
            if rec.get("request_id") == "r1":
                rec["attested"]["range"]["blocks"][0]["transactions"][0][
                    "amount"
                ] += 1
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, sort_keys=True)
        self.store = LedgerStore(self.path)
        self.assertNotIn(("node-x", "r1"), self.store.attested_syncs)
        self.assertNotIn(first["tip_hash"], self.store.forks)

    def test_restart_drops_record_with_tampered_signature(self) -> None:
        tail = self._tail(1)
        payload = self._payload(1, tail, seed_of(self.ka), request_id="sig")
        status, first = self.service.submit_fork_sync_range_attested(payload)
        self.assertEqual(status, 201)
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        for rec in raw["attested_syncs"]:
            if rec.get("request_id") == "sig":
                rec["attested"]["signature"] = "a" * 128
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, sort_keys=True)
        self.store = LedgerStore(self.path)
        self.assertNotIn(("node-x", "sig"), self.store.attested_syncs)
        self.assertNotIn(first["tip_hash"], self.store.forks)


class AttestedRangeHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.service = LedgerService(LedgerStore(os.path.join(cls.tmp, "http.json")))
        cls.exp = int(time.time()) + 10_000_000
        cls.service.register_trust_source(
            {"source": "http-x", "public_key": cls.A, "expires_at": cls.exp}
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

    @classmethod
    def request(cls, method: str, path: str, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{cls.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_attested_range_over_http(self) -> None:
        genesis = self.service.store.chain[0]
        _, recipient = keypair()
        tail = make_tail(
            genesis.block_hash, 1, [[(self.ka, self.A, recipient, 5)]]
        )
        end = tail[-1]
        blocks = [b.to_dict() for b in tail]
        anchor = {"height": 0, "block_hash": genesis.block_hash}
        tip = {
            "tip_hash": end.block_hash, "height": 1, "length": 2,
            "status": "confirmed",
        }
        message = attested_range_message(
            "http-x", "h1", self.exp, anchor, blocks, tip
        )
        signature = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(message).digest()
        )
        payload = {
            "source": "http-x", "request_id": "h1", "expires_at": self.exp,
            "anchor": anchor, "blocks": blocks, "tip": tip,
            "signature": signature,
        }
        status, body = self.request("POST", "/v1/forks/sync/range/attested", payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], end.block_hash)
        # Idempotent replay over HTTP.
        status, replay = self.request(
            "POST", "/v1/forks/sync/range/attested", payload
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, body)
        # Malformed envelope is 400; an unknown source (well-formed, validly
        # signed) is 403.
        self.assertEqual(
            self.request("POST", "/v1/forks/sync/range/attested", {"nope": True})[0],
            400,
        )
        ghost = json.loads(json.dumps(payload))
        ghost["source"] = "ghost"
        ghost["request_id"] = "h2"
        msg = attested_range_message(
            "ghost", "h2", self.exp, anchor, blocks, tip
        )
        ghost["signature"] = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(msg).digest()
        )
        self.assertEqual(
            self.request("POST", "/v1/forks/sync/range/attested", ghost)[0], 403
        )


class AttestedRangeCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(LedgerStore(os.path.join(cls.tmp, "cli.json")))
        cls.exp = int(time.time()) + 10_000_000
        cls.service.register_trust_source(
            {"source": "cli-x", "public_key": cls.A, "expires_at": cls.exp}
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args, stdin: str | None = None) -> tuple[int, dict]:
        buf = io.StringIO()
        old_stdin = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with redirect_stdout(buf):
                rc = cli_main(["--base-url", self.base_url, *args])
        finally:
            sys.stdin = old_stdin
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1)
        return rc, json.loads(raw)

    def test_sync_range_attested_cli(self) -> None:
        genesis = self.service.store.chain[0]
        tail = make_tail(genesis.block_hash, 1, [[(self.ka, self.A, self.B, 5)]])
        document = json.dumps(
            {
                "anchor": {"height": 0, "block_hash": genesis.block_hash},
                "blocks": [b.to_dict() for b in tail],
            }
        )
        seed = seed_of(self.ka)
        # First push: exit 0, one JSON line, tip derived from the tail.
        rc, body = self.run_cli(
            "sync-range-attested",
            "--source", "cli-x",
            "--request-id", "c1",
            "--expires-at", str(self.exp),
            "--signing-key", seed,
            document,
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["tip_hash"], tail[-1].block_hash)
        self.assertEqual(body["length"], 2)
        # Idempotent retry prints the identical line and exits 0.
        rc, retry = self.run_cli(
            "sync-range-attested",
            "--source", "cli-x",
            "--request-id", "c1",
            "--expires-at", str(self.exp),
            "--signing-key", seed,
            document,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(retry, body)
        # Reading a fresh range document from stdin via "-" works too.
        tail2 = make_tail(genesis.block_hash, 1, [[(self.ka, self.A, self.B, 6)]])
        document2 = json.dumps(
            {
                "anchor": {"height": 0, "block_hash": genesis.block_hash},
                "blocks": [b.to_dict() for b in tail2],
            }
        )
        rc, via_stdin = self.run_cli(
            "sync-range-attested",
            "--source", "cli-x",
            "--request-id", "c2",
            "--expires-at", str(self.exp),
            "--signing-key", seed,
            "-",
            stdin=document2,
        )
        self.assertEqual(rc, 0, via_stdin)
        # An unauthorized source exits 1 with a single JSON line.
        rc, err = self.run_cli(
            "sync-range-attested",
            "--source", "ghost",
            "--request-id", "c3",
            "--expires-at", str(self.exp),
            "--signing-key", seed,
            document,
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", err)
        # A malformed 64-hex seed exits 1.
        rc, err = self.run_cli(
            "sync-range-attested",
            "--source", "cli-x",
            "--request-id", "c4",
            "--expires-at", str(self.exp),
            "--signing-key", "zz",
            document,
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", err)
        # A malformed JSON document exits 1.
        rc, err = self.run_cli(
            "sync-range-attested",
            "--source", "cli-x",
            "--request-id", "c5",
            "--expires-at", str(self.exp),
            "--signing-key", seed,
            "{not json",
        )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

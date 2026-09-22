"""Tests for source-signed (attested) candidate-chain sync.

Covers POST /v1/forks/sync/attested: envelope/type validation (signature must
be exactly 128 lowercase hex characters; candidate keeps its delivered form —
export document, {"blocks": ...} wrapper or a bare array), the canonical
signed message {domain:"ledger-sync-v1", source, request_id, expires_at,
candidate} hashed with raw SHA-256 and Ed25519-signed, status precedence
400 -> 403 unauthorized -> 410 expired -> 403 bad signature -> 400 chain /
summary -> 409 duplicate, no writes on a failed signature, frozen
public_key/version/signature/fingerprint (incl. the signed original form)
stored atomically with the candidate and a mode-tagged sync_received,
separate-plain/attested idempotency domains, same-key retries re-verifying the
signature against the frozen key (403 / 200 / 409) and re-validating the
chain, rotation/revocation immunity of frozen-key replay, runtime expiry
removal plus key reuse, adoption with a mode-tagged sync_adopted and canonical
preservation on later expiry, restart reconciliation (re-verification, silent
cache-only drops, expiry / authorization-loss backfill with mode and no
duplicates, audit continuity), the HTTP surface and the CLI sync-attested
subcommand.

Run: python3 tests/attested_sync_test.py
"""
from __future__ import annotations

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
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import EVENT_MODE_ATTESTED, LedgerService
from ledger.store import LedgerStore

DOMAIN = "ledger-sync-v1"


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(signed_tx(key, sender, to, amount))


def make_fork(genesis: Block, blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


def attest(
    key: Ed25519PrivateKey,
    source: str,
    request_id: str,
    expires_at: int,
    candidate: object,
) -> str:
    """Sign the raw SHA-256 digest of the canonical attested message."""
    digest = crypto.attested_sync_digest(source, request_id, expires_at, candidate)
    return key.sign(digest).hex()


def reopen(path: str, balance: int = 1000) -> LedgerStore:
    return LedgerStore(path, initial_balance=balance)


class AttestedSyncServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.future = int(time.time()) + 10_000_000
        self.svc.register_trust_source(
            {"source": "node-1", "public_key": self.A, "expires_at": self.future}
        )

    def block1(self, amount: int = 10, *, status: str = "confirmed") -> Block:
        return Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.B, amount)],
            status,
        )

    def submit(self, candidate, *, key=None, source="node-1", request_id="req-1",
               expires_at=None, signature=None, pub_for_sig=None):
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        if signature is None:
            signature = attest(key or self.ka, source, request_id, expires_at, candidate)
        return self.svc.submit_fork_sync_attested(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": candidate,
                "signature": signature,
            }
        )

    def received_events(self, request_id="req-1"):
        return [
            e for e in self.store.audit_events
            if e.get("kind") == "sync_received" and e.get("request_id") == request_id
        ]

    # -- success / envelope -------------------------------------------------

    def test_valid_attested_sync_returns_201_and_freezes_record(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        status, body = self.submit(doc, expires_at=exp)
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "tip_hash": block.block_hash,
                "height": 1,
                "length": 2,
                "status": "confirmed",
                "expires_at": exp,
            },
        )
        rec = self.store.attested_syncs[("node-1", "req-1")]
        self.assertEqual(rec["public_key"], self.A)
        self.assertEqual(rec["key_version"], 1)
        self.assertEqual(crypto.is_hex128(rec["signature"]), True)
        self.assertEqual(rec["candidate"], doc)
        events = self.received_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["mode"], EVENT_MODE_ATTESTED)
        self.assertIn(block.block_hash, self.store.forks)

    def test_candidate_kept_verbatim_for_all_three_shapes(self) -> None:
        block = self.block1()
        blocks = [self.genesis.to_dict(), block.to_dict()]
        exp = int(time.time()) + 3600
        # Bare array.
        sig = attest(self.ka, "node-1", "bare", exp, blocks)
        self.assertEqual(
            self.submit(blocks, request_id="bare", expires_at=exp, signature=sig)[0],
            201,
        )
        self.assertEqual(
            self.store.attested_syncs[("node-1", "bare")]["candidate"], blocks
        )
        # {"blocks": [...]} wrapper (different tip from the export doc -> its
        # own fork entry allowed, since the first is also a distinct request).
        wrapped = {"blocks": blocks}
        # Same chain, so the tip already exists; use a distinct amount chain.
        block2 = self.block1(11)
        blocks2 = [self.genesis.to_dict(), block2.to_dict()]
        wrapped2 = {"blocks": blocks2}
        sig2 = attest(self.ka, "node-1", "wrap", exp, wrapped2)
        status, body = self.submit(
            wrapped2, request_id="wrap", expires_at=exp, signature=sig2
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(
            self.store.attested_syncs[("node-1", "wrap")]["candidate"], wrapped2
        )

    def test_signature_is_over_canonical_sha256_digest(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        expected_msg = json.dumps(
            {
                "domain": DOMAIN,
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": exp,
                "candidate": doc,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        # Sign the message directly (not its digest) -> must fail verification.
        raw_sig = self.ka.sign(expected_msg).hex()
        self.assertEqual(self.submit(doc, expires_at=exp, signature=raw_sig)[0], 403)
        # Signing the SHA-256 digest succeeds.
        import hashlib
        good = self.ka.sign(hashlib.sha256(expected_msg).digest()).hex()
        self.assertEqual(self.submit(doc, expires_at=exp, signature=good)[0], 201)

    # -- 400 envelope -------------------------------------------------------

    def test_malformed_envelope_is_400(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        base = {"source": "node-1", "request_id": "r", "expires_at": exp,
                "candidate": doc, "signature": attest(self.ka, "node-1", "r", exp, doc)}
        for field in ("source", "request_id", "expires_at", "candidate", "signature"):
            bad = dict(base)
            del bad[field]
            self.assertEqual(self.svc.submit_fork_sync_attested(bad)[0], 400, field)
        self.assertEqual(self.svc.submit_fork_sync_attested("nope")[0], 400)
        # Signature format: exactly 128 lowercase hex.
        for bad_sig in ("", "ab", "00" * 63, "00" * 65, "A" * 128, "g" * 128, 123):
            bad = dict(base, signature=bad_sig, request_id="rs")
            self.assertEqual(
                self.svc.submit_fork_sync_attested(bad)[0], 400, bad_sig
            )
        # Boolean/string expiry and non-list candidate.
        self.assertEqual(
            self.svc.submit_fork_sync_attested(
                dict(base, request_id="re", expires_at=True)
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.submit_fork_sync_attested(
                dict(base, request_id="rc", candidate={"nope": []})
            )[0],
            400,
        )
        # No writes from any of the rejected requests.
        self.assertEqual(self.store.attested_syncs, {})
        self.assertEqual(self.store.forks, {})

    # -- precedence ---------------------------------------------------------

    def test_precedence_unauthorized_expired_badsig_chain_duplicate(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        # Unknown source -> 403 even though the body is otherwise valid.
        self.assertEqual(self.submit(doc, source="ghost")[0], 403)
        # Registered source but expired request -> 410 (signature irrelevant).
        self.assertEqual(
            self.submit(doc, expires_at=int(time.time()) - 1)[0], 410
        )
        # Valid source/deadline, wrong signature -> 403.
        self.assertEqual(self.submit(doc, signature="00" * 64)[0], 403)
        # Correct signature over a tampered chain -> 400.
        bad = json.loads(json.dumps(doc))
        bad["blocks"][1]["transactions"][0]["amount"] = 999
        self.assertEqual(self.submit(bad, request_id="badchain")[0], 400)
        # Tampered export summary with a matching signature -> 400.
        tampered = dict(doc, height=9)
        self.assertEqual(self.submit(tampered, request_id="badsum")[0], 400)
        # Fully valid -> 201, then the same tip duplicates -> 409.
        self.assertEqual(self.submit(doc, request_id="ok")[0], 201)
        self.assertEqual(self.submit(doc, request_id="dup")[0], 409)
        # Nothing was written by the rejected deliveries except the success.
        self.assertEqual(set(self.store.attested_syncs), {("node-1", "ok")})

    def test_bad_signature_writes_nothing_and_keeps_existing(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        sig = attest(self.ka, "node-1", "keep", exp, doc)
        self.assertEqual(
            self.submit(doc, request_id="keep", expires_at=exp, signature=sig)[0],
            201,
        )
        forks_before = set(self.store.forks)
        events_before = len(self.store.audit_events)
        # A retry carrying a garbage signature must 403 and leave the recorded
        # delivery, its candidate and the audit history exactly as they were.
        self.assertEqual(
            self.submit(doc, request_id="keep", expires_at=exp, signature="11" * 64)[0],
            403,
        )
        self.assertIn(("node-1", "keep"), self.store.attested_syncs)
        self.assertEqual(set(self.store.forks), forks_before)
        self.assertEqual(len(self.store.audit_events), events_before)

    # -- idempotency --------------------------------------------------------

    def test_same_key_retry_identical_is_200_original_result(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        sig = attest(self.ka, "node-1", "id", exp, doc)
        self.assertEqual(
            self.submit(doc, request_id="id", expires_at=exp, signature=sig)[0], 201
        )
        # Even after the request deadline passes, a live recorded key replays
        # 200 with the ORIGINAL expires_at (retry skips the deadline gate).
        status, body = self.submit(
            doc, request_id="id", expires_at=exp, signature=sig
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["expires_at"], exp)
        self.assertEqual(body["tip_hash"], block.block_hash)

    def test_same_key_retry_different_content_is_409(self) -> None:
        block = self.block1(10)
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        self.assertEqual(self.submit(doc, request_id="id", expires_at=exp)[0], 201)
        # Same key, valid signature, different candidate content -> 409.
        other = self.block1(12)
        other_doc = make_fork(self.genesis, [self.genesis, other])
        status, _ = self.submit(other_doc, request_id="id", expires_at=exp)
        self.assertEqual(status, 409)

    def test_same_key_retry_revalidates_chain_tampered_is_400(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        self.assertEqual(self.submit(doc, request_id="id", expires_at=exp)[0], 201)
        # Re-sign a tampered candidate for the same key/message envelope:
        # signature verifies but the chain re-validation fails -> 400, never a
        # cached 200.
        tampered = json.loads(json.dumps(doc))
        tampered["blocks"][1]["height"] = 2
        sig = attest(self.ka, "node-1", "id", exp, tampered)
        self.assertEqual(
            self.submit(tampered, request_id="id", expires_at=exp, signature=sig)[0],
            400,
        )

    def test_frozen_key_replay_unaffected_by_rotation_and_revocation(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        sig = attest(self.ka, "node-1", "rot", exp, doc)
        self.assertEqual(
            self.submit(doc, request_id="rot", expires_at=exp, signature=sig)[0], 201
        )
        kb, B = keypair()
        self.assertEqual(
            self.svc.rotate_trust_source(
                "node-1",
                {"public_key": B, "expires_at": self.future, "expected_version": 1},
            )[0],
            200,
        )
        # Retry still verifies against the frozen version-1 public key -> 200.
        self.assertEqual(
            self.submit(doc, request_id="rot", expires_at=exp, signature=sig)[0], 200
        )
        rec = self.store.attested_syncs[("node-1", "rot")]
        self.assertEqual(rec["public_key"], self.A)
        self.assertEqual(rec["key_version"], 1)
        # Revocation does not change the recorded replay either.
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 2})[0], 200
        )
        self.assertEqual(
            self.submit(doc, request_id="rot", expires_at=exp, signature=sig)[0], 200
        )
        # A brand-new key from the now-revoked source is refused 403.
        self.assertEqual(self.submit(doc, request_id="new")[0], 403)

    # -- domain separation --------------------------------------------------

    def test_attested_and_plain_keys_are_separate_domains(self) -> None:
        block_a = self.block1(10)
        doc_a = make_fork(self.genesis, [self.genesis, block_a])
        block_b = self.block1(20)
        doc_b = make_fork(self.genesis, [self.genesis, block_b])
        exp = int(time.time()) + 3600
        self.assertEqual(
            self.svc.submit_fork_sync(
                {"source": "node-1", "request_id": "same", "expires_at": exp,
                 "candidate": doc_a}
            )[0],
            201,
        )
        # Same (source, request_id) in the attested domain, different tip: the
        # separate idempotency scope accepts it.
        self.assertEqual(
            self.submit(doc_b, request_id="same", expires_at=exp)[0], 201
        )
        self.assertIn(("node-1", "same"), self.store.syncs)
        self.assertIn(("node-1", "same"), self.store.attested_syncs)

    # -- expiry / adoption --------------------------------------------------

    def test_runtime_expiry_removes_record_and_fork_then_key_reusable(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        short = int(time.time()) + 1
        self.assertEqual(self.submit(doc, expires_at=short)[0], 201)
        self.assertIn(block.block_hash, self.store.forks)
        time.sleep(1.1)
        self.svc.get_chain()  # triggers the shared sweep
        self.assertNotIn(("node-1", "req-1"), self.store.attested_syncs)
        self.assertNotIn(block.block_hash, self.store.forks)
        expired = [
            e for e in self.store.audit_events
            if e.get("kind") == "sync_expired" and e.get("request_id") == "req-1"
        ]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["mode"], EVENT_MODE_ATTESTED)
        # The same key can start a fresh lifecycle.
        exp2 = int(time.time()) + 3600
        self.assertEqual(self.submit(doc, expires_at=exp2)[0], 201)

    def test_adoption_records_mode_event_and_expiry_keeps_canonical(self) -> None:
        # Canonical grows a confirmed block, then a longer synced fork wins.
        canon = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 5)]
        )
        self.store.chain.append(canon)
        self.store.rebuild_derived()
        self.store.save()
        f1 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 6)]
        )
        f2 = Block.create(
            2, f1.block_hash, [tx_obj(self.kb, self.B, self.A, 1)]
        )
        doc = make_fork(self.genesis, [self.genesis, f1, f2])
        short = int(time.time()) + 1
        self.assertEqual(self.submit(doc, request_id="ad", expires_at=short)[0], 201)
        self.assertEqual(self.svc.adopt_fork(f2.block_hash)[0], 200)
        self.assertEqual(self.store.tip_hash(), f2.block_hash)
        adopted = [e for e in self.store.audit_events if e.get("kind") == "sync_adopted"]
        self.assertEqual(len(adopted), 1)
        self.assertEqual(adopted[0]["mode"], EVENT_MODE_ATTESTED)
        time.sleep(1.1)
        self.svc.get_chain()
        # Adopted tip: only metadata is removed; the canonical chain is intact.
        self.assertNotIn(("node-1", "ad"), self.store.attested_syncs)
        self.assertEqual(self.store.tip_hash(), f2.block_hash)
        expired = [e for e in self.store.audit_events if e.get("kind") == "sync_expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["mode"], EVENT_MODE_ATTESTED)

    def test_failed_write_rolls_back_record_fork_and_event(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600

        def boom():
            raise OSError("simulated disk failure")

        self.store.save = boom  # type: ignore[assignment]
        with self.assertRaises(OSError):
            self.submit(doc, expires_at=exp)
        self.assertEqual(self.store.attested_syncs, {})
        self.assertEqual(self.store.forks, {})
        self.assertFalse(self.received_events())


class AttestedSyncRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.future = int(time.time()) + 10_000_000

    def _service(self) -> LedgerService:
        return LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )

    def _fork(self, svc: LedgerService, amount: int) -> tuple[dict, Block]:
        g = svc.store.chain[0]
        block = Block.create(1, g.block_hash, [tx_obj(self.ka, self.A, self.B, amount)])
        return make_fork(g, [g, block]), block

    def _deliver(self, svc: LedgerService, doc: dict, request_id: str,
                 expires_at: int | None = None, key=None) -> tuple[int, dict]:
        exp = self.future if expires_at is None else expires_at
        sig = attest(key or self.ka, "node-1", request_id, exp, doc)
        return svc.submit_fork_sync_attested(
            {"source": "node-1", "request_id": request_id, "expires_at": exp,
             "candidate": doc, "signature": sig}
        )

    def _raw(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_raw(self, raw: dict) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)

    def test_surviving_record_reverifies_and_keeps_frozen_key_after_rotation(self) -> None:
        svc = self._service()
        svc.register_trust_source(
            {"source": "node-1", "public_key": self.A, "expires_at": self.future}
        )
        doc, block = self._fork(svc, 10)
        self.assertEqual(self._deliver(svc, doc, "k1")[0], 201)
        # Rotate to a different current key; the frozen version-1 signature
        # must still re-verify on restart.
        self.assertEqual(
            svc.rotate_trust_source(
                "node-1",
                {"public_key": self.B, "expires_at": self.future, "expected_version": 1},
            )[0],
            200,
        )
        reopened = reopen(self.path)
        rec = reopened.attested_syncs[("node-1", "k1")]
        self.assertEqual(rec["public_key"], self.A)
        self.assertEqual(rec["key_version"], 1)
        self.assertIn(block.block_hash, reopened.forks)

    def test_tampered_signature_is_silent_cache_drop_chain_unchanged(self) -> None:
        svc = self._service()
        svc.register_trust_source(
            {"source": "node-1", "public_key": self.A, "expires_at": self.future}
        )
        doc, block = self._fork(svc, 10)
        self.assertEqual(self._deliver(svc, doc, "k1")[0], 201)
        event_count = len(svc.store.audit_events)
        raw = self._raw()
        for rec in raw["attested_syncs"]:
            if rec["request_id"] == "k1":
                rec["signature"] = "11" * 64
        self._write_raw(raw)
        reopened = reopen(self.path)
        self.assertNotIn(("node-1", "k1"), reopened.attested_syncs)
        self.assertNotIn(block.block_hash, reopened.forks)
        # Canonical chain untouched; no new lifecycle event; history retained.
        self.assertEqual(reopened.chain[-1].height, 0)
        self.assertEqual(len(reopened.audit_events), event_count)
        self.assertTrue(
            any(
                e.get("kind") == "sync_received" and e.get("request_id") == "k1"
                for e in reopened.audit_events
            )
        )

    def test_tampered_candidate_shape_is_silent_cache_drop(self) -> None:
        svc = self._service()
        svc.register_trust_source(
            {"source": "node-1", "public_key": self.A, "expires_at": self.future}
        )
        doc, block = self._fork(svc, 10)
        self.assertEqual(self._deliver(svc, doc, "k1")[0], 201)
        raw = self._raw()
        for rec in raw["attested_syncs"]:
            if rec["request_id"] == "k1":
                # Re-wrap into {"blocks": ...}: same valid chain, but the
                # signed original form changed, so signature/fingerprint fail.
                rec["candidate"] = {"blocks": rec["candidate"]["blocks"]}
        self._write_raw(raw)
        reopened = reopen(self.path)
        self.assertNotIn(("node-1", "k1"), reopened.attested_syncs)
        self.assertNotIn(block.block_hash, reopened.forks)

    def test_own_expiry_while_down_backfills_mode_event_once(self) -> None:
        svc = self._service()
        svc.register_trust_source(
            {"source": "node-1", "public_key": self.A, "expires_at": self.future}
        )
        doc, block = self._fork(svc, 10)
        self.assertEqual(self._deliver(svc, doc, "k1", expires_at=int(time.time()) + 1)[0], 201)
        time.sleep(1.2)
        reopened = reopen(self.path)
        self.assertNotIn(("node-1", "k1"), reopened.attested_syncs)
        self.assertNotIn(block.block_hash, reopened.forks)
        expired = [
            e for e in reopened.audit_events
            if e.get("kind") == "sync_expired" and e.get("request_id") == "k1"
        ]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["mode"], EVENT_MODE_ATTESTED)
        # A second restart must not duplicate the backfilled event.
        reopened2 = reopen(self.path)
        expired2 = [
            e for e in reopened2.audit_events
            if e.get("kind") == "sync_expired" and e.get("request_id") == "k1"
        ]
        self.assertEqual(len(expired2), 1)

    def test_authorization_loss_while_down_backfills_and_drops(self) -> None:
        svc = self._service()
        svc.register_trust_source(
            {"source": "node-1", "public_key": self.A, "expires_at": self.future}
        )
        doc, block = self._fork(svc, 10)
        self.assertEqual(self._deliver(svc, doc, "k1")[0], 201)
        # Revocation while "down": the next restart re-authorizes and prunes.
        self.assertEqual(
            svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        reopened = reopen(self.path)
        self.assertNotIn(("node-1", "k1"), reopened.attested_syncs)
        self.assertNotIn(block.block_hash, reopened.forks)
        expired = [
            e for e in reopened.audit_events
            if e.get("kind") == "sync_expired" and e.get("request_id") == "k1"
        ]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["mode"], EVENT_MODE_ATTESTED)

    def test_plain_and_attested_records_both_survive_restart(self) -> None:
        svc = self._service()
        svc.register_trust_source(
            {"source": "node-1", "public_key": self.A, "expires_at": self.future}
        )
        doc_a, block_a = self._fork(svc, 10)
        doc_b, block_b = self._fork(svc, 20)
        sig = attest(self.ka, "node-1", "same", self.future, doc_b)
        self.assertEqual(
            svc.submit_fork_sync(
                {"source": "node-1", "request_id": "same",
                 "expires_at": self.future, "candidate": doc_a}
            )[0],
            201,
        )
        self.assertEqual(
            svc.submit_fork_sync_attested(
                {"source": "node-1", "request_id": "same", "expires_at": self.future,
                 "candidate": doc_b, "signature": sig}
            )[0],
            201,
        )
        reopened = reopen(self.path)
        self.assertIn(("node-1", "same"), reopened.syncs)
        self.assertIn(("node-1", "same"), reopened.attested_syncs)
        self.assertIn(block_a.block_hash, reopened.forks)
        self.assertIn(block_b.block_hash, reopened.forks)


class AttestedSyncHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.genesis = cls.service.store.chain[0]
        status, _ = cls.service.register_trust_source(
            {"source": "http-node", "public_key": cls.A,
             "expires_at": int(time.time()) + 10_000_000}
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

    def _payload(self, request_id: str, amount: int = 7) -> dict:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, amount)]
        )
        doc = make_fork(self.genesis, [self.genesis, block])
        exp = int(time.time()) + 3600
        return {
            "source": "http-node",
            "request_id": request_id,
            "expires_at": exp,
            "candidate": doc,
            "signature": attest(self.ka, "http-node", request_id, exp, doc),
            "_block_hash": block.block_hash,
        }

    def test_attested_sync_over_http(self) -> None:
        payload = self._payload("h1")
        block_hash = payload.pop("_block_hash")
        status, body = self.request("POST", "/v1/forks/sync/attested", payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], block_hash)
        # Identical retry -> 200 original body.
        status, retry = self.request("POST", "/v1/forks/sync/attested", payload)
        self.assertEqual(status, 200)
        self.assertEqual(retry, body)
        # Bad signature -> 403.
        bad = dict(payload, signature="00" * 64)
        self.assertEqual(
            self.request("POST", "/v1/forks/sync/attested", bad)[0], 403
        )
        # Unknown source -> 403; malformed signature length -> 400.
        unauth = dict(payload, source="ghost", request_id="h2")
        self.assertEqual(
            self.request("POST", "/v1/forks/sync/attested", unauth)[0], 403
        )
        short = dict(payload, signature="ab", request_id="h3")
        self.assertEqual(
            self.request("POST", "/v1/forks/sync/attested", short)[0], 400
        )

    def test_non_json_body_400(self) -> None:
        req = urllib.request.Request(
            f"{self.base}/v1/forks/sync/attested",
            data=b"not-json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)


class AttestedSyncCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.genesis = cls.service.store.chain[0]
        status, _ = cls.service.register_trust_source(
            {"source": "cli-node", "public_key": cls.A,
             "expires_at": int(time.time()) + 10_000_000}
        )
        assert status in (200, 201), status
        cls.seed = bytes(
            cls.ka.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).hex()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw)

    def test_sync_attested_cli_signs_and_retries(self) -> None:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 4)]
        )
        # Submit the candidate as a bare block array; the CLI must keep it bare.
        candidate = json.dumps([self.genesis.to_dict(), block.to_dict()])
        exp = str(int(time.time()) + 3600)
        rc, body = self.run_cli(
            "sync-attested", "--source", "cli-node", "--request-id", "c1",
            "--expires-at", exp, "--signing-key", self.seed, candidate,
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["tip_hash"], block.block_hash)
        rec = self.service.store.attested_syncs[("cli-node", "c1")]
        self.assertEqual(rec["public_key"], self.A)
        self.assertTrue(isinstance(rec["candidate"], list))  # bare form kept
        # Idempotent retry.
        rc, retry = self.run_cli(
            "sync-attested", "--source", "cli-node", "--request-id", "c1",
            "--expires-at", exp, "--signing-key", self.seed, candidate,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(retry, body)

    def test_sync_attested_cli_bad_seed_exits_1(self) -> None:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 5)]
        )
        candidate = json.dumps([self.genesis.to_dict(), block.to_dict()])
        rc, body = self.run_cli(
            "sync-attested", "--source", "cli-node", "--request-id", "c2",
            "--expires-at", str(int(time.time()) + 3600),
            "--signing-key", "not-a-seed", candidate,
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)

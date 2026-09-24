"""Tests for the single-record sync export.

Covers GET /v1/forks/sync/export?source=S&request_id=R&mode=M at the
service, HTTP and CLI layers:

* strict parameter validation — source/request_id/mode all required, each a
  single non-empty value, mode only plain|attested, unknown or repeated
  parameters rejected 400;
* a hit returns 200 with the fixed key order
  source, request_id, mode, expires_at, tip_hash, height, length, status,
  candidate, attestation; expires_at/height/length are non-boolean integers,
  tip_hash 64 lowercase hex and status pending|confirmed;
* plain — candidate is exactly {tip_hash, height, length, status, blocks}
  rebuilt from the stored fork (or the canonical prefix after adoption) with
  attestation null and the content fingerprint recomputed;
* attested — the signed candidate is retained verbatim and attestation is
  {public_key, version, signature}, re-verified by domain, frozen public key
  and fingerprint;
* range deliveries (plain or attested) hit 409; unknown, expired or pruned
  records 404, including signature/fingerprint/summary mismatches and an
  unresolvable tip;
* restart produces the identical export without adding any authoritative
  copy, while signature/digest mismatches drop the cache at recovery but
  keep the audit history;
* a failed sweep save during export restores records/forks/events and
  propagates OSError;
* HTTP fixed raw key order and repeated-parameter 400; the sync-export CLI
  forwards the same parameters, prints one JSON line and exits 1 on non-2xx.

Run: python3 tests/sync_export_test.py
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
    attested_fingerprint,
    attested_message,
    attested_range_message,
)


EXPORT_KEYS = [
    "source", "request_id", "mode", "expires_at", "tip_hash", "height",
    "length", "status", "candidate", "attestation",
]
PLAIN_CANDIDATE_KEYS = ["tip_hash", "height", "length", "status", "blocks"]
ATTESTATION_KEYS = ["public_key", "version", "signature"]


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


def make_linked(prev_hash: str, start_height: int, specs,
                pending_last: bool = False) -> list[Block]:
    blocks: list[Block] = []
    prev = prev_hash
    for i, group in enumerate(specs):
        txs = [tx_obj(k, s, r, a) for (k, s, r, a) in group]
        status = (
            STATUS_PENDING if pending_last and i == len(specs) - 1 else "confirmed"
        )
        block = Block.create(start_height + i, prev, txs, status)
        blocks.append(block)
        prev = block.block_hash
    return blocks


def make_full_fork(genesis: Block, specs) -> list[Block]:
    return [genesis, *make_linked(genesis.block_hash, 1, specs)]


class SyncExportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "export.json")
        self.store = LedgerStore(self.path, initial_balance=1_000_000)
        self.service = LedgerService(self.store, initial_balance=1_000_000)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.exp = int(time.time()) + 10_000_000
        # Confirmed canonical chain 0..3 on the receiver.
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
        self.genesis = self.store.chain[0]

    # -- delivery helpers -----------------------------------------------------

    def plain_full(self, request_id: str = "plain-1", *, blocks=None,
                   expires_at=None) -> tuple[int, dict]:
        if blocks is None:
            blocks = make_full_fork(
                self.genesis, [[(self.ka, self.A, self.B, 99)]]
            )
        candidate = {
            "tip_hash": blocks[-1].block_hash,
            "height": blocks[-1].height,
            "length": len(blocks),
            "status": blocks[-1].status,
            "blocks": [b.to_dict() for b in blocks],
        }
        payload = {
            "source": "node-x",
            "request_id": request_id,
            "expires_at": self.exp if expires_at is None else expires_at,
            "candidate": candidate,
        }
        return self.service.submit_fork_sync(payload)

    def attested_full(self, request_id: str = "att-1", *, candidate=None,
                      seed=None, expires_at=None) -> tuple[int, dict]:
        if candidate is None:
            blocks = make_full_fork(
                self.genesis, [[(self.ka, self.A, self.B, 98)]]
            )
            candidate = [b.to_dict() for b in blocks]
        deadline = self.exp if expires_at is None else expires_at
        seed = seed_of(self.ka) if seed is None else seed
        message = attested_message("node-x", request_id, deadline, candidate)
        signature = crypto.sign_message(
            seed, hashlib.sha256(message).digest()
        )
        self.assertIsNotNone(signature)
        payload = {
            "source": "node-x",
            "request_id": request_id,
            "expires_at": deadline,
            "candidate": candidate,
            "signature": signature,
        }
        return self.service.submit_fork_sync_attested(payload)

    def plain_range(self, request_id: str = "range-1") -> tuple[int, dict]:
        tail = make_linked(
            self.store.chain[1].block_hash, 2,
            [[(self.ka, self.A, self.B, 40)]],
        )
        end = tail[-1]
        payload = {
            "source": "node-x",
            "request_id": request_id,
            "expires_at": self.exp,
            "anchor": {
                "height": 1,
                "block_hash": self.store.chain[1].block_hash,
            },
            "blocks": [b.to_dict() for b in tail],
            "tip": {
                "tip_hash": end.block_hash,
                "height": end.height,
                "length": 1 + 1 + len(tail),
                "status": end.status,
            },
        }
        return self.service.submit_fork_sync_range(payload)

    def attested_range(self, request_id: str = "arange-1") -> tuple[int, dict]:
        tail = make_linked(
            self.store.chain[1].block_hash, 2,
            [[(self.ka, self.A, self.B, 41)]],
        )
        end = tail[-1]
        anchor = {"height": 1, "block_hash": self.store.chain[1].block_hash}
        blocks = [b.to_dict() for b in tail]
        tip = {
            "tip_hash": end.block_hash,
            "height": end.height,
            "length": 1 + 1 + len(tail),
            "status": end.status,
        }
        message = attested_range_message(
            "node-x", request_id, self.exp, anchor, blocks, tip
        )
        signature = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(message).digest()
        )
        payload = {
            "source": "node-x",
            "request_id": request_id,
            "expires_at": self.exp,
            "anchor": anchor,
            "blocks": blocks,
            "tip": tip,
            "signature": signature,
        }
        return self.service.submit_fork_sync_range_attested(payload)

    def export(self, request_id: str, mode: str, *, source="node-x"):
        return self.service.export_fork_sync(
            {"source": source, "request_id": request_id, "mode": mode}
        )

    # -- plain ---------------------------------------------------------------

    def test_plain_hit_shape_and_key_order(self) -> None:
        status, received = self.plain_full("plain-hit")
        self.assertEqual(status, 201, received)
        status, body = self.export("plain-hit", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body.keys()), EXPORT_KEYS)
        self.assertEqual(body["source"], "node-x")
        self.assertEqual(body["request_id"], "plain-hit")
        self.assertEqual(body["mode"], "plain")
        self.assertEqual(body["expires_at"], self.exp)
        self.assertEqual(body["tip_hash"], received["tip_hash"])
        self.assertEqual(body["height"], received["height"])
        self.assertEqual(body["length"], received["length"])
        self.assertEqual(body["status"], "confirmed")
        # Strict JSON types.
        self.assertIsInstance(body["expires_at"], int)
        self.assertNotIsInstance(body["expires_at"], bool)
        self.assertIsInstance(body["height"], int)
        self.assertIsInstance(body["length"], int)
        self.assertNotIsInstance(body["height"], bool)
        self.assertIn(body["status"], ("pending", "confirmed"))
        self.assertTrue(crypto.is_hex64(body["tip_hash"]))
        # Plain candidate: five-field export document, attestation null.
        self.assertIsNone(body["attestation"])
        candidate = body["candidate"]
        self.assertEqual(list(candidate.keys()), PLAIN_CANDIDATE_KEYS)
        self.assertEqual(candidate["tip_hash"], body["tip_hash"])
        self.assertEqual(candidate["height"], body["height"])
        self.assertEqual(candidate["length"], body["length"])
        self.assertEqual(candidate["status"], body["status"])
        self.assertEqual(len(candidate["blocks"]), body["length"])
        # The rebuilt candidate is byte-for-byte the stored fork export and
        # can be re-fetched through GET /v1/forks/{tip}/export.
        status, fork_export = self.service.export_fork(body["tip_hash"])
        self.assertEqual(status, 200)
        self.assertEqual(candidate, fork_export)
        self.assertEqual(candidate["blocks"][0], self.genesis.to_dict())

    def test_plain_pending_tip_status(self) -> None:
        blocks = make_full_fork(
            self.genesis, [[(self.ka, self.A, self.B, 7)]],
        )
        # make_full_fork builds confirmed blocks; flip the unique tip to
        # pending for a valid pending-tip delivery.
        pending = [b.to_dict() for b in blocks]
        pending[-1]["status"] = STATUS_PENDING
        status, received = self.service.submit_fork_sync({
            "source": "node-x",
            "request_id": "plain-pending",
            "expires_at": self.exp,
            "candidate": {"blocks": pending},
        })
        self.assertEqual(status, 201, received)
        status, body = self.export("plain-pending", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], STATUS_PENDING)
        self.assertEqual(body["candidate"]["status"], STATUS_PENDING)
        self.assertEqual(body["candidate"]["blocks"][-1]["status"], STATUS_PENDING)

    def test_plain_export_rebuilds_after_adoption(self) -> None:
        # A strictly longer alternative: genesis + four blocks beats the
        # canonical chain of four blocks (0..3) on length.
        specs = [
            [(self.ka, self.A, self.B, 40)],
            [(self.kb, self.B, self.A, 5)],
            [(self.ka, self.A, self.B, 7)],
            [(self.kb, self.B, self.A, 2)],
        ]
        blocks = make_full_fork(self.genesis, specs)
        status, received = self.plain_full("plain-adopt", blocks=blocks)
        self.assertEqual(status, 201, received)
        self.assertEqual(self.service.adopt_fork(received["tip_hash"])[0], 200)
        # The candidate is no longer in forks; export resolves the canonical
        # prefix and adds no new authoritative copy.
        self.assertNotIn(received["tip_hash"], self.store.forks)
        status, body = self.export("plain-adopt", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tip_hash"], received["tip_hash"])
        self.assertEqual(body["length"], 5)
        self.assertEqual(
            body["candidate"]["blocks"],
            [b.to_dict() for b in self.store.chain],
        )
        self.assertEqual(len(self.store.forks), 0)

    # -- attested ------------------------------------------------------------

    def test_attested_hit_retains_signed_bare_list(self) -> None:
        blocks = make_full_fork(
            self.genesis, [[(self.ka, self.A, self.B, 97)]]
        )
        candidate = [b.to_dict() for b in blocks]
        status, received = self.attested_full("att-hit", candidate=candidate)
        self.assertEqual(status, 201, received)
        status, body = self.export("att-hit", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body.keys()), EXPORT_KEYS)
        self.assertEqual(body["mode"], "attested")
        # The signed candidate is retained in its exact delivered form (a
        # bare list here), never re-wrapped.
        self.assertIsInstance(body["candidate"], list)
        self.assertEqual(body["candidate"], candidate)
        attestation = body["attestation"]
        self.assertEqual(list(attestation.keys()), ATTESTATION_KEYS)
        self.assertEqual(attestation["public_key"], self.A)
        self.assertEqual(attestation["version"], 1)
        rec = self.store.attested_syncs[("node-x", "att-hit")]
        self.assertEqual(attestation["signature"], rec["attested"]["signature"])
        self.assertEqual(body["tip_hash"], received["tip_hash"])

    def test_attested_hit_retains_export_object_form(self) -> None:
        blocks = make_full_fork(
            self.genesis, [[(self.ka, self.A, self.B, 96)]]
        )
        candidate = {
            "tip_hash": blocks[-1].block_hash,
            "height": blocks[-1].height,
            "length": len(blocks),
            "status": blocks[-1].status,
            "blocks": [b.to_dict() for b in blocks],
        }
        status, received = self.attested_full("att-doc", candidate=candidate)
        self.assertEqual(status, 201, received)
        status, body = self.export("att-doc", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["candidate"], candidate)
        self.assertEqual(body["candidate"]["blocks"][0], self.genesis.to_dict())

    def test_attested_export_survives_key_rotation_and_adoption(self) -> None:
        blocks = make_full_fork(
            self.genesis,
            [
                [(self.ka, self.A, self.B, 40)],
                [(self.kb, self.B, self.A, 5)],
                [(self.ka, self.A, self.B, 7)],
                [(self.kb, self.B, self.A, 2)],
            ],
        )
        candidate = [b.to_dict() for b in blocks]
        status, received = self.attested_full("att-adopt", candidate=candidate)
        self.assertEqual(status, 201, received)
        # Rotate to a new key; the frozen-key export must still verify.
        kn, new_pub = keypair()
        self.assertEqual(
            self.service.rotate_trust_source(
                "node-x",
                {"public_key": new_pub, "expires_at": self.exp,
                 "expected_version": 1},
            )[0],
            200,
        )
        status, pre_adopt = self.export("att-adopt", "attested")
        self.assertEqual(status, 200)
        self.assertEqual(pre_adopt["attestation"]["public_key"], self.A)
        # Adopt; the export resolves the canonical prefix while the
        # attestation still binds the signed candidate.
        self.assertEqual(self.service.adopt_fork(received["tip_hash"])[0], 200)
        status, body = self.export("att-adopt", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tip_hash"], received["tip_hash"])
        self.assertEqual(body["length"], 5)
        self.assertEqual(body["candidate"], candidate)
        self.assertEqual(body["attestation"]["public_key"], self.A)

    # -- parameter validation -------------------------------------------------

    def test_parameter_validation_is_400(self) -> None:
        good = {"source": "node-x", "request_id": "plain-hit", "mode": "plain"}
        self.assertEqual(self.plain_full("plain-hit")[0], 201)
        # Missing parameter.
        self.assertEqual(self.service.export_fork_sync(
            {"source": "node-x", "request_id": "plain-hit"})[0], 400)
        self.assertEqual(self.service.export_fork_sync(
            {"source": "node-x", "mode": "plain"})[0], 400)
        self.assertEqual(self.service.export_fork_sync(
            {"request_id": "plain-hit", "mode": "plain"})[0], 400)
        # Empty values.
        for params in (
            {"source": "", "request_id": "r", "mode": "plain"},
            {"source": "s", "request_id": "", "mode": "plain"},
        ):
            self.assertEqual(self.service.export_fork_sync(params)[0], 400)
        # Non-string values.
        self.assertEqual(self.service.export_fork_sync(
            {"source": 1, "request_id": "r", "mode": "plain"})[0], 400)
        # Bad mode (only plain/attested; "all" is a listing filter, not an
        # export mode).
        self.assertEqual(self.service.export_fork_sync(
            {"source": "node-x", "request_id": "plain-hit", "mode": "all"})[0], 400)
        self.assertEqual(self.service.export_fork_sync(
            {"source": "node-x", "request_id": "plain-hit", "mode": ""})[0], 400)
        self.assertEqual(self.service.export_fork_sync(
            {"source": "node-x", "request_id": "plain-hit",
             "mode": "ATTESTED"})[0], 400)
        # Unknown parameter.
        bad = dict(good)
        bad["extra"] = "1"
        self.assertEqual(self.service.export_fork_sync(bad)[0], 400)
        bad = dict(good)
        bad["limit"] = "10"
        self.assertEqual(self.service.export_fork_sync(bad)[0], 400)

    # -- 404 / namespace / range 409 -----------------------------------------

    def test_unknown_record_is_404(self) -> None:
        self.assertEqual(self.export("ghost", "plain")[0], 404)
        self.assertEqual(self.export("ghost", "attested")[0], 404)
        self.assertEqual(
            self.service.export_fork_sync(
                {"source": "ghost-source", "request_id": "r", "mode": "plain"}
            )[0],
            404,
        )

    def test_mode_namespaces_are_distinct(self) -> None:
        self.assertEqual(self.plain_full("only-plain")[0], 201)
        self.assertEqual(self.attested_full("only-att")[0], 201)
        self.assertEqual(self.export("only-plain", "attested")[0], 404)
        self.assertEqual(self.export("only-att", "plain")[0], 404)
        self.assertEqual(self.export("only-plain", "plain")[0], 200)
        self.assertEqual(self.export("only-att", "attested")[0], 200)

    def test_plain_range_hit_is_409(self) -> None:
        self.assertEqual(self.plain_range()[0], 201)
        status, body = self.export("range-1", "plain")
        self.assertEqual(status, 409, body)

    def test_attested_range_hit_is_409(self) -> None:
        self.assertEqual(self.attested_range()[0], 201)
        status, body = self.export("arange-1", "attested")
        self.assertEqual(status, 409, body)

    def test_expired_record_is_404_and_audit_kept(self) -> None:
        status, received = self.plain_full(
            "plain-exp", expires_at=int(time.time()) + 1
        )
        self.assertEqual(status, 201)
        time.sleep(1.1)
        status, body = self.export("plain-exp", "plain")
        self.assertEqual(status, 404, body)
        self.assertNotIn(("node-x", "plain-exp"), self.store.syncs)
        self.assertNotIn(received["tip_hash"], self.store.forks)
        # The append-only history survives the cleanup.
        kinds = [e["kind"] for e in self.store.audit_events]
        self.assertIn("sync_received", kinds)
        self.assertIn("sync_expired", kinds)
        history_status, history = self.service.list_fork_sync_history({})
        self.assertEqual(history_status, 200)
        self.assertGreaterEqual(history["total"], 2)

    def test_expired_attested_record_is_404(self) -> None:
        status, received = self.attested_full(
            "att-exp", expires_at=int(time.time()) + 1
        )
        self.assertEqual(status, 201)
        time.sleep(1.1)
        status, body = self.export("att-exp", "attested")
        self.assertEqual(status, 404, body)
        self.assertNotIn(received["tip_hash"], self.store.forks)

    def test_tampered_fingerprint_or_signature_is_404(self) -> None:
        self.assertEqual(self.plain_full("plain-tamper")[0], 201)
        rec = self.store.syncs[("node-x", "plain-tamper")]
        original_fp = rec["fingerprint"]
        rec["fingerprint"] = "0" * 64
        self.assertEqual(self.export("plain-tamper", "plain")[0], 404)
        rec["fingerprint"] = original_fp
        self.assertEqual(self.export("plain-tamper", "plain")[0], 200)
        # Frozen summary disagreement is a silent miss too.
        rec["height"] = 999
        self.assertEqual(self.export("plain-tamper", "plain")[0], 404)
        rec["height"] = 1
        self.assertEqual(self.export("plain-tamper", "plain")[0], 200)

        self.assertEqual(self.attested_full("att-tamper")[0], 201)
        arec = self.store.attested_syncs[("node-x", "att-tamper")]
        original_sig = arec["attested"]["signature"]
        arec["attested"]["signature"] = "a" * 128
        self.assertEqual(self.export("att-tamper", "attested")[0], 404)
        arec["attested"]["signature"] = original_sig
        self.assertEqual(self.export("att-tamper", "attested")[0], 200)
        # A fingerprint that no longer matches (rotated signed content).
        arec["fingerprint"] = "f" * 64
        self.assertEqual(self.export("att-tamper", "attested")[0], 404)

    def test_unresolvable_tip_is_404(self) -> None:
        status, received = self.plain_full("plain-dangle")
        self.assertEqual(status, 201)
        self.store.forks.pop(received["tip_hash"])
        self.assertEqual(self.export("plain-dangle", "plain")[0], 404)

    # -- restart --------------------------------------------------------------

    def test_restart_plain_export_is_identical(self) -> None:
        self.assertEqual(self.plain_full("plain-restart")[0], 201)
        status, before = self.export("plain-restart", "plain")
        self.assertEqual(status, 200)
        self.store = LedgerStore(self.path)
        self.service = LedgerService(self.store)
        status, after = self.service.export_fork_sync(
            {"source": "node-x", "request_id": "plain-restart", "mode": "plain"}
        )
        self.assertEqual(status, 200, after)
        self.assertEqual(after, before)

    def test_restart_attested_export_is_identical(self) -> None:
        self.assertEqual(self.attested_full("att-restart")[0], 201)
        status, before = self.export("att-restart", "attested")
        self.assertEqual(status, 200)
        self.store = LedgerStore(self.path)
        self.service = LedgerService(self.store)
        status, after = self.service.export_fork_sync(
            {"source": "node-x", "request_id": "att-restart", "mode": "attested"}
        )
        self.assertEqual(status, 200, after)
        self.assertEqual(after, before)
        self.assertEqual(after["attestation"]["public_key"], self.A)

    def test_restart_drops_tampered_attested_keeps_audit(self) -> None:
        status, received = self.attested_full("att-tamper-restart")
        self.assertEqual(status, 201)
        received_events = len(self.store.audit_events)
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        for rec in raw["attested_syncs"]:
            if rec.get("request_id") == "att-tamper-restart":
                rec["attested"]["signature"] = "b" * 128
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, sort_keys=True)
        self.store = LedgerStore(self.path)
        self.service = LedgerService(self.store)
        self.assertNotIn(
            ("node-x", "att-tamper-restart"), self.store.attested_syncs
        )
        self.assertNotIn(received["tip_hash"], self.store.forks)
        # Audit history is preserved verbatim...
        self.assertEqual(len(self.store.audit_events), received_events)
        # ...so the export now misses (404) but the lifecycle is still
        # auditable.
        status, body = self.service.export_fork_sync(
            {"source": "node-x", "request_id": "att-tamper-restart",
             "mode": "attested"}
        )
        self.assertEqual(status, 404, body)

    # -- save failure during the lazy sweep -----------------------------------

    def test_failed_sweep_save_restores_state_and_raises_oserror(self) -> None:
        status, received = self.plain_full(
            "plain-sweepfail", expires_at=int(time.time()) + 1
        )
        self.assertEqual(status, 201)
        time.sleep(1.1)
        gen = self.store.generation
        n_events = len(self.store.audit_events)

        def failing() -> None:
            raise OSError("disk full")

        self.store.save = failing  # type: ignore[method-assign]
        try:
            with self.assertRaises(OSError):
                self.export("plain-sweepfail", "plain")
        finally:
            del self.store.save
        # Pre-sweep state fully restored.
        self.assertIn(("node-x", "plain-sweepfail"), self.store.syncs)
        self.assertIn(received["tip_hash"], self.store.forks)
        self.assertEqual(self.store.generation, gen)
        self.assertEqual(len(self.store.audit_events), n_events)
        # A subsequent (successful) sweep completes the expiry: 404.
        status, body = self.export("plain-sweepfail", "plain")
        self.assertEqual(status, 404, body)


class SyncExportHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"))
        )
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
    def request_raw(cls, path: str) -> tuple[int, str]:
        req = urllib.request.Request(f"{cls.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def _deliver_plain(self, request_id: str, amount: int) -> str:
        genesis = self.service.store.chain[0]
        tail = make_linked(
            genesis.block_hash, 1, [[(self.ka, self.A, keypair()[1], amount)]]
        )
        candidate = {
            "tip_hash": tail[-1].block_hash,
            "height": tail[-1].height,
            "length": 1 + len(tail),
            "status": tail[-1].status,
            "blocks": [genesis.to_dict(), *[b.to_dict() for b in tail]],
        }
        status, body = self.service.submit_fork_sync({
            "source": "http-x",
            "request_id": request_id,
            "expires_at": self.exp,
            "candidate": candidate,
        })
        self.assertEqual(status, 201, body)
        return body["tip_hash"]

    def test_plain_export_over_http_key_order(self) -> None:
        tip = self._deliver_plain("hp", 11)
        status, raw = self.request_raw(
            "/v1/forks/sync/export?source=http-x&request_id=hp&mode=plain"
        )
        self.assertEqual(status, 200, raw)
        body = json.loads(raw)
        self.assertEqual(list(body.keys()), EXPORT_KEYS)
        self.assertEqual(body["tip_hash"], tip)
        self.assertIsNone(body["attestation"])
        self.assertEqual(list(body["candidate"].keys()), PLAIN_CANDIDATE_KEYS)
        # The raw wire document really is in the fixed order, not sorted.
        self.assertLess(raw.index('"source"'), raw.index('"request_id"'))
        self.assertLess(raw.index('"request_id"'), raw.index('"mode"'))
        self.assertLess(raw.index('"mode"'), raw.index('"expires_at"'))
        self.assertLess(raw.index('"candidate"'), raw.index('"attestation"'))

    def test_attested_export_over_http(self) -> None:
        genesis = self.service.store.chain[0]
        tail = make_linked(
            genesis.block_hash, 1, [[(self.ka, self.A, keypair()[1], 12)]]
        )
        candidate = [genesis.to_dict(), *[b.to_dict() for b in tail]]
        message = attested_message("http-x", "ha", self.exp, candidate)
        signature = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(message).digest()
        )
        status, body = self.service.submit_fork_sync_attested({
            "source": "http-x",
            "request_id": "ha",
            "expires_at": self.exp,
            "candidate": candidate,
            "signature": signature,
        })
        self.assertEqual(status, 201, body)
        status, raw = self.request_raw(
            "/v1/forks/sync/export?source=http-x&request_id=ha&mode=attested"
        )
        self.assertEqual(status, 200, raw)
        exported = json.loads(raw)
        self.assertEqual(exported["mode"], "attested")
        self.assertEqual(list(exported["attestation"].keys()), ATTESTATION_KEYS)
        self.assertEqual(exported["attestation"]["public_key"], self.A)

    def test_http_parameter_errors(self) -> None:
        # Repeated parameter.
        status, raw = self.request_raw(
            "/v1/forks/sync/export?source=http-x&source=other"
            "&request_id=hp&mode=plain"
        )
        self.assertEqual(status, 400, raw)
        # Unknown parameter.
        status, _ = self.request_raw(
            "/v1/forks/sync/export?source=http-x&request_id=hp&mode=plain&bogus=1"
        )
        self.assertEqual(status, 400)
        # Missing / blank / bad mode.
        self.assertEqual(
            self.request_raw(
                "/v1/forks/sync/export?source=http-x&request_id=hp"
            )[0],
            400,
        )
        self.assertEqual(
            self.request_raw(
                "/v1/forks/sync/export?source=&request_id=hp&mode=plain"
            )[0],
            400,
        )
        self.assertEqual(
            self.request_raw(
                "/v1/forks/sync/export?source=http-x&request_id=hp&mode=all"
            )[0],
            400,
        )

    def test_http_unknown_is_404_and_range_is_409(self) -> None:
        status, _ = self.request_raw(
            "/v1/forks/sync/export?source=http-x&request_id=nope&mode=plain"
        )
        self.assertEqual(status, 404)
        # Deliver a plain range and confirm the 409 over HTTP.
        store = self.service.store
        tail = make_linked(
            store.chain[0].block_hash, 1,
            [[(self.ka, self.A, keypair()[1], 13)]],
        )
        end = tail[-1]
        anchor = {"height": 0, "block_hash": store.chain[0].block_hash}
        blocks = [b.to_dict() for b in tail]
        tip = {
            "tip_hash": end.block_hash, "height": 1, "length": 2,
            "status": "confirmed",
        }
        status, body = self.service.submit_fork_sync_range({
            "source": "http-x", "request_id": "hr", "expires_at": self.exp,
            "anchor": anchor, "blocks": blocks, "tip": tip,
        })
        self.assertEqual(status, 201, body)
        status, raw = self.request_raw(
            "/v1/forks/sync/export?source=http-x&request_id=hr&mode=plain"
        )
        self.assertEqual(status, 409, raw)


class SyncExportCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json"))
        )
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

    def run_cli(self, *args) -> tuple[int, dict, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1)
        return rc, json.loads(raw), raw

    def _deliver(self, request_id: str, amount: int, *, attested: bool = False):
        genesis = self.service.store.chain[0]
        tail = make_linked(
            genesis.block_hash, 1, [[(self.ka, self.A, keypair()[1], amount)]]
        )
        blocks = [genesis.to_dict(), *[b.to_dict() for b in tail]]
        if attested:
            message = attested_message("cli-x", request_id, self.exp, blocks)
            signature = crypto.sign_message(
                seed_of(self.ka), hashlib.sha256(message).digest()
            )
            return self.service.submit_fork_sync_attested({
                "source": "cli-x", "request_id": request_id,
                "expires_at": self.exp, "candidate": blocks,
                "signature": signature,
            })
        return self.service.submit_fork_sync({
            "source": "cli-x", "request_id": request_id,
            "expires_at": self.exp, "candidate": {"blocks": blocks},
        })

    def test_sync_export_cli_plain_and_attested(self) -> None:
        status, plain_body = self._deliver("cp", 21)
        self.assertEqual(status, 201, plain_body)
        rc, body, raw = self.run_cli(
            "sync-export", "--source", "cli-x", "--request-id", "cp",
            "--mode", "plain",
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(list(body.keys()), EXPORT_KEYS)
        self.assertEqual(body["tip_hash"], plain_body["tip_hash"])
        self.assertIsNone(body["attestation"])
        self.assertLess(raw.index('"source"'), raw.index('"attestation"'))

        status, att_body = self._deliver("ca", 22, attested=True)
        self.assertEqual(status, 201, att_body)
        rc, body, raw = self.run_cli(
            "sync-export", "--source", "cli-x", "--request-id", "ca",
            "--mode", "attested",
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["mode"], "attested")
        self.assertEqual(list(body["attestation"].keys()), ATTESTATION_KEYS)

    def test_sync_export_cli_non_2xx_exits_1(self) -> None:
        rc, body, _ = self.run_cli(
            "sync-export", "--source", "cli-x", "--request-id", "missing",
            "--mode", "plain",
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", body)

    def test_sync_export_cli_bad_mode_is_server_400(self) -> None:
        # The CLI forwards --mode verbatim; an invalid value must surface as
        # the server's single-line 400 JSON (exit 1), not an argparse exit 2.
        rc, body, _ = self.run_cli(
            "sync-export", "--source", "cli-x", "--request-id", "cp",
            "--mode", "all",
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for offline light-client bundle verification (ledger.light_client).

Covers input/auth/expired/integrity/proof categorization, Ed25519 bundle
signing over the canonical unsigned document, full chain recomputation from
the pinned genesis, response/candidate-summary cross-checks, proof uniqueness
and the pending-tip ban, plus the offline ``ledger verify`` CLI (file and
stdin input, exit codes and single-line JSON output).

Run: python3 tests/light_client_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    ERR_AUTH,
    ERR_EXPIRED,
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_PROOF,
    bundle_signing_digest,
    canonical_bundle_bytes,
    verify_bundle,
)
from ledger.models import STATUS_PENDING, Block, Transaction
from ledger.store import LedgerStore

NOW = 1_000_000_000
FUTURE = NOW + 10_000
PAST = NOW - 1
BOB = "b" * 64


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class LightClientFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice_pub = pub_hex(self.alice_key)

        self.genesis = LedgerStore.create_genesis()
        self.tx = Transaction(
            self.alice_pub, BOB, 100,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 100)
            ).hex(),
        )
        self.block1 = Block.create(1, self.genesis.block_hash, [self.tx])
        self.tx2 = Transaction(
            self.alice_pub, BOB, 50,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 50)
            ).hex(),
        )
        self.block_pending = Block.create(
            2, self.block1.block_hash, [self.tx2], status=STATUS_PENDING
        )
        self.chain = [self.genesis, self.block1]
        self.S = {
            "tip_hash": self.block1.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
        }
        self.proof_doc = self._proof(self.block1, self.tx.tx_id)
        self.trust = {
            "genesis_hash": self.genesis.block_hash,
            "sources": {
                "node-a": {"public_key": self.source_pub, "expires_at": FUTURE}
            },
            "allowlist": {"node-b": FUTURE},
        }

    @staticmethod
    def _proof(block: Block, tx_id: str) -> dict:
        ids = [t.tx_id for t in block.transactions]
        index = ids.index(tx_id)
        return {
            "height": block.height,
            "tx_id": tx_id,
            "index": index,
            "merkle_root": block.merkle_root,
            "block_hash": block.block_hash,
            "siblings": crypto.merkle_proof(ids, index),
        }

    def bundle(
        self,
        *,
        blocks=None,
        proofs=None,
        source="node-a",
        expires_at=FUTURE,
        response=None,
        sign=True,
        wrap=False,
    ) -> dict:
        blocks = self.chain if blocks is None else blocks
        if proofs is None:
            proofs = [{"height": self.block1.height, "proof": self.proof_doc}]
        candidate = [b.to_dict() for b in blocks]
        if wrap:
            candidate = {
                "tip_hash": blocks[-1].block_hash,
                "height": blocks[-1].height,
                "length": len(blocks),
                "status": blocks[-1].status,
                "blocks": candidate,
            }
        bundle = {
            "source": source,
            "expires_at": expires_at,
            "response": dict(self.S) if response is None else response,
            "candidate": candidate,
            "proofs": proofs,
        }
        if sign:
            bundle["signature"] = self.source_key.sign(
                bundle_signing_digest(bundle)
            ).hex()
        return bundle

    def resign(self, bundle: dict) -> dict:
        bundle.pop("signature", None)
        bundle["signature"] = self.source_key.sign(
            bundle_signing_digest(bundle)
        ).hex()
        return bundle


class SuccessTests(LightClientFixture):
    def test_signed_happy_path(self) -> None:
        result = verify_bundle(self.bundle(), self.trust, now=NOW)
        self.assertEqual(
            result,
            {
                "ok": True,
                "source": "node-a",
                "S": self.S,
                "verified_tx_ids": [self.tx.tx_id],
            },
        )

    def test_allowlisted_unsigned(self) -> None:
        result = verify_bundle(
            self.bundle(source="node-b", sign=False), self.trust, now=NOW
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["source"], "node-b")
        self.assertEqual(result["verified_tx_ids"], [self.tx.tx_id])

    def test_no_proofs(self) -> None:
        result = verify_bundle(self.bundle(proofs=[]), self.trust, now=NOW)
        self.assertTrue(result["ok"])
        self.assertEqual(result["verified_tx_ids"], [])

    def test_response_may_be_superset(self) -> None:
        result = verify_bundle(
            self.bundle(response={**self.S, "transaction_ids": [self.tx.tx_id]}),
            self.trust,
            now=NOW,
        )
        self.assertTrue(result["ok"])

    def test_export_wrapped_candidate(self) -> None:
        result = verify_bundle(self.bundle(wrap=True), self.trust, now=NOW)
        self.assertTrue(result["ok"])
        self.assertEqual(result["S"], self.S)

    def test_canonical_bytes_stable_and_signature_covers_unsigned(self) -> None:
        bundle = self.bundle()
        unsigned = {k: v for k, v in bundle.items() if k != "signature"}
        expected = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertEqual(canonical_bundle_bytes(bundle), expected)
        # Signature survives a key reorder of the outer bundle.
        reordered = {key: bundle[key] for key in reversed(list(bundle))}
        self.assertEqual(
            crypto.sha256_hex(canonical_bundle_bytes(reordered)),
            crypto.sha256_hex(expected),
        )


class AuthTests(LightClientFixture):
    def test_unknown_source(self) -> None:
        self.assertEqual(
            verify_bundle(self.bundle(source="stranger"), self.trust, now=NOW),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_keyed_source_without_signature(self) -> None:
        self.assertEqual(
            verify_bundle(self.bundle(sign=False), self.trust, now=NOW),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_allowlisted_source_with_signature(self) -> None:
        self.assertEqual(
            verify_bundle(self.bundle(source="node-b", sign=True), self.trust, now=NOW),
            {"ok": False, "error": ERR_AUTH},
        )


class ExpiryTests(LightClientFixture):
    def test_bundle_expired(self) -> None:
        self.assertEqual(
            verify_bundle(self.bundle(expires_at=PAST), self.trust, now=NOW),
            {"ok": False, "error": ERR_EXPIRED},
        )

    def test_bundle_deadline_equal_to_now_is_expired(self) -> None:
        self.assertEqual(
            verify_bundle(self.bundle(expires_at=NOW), self.trust, now=NOW),
            {"ok": False, "error": ERR_EXPIRED},
        )

    def test_source_entry_expired(self) -> None:
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = PAST
        self.assertEqual(
            verify_bundle(self.bundle(), trust, now=NOW),
            {"ok": False, "error": ERR_EXPIRED},
        )

    def test_allowlist_entry_expired(self) -> None:
        trust = json.loads(json.dumps(self.trust))
        trust["allowlist"]["node-b"] = PAST
        self.assertEqual(
            verify_bundle(
                self.bundle(source="node-b", sign=False), trust, now=NOW
            ),
            {"ok": False, "error": ERR_EXPIRED},
        )


class IntegrityTests(LightClientFixture):
    def test_bad_signature(self) -> None:
        bundle = self.bundle()
        bundle["signature"] = "00" * 64
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_post_signing_tamper(self) -> None:
        bundle = self.bundle()
        bundle["expires_at"] = FUTURE + 1  # unsigned content changed
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_wrong_pinned_genesis(self) -> None:
        trust = json.loads(json.dumps(self.trust))
        trust["genesis_hash"] = "1" * 64
        self.assertEqual(
            verify_bundle(self.bundle(), trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_tampered_block_hash(self) -> None:
        bundle = self.bundle()
        bundle["candidate"][1]["block_hash"] = "f" * 64
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_bad_transaction_signature(self) -> None:
        bundle = self.bundle()
        bundle["candidate"][1]["transactions"][0]["signature"] = "00" * 64
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_broken_prev_hash_linkage(self) -> None:
        bundle = self.bundle()
        bundle["candidate"][1]["prev_hash"] = "9" * 64
        # block_hash no longer matches prev_hash regardless of re-signing
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_response_descriptor_mismatch(self) -> None:
        bundle = self.bundle(
            response={
                "tip_hash": "e" * 64,
                "height": 1,
                "length": 2,
                "status": "confirmed",
            }
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_response_without_descriptor_fields(self) -> None:
        bundle = self.bundle(response={"unrelated": 1})
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_export_summary_mismatch(self) -> None:
        bundle = self.bundle(wrap=True)
        bundle["candidate"]["height"] = 9
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_duplicate_tx_id_across_blocks(self) -> None:
        # A transaction already included in block 1 reappearing in block 2
        # violates global tx_id uniqueness even though each block is otherwise
        # internally consistent.
        other = Transaction(
            self.alice_pub, BOB, 200,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 200)
            ).hex(),
        )
        duplicate_block = Block.create(
            2, self.block1.block_hash, [self.tx, other]
        )
        bundle = self.bundle(
            blocks=[self.genesis, self.block1, duplicate_block],
            proofs=[],
        )
        bundle["response"] = {
            "tip_hash": duplicate_block.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )


class ProofTests(LightClientFixture):
    def test_duplicate_proof(self) -> None:
        entry = {"height": 1, "proof": self.proof_doc}
        bundle = self.bundle(proofs=[entry, dict(entry)])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_proof_on_pending_tip_forbidden(self) -> None:
        pending_doc = self._proof(self.block_pending, self.tx2.tx_id)
        bundle = self.bundle(
            blocks=[self.genesis, self.block1, self.block_pending],
            response={
                "tip_hash": self.block_pending.block_hash,
                "height": 2,
                "length": 3,
                "status": "pending",
            },
            proofs=[{"height": 2, "proof": pending_doc}],
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_proof_block_hash_mismatch(self) -> None:
        evil = json.loads(json.dumps(self.proof_doc))
        evil["block_hash"] = "9" * 64
        bundle = self.bundle(proofs=[{"height": 1, "proof": evil}])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_proof_height_out_of_range(self) -> None:
        bundle = self.bundle(proofs=[{"height": 9, "proof": self.proof_doc}])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_proof_entry_height_differs_from_document(self) -> None:
        bundle = self.bundle(
            proofs=[{"height": 0, "proof": self.proof_doc}]
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_tampered_sibling_hash(self) -> None:
        tx_b = Transaction(
            self.alice_pub, BOB, 70,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 70)
            ).hex(),
        )
        block = Block.create(1, self.genesis.block_hash, [self.tx, tx_b])
        ids = sorted(t.tx_id for t in [self.tx, tx_b])
        index = ids.index(self.tx.tx_id)
        doc = {
            "height": 1,
            "tx_id": self.tx.tx_id,
            "index": index,
            "merkle_root": block.merkle_root,
            "block_hash": block.block_hash,
            "siblings": crypto.merkle_proof(ids, index),
        }
        doc["siblings"][0]["hash"] = "0" * 64
        S = {
            "tip_hash": block.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
        }
        bundle = self.bundle(
            blocks=[self.genesis, block],
            response=S,
            proofs=[{"height": 1, "proof": doc}],
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_proof_index_does_not_name_proof_tx(self) -> None:
        evil = json.loads(json.dumps(self.proof_doc))
        evil["index"] = 0
        evil["tx_id"] = "a" * 64
        bundle = self.bundle(proofs=[{"height": 1, "proof": evil}])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )


class InputTests(LightClientFixture):
    def test_malformed_bundles(self) -> None:
        for bad in (None, [], "x", 42, {}, {"source": "node-a"}):
            self.assertEqual(
                verify_bundle(bad, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
            )

    def test_missing_required_fields(self) -> None:
        good = self.bundle()
        for field in ("source", "expires_at", "response", "candidate", "proofs"):
            bad = dict(good)
            del bad[field]
            self.assertEqual(
                verify_bundle(bad, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
            )

    def test_malformed_trust(self) -> None:
        bad_documents = (
            None,
            {},
            {"genesis_hash": "zz"},
            {"genesis_hash": self.genesis.block_hash, "sources": []},
            {
                "genesis_hash": self.genesis.block_hash,
                "sources": {
                    "node-a": {"public_key": "abc", "expires_at": FUTURE}
                },
            },
            {"genesis_hash": self.genesis.block_hash, "allowlist": []},
            {
                "genesis_hash": self.genesis.block_hash,
                "allowlist": {"node-b": "soon"},
            },
        )
        for bad in bad_documents:
            self.assertEqual(
                verify_bundle(self.bundle(), bad, now=NOW),
                {"ok": False, "error": ERR_INPUT},
            )

    def test_bool_expiry_rejected(self) -> None:
        bundle = self.bundle()
        bundle["expires_at"] = True
        bundle.pop("signature", None)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_non_dict_response_rejected(self) -> None:
        bundle = self.bundle(response=["not", "an", "object"])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_empty_candidate_rejected(self) -> None:
        bundle = self.bundle()
        bundle["candidate"] = []
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_string_height_in_candidate_rejected(self) -> None:
        bundle = self.bundle()
        bundle["candidate"][1]["height"] = "1"
        self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )


class CliTests(LightClientFixture):
    def _live_trust(self) -> tuple[dict, int]:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = live
        trust["allowlist"]["node-b"] = live
        return trust, live

    def _run(self, bundle_text: str, trust: dict) -> subprocess.CompletedProcess:
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            bpath = Path(tmp) / "bundle.json"
            tpath = Path(tmp) / "trust.json"
            bpath.write_text(bundle_text)
            tpath.write_text(json.dumps(trust))
            env = dict(os.environ, PYTHONPATH=str(repo))
            return subprocess.run(
                [sys.executable, "-m", "ledger.cli", "verify",
                 "--bundle", str(bpath), "--trust", str(tpath)],
                capture_output=True,
                text=True,
                env=env,
            )

    def test_success_from_file_exit_zero_single_line(self) -> None:
        trust, live = self._live_trust()
        proc = self._run(json.dumps(self.bundle(expires_at=live)), trust)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
        body = json.loads(proc.stdout)
        self.assertTrue(body["ok"])
        self.assertEqual(body["S"], self.S)
        self.assertEqual(body["verified_tx_ids"], [self.tx.tx_id])

    def test_success_from_stdin(self) -> None:
        trust, live = self._live_trust()
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp) / "trust.json"
            tpath.write_text(json.dumps(trust))
            env = dict(os.environ, PYTHONPATH=str(repo))
            proc = subprocess.run(
                [sys.executable, "-m", "ledger.cli", "verify",
                 "--bundle", "-", "--trust", str(tpath)],
                input=json.dumps(self.bundle(expires_at=live)),
                capture_output=True,
                text=True,
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_failure_exit_one(self) -> None:
        trust, live = self._live_trust()
        proc = self._run(
            json.dumps(self.bundle(expires_at=live - 20_000)), trust
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            json.loads(proc.stdout), {"ok": False, "error": "expired"}
        )

    def test_unreadable_bundle_is_input_exit_one(self) -> None:
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp) / "trust.json"
            tpath.write_text(json.dumps(self._live_trust()[0]))
            env = dict(os.environ, PYTHONPATH=str(repo))
            proc = subprocess.run(
                [sys.executable, "-m", "ledger.cli", "verify",
                 "--bundle", str(Path(tmp) / "missing.json"),
                 "--trust", str(tpath)],
                capture_output=True,
                text=True,
                env=env,
            )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            json.loads(proc.stdout), {"ok": False, "error": "input"}
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

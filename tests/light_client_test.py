"""Tests for offline light-client bundle verification.

Covers ledger.light_client.verify_bundle and the ``ledger verify`` CLI:

* happy path over a recomputed chain (signed source, export candidate),
* input validation of bundle and trust documents,
* source trust/expiry and the signature policy (registered public key forces
  a signature; unsigned bundles pass only through the allowlist),
* Ed25519 signature over SHA256(sorted compact UTF-8 JSON) and tampering,
* chain recomputation against the trusted genesis hash (heights, prev_hash,
  tx_id, signatures, Merkle roots, block hashes, pending-only-at-tip),
* proof uniqueness and field consistency, Merkle verification, the pending-tip
  proof ban, and response/chain cross-checking,
* CLI file/stdin input, single-line JSON and exit codes.

Run: python3 tests/light_client_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import Block, Transaction
from ledger.light_client import verify_bundle

NOW = 1_000_000_000
# Year ~2096: must stay ahead of real wall-clock time for the CLI tests,
# which verify without injecting ``now``.
FAR_FUTURE = 4_000_000_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub_hex


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    msg = crypto.canonical_message(sender, to, amount)
    return Transaction(sender, to, amount, key.sign(msg).hex())


def sign_bundle(bundle: dict, key: Ed25519PrivateKey) -> str:
    canonical = json.dumps(
        {k: v for k, v in bundle.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return key.sign(hashlib.sha256(canonical).digest()).hex()


class LightClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        genesis = Block.create(0, "0" * 64, [], status="confirmed")
        t1 = make_tx(self.ka, self.A, self.B, 10)
        b1 = Block.create(1, genesis.block_hash, [t1], status="confirmed")
        t2 = make_tx(self.ka, self.A, self.B, 20)
        t3 = make_tx(self.kb, self.B, self.A, 5)
        b2 = Block.create(2, b1.block_hash, [t3, t2], status="confirmed")
        self.genesis, self.b1, self.b2 = genesis, b1, b2
        self.t1, self.t2, self.t3 = t1, t2, t3
        self.blocks = [genesis, b1, b2]
        ids2 = sorted([t2.tx_id, t3.tx_id])
        self.i2, self.i3 = ids2.index(t2.tx_id), ids2.index(t3.tx_id)
        self.p1 = self._proof([t1.tx_id], 0, b1)
        self.p2 = self._proof(ids2, self.i2, b2)
        self.p3 = self._proof(ids2, self.i3, b2)
        self.trust = {
            "genesis_hash": genesis.block_hash,
            "sources": {"node-1": [self.A, FAR_FUTURE]},
            "allowlist": {"node-anon": FAR_FUTURE},
        }

    @staticmethod
    def _proof(tx_ids: list[str], index: int, block: Block) -> dict:
        return {
            "tx_id": tx_ids[index],
            "index": index,
            "merkle_root": block.merkle_root,
            "block_hash": block.block_hash,
            "siblings": crypto.merkle_proof(tx_ids, index),
        }

    def bundle(self, *, source: str = "node-1", sign: bool = True,
               response: dict | None = None, blocks=None,
               proofs: list | None = None) -> dict:
        blocks = self.blocks if blocks is None else blocks
        proofs = [
            {"height": 1, "proof": self.p1},
            {"height": 2, "proof": self.p2},
            {"height": 2, "proof": self.p3},
        ] if proofs is None else proofs
        if response is None:
            response = {
                "items": [
                    {"tx_id": self.t1.tx_id, "height": 1,
                     "block_hash": self.b1.block_hash, "index": 0,
                     "from": self.A, "to": self.B, "amount": 10},
                    {"tx_id": self.t3.tx_id, "height": 2,
                     "block_hash": self.b2.block_hash, "index": self.i3,
                     "from": self.B, "to": self.A, "amount": 5},
                ],
                "total": 2,
                "next_cursor": None,
            }
        bundle = {
            "source": source,
            "expires_at": FAR_FUTURE,
            "response": response,
            "candidate": [b.to_dict() for b in blocks],
            "proofs": proofs,
        }
        if sign:
            bundle["signature"] = sign_bundle(bundle, self.ka)
        return bundle

    # -- happy path -----------------------------------------------------------

    def test_signed_happy_path(self):
        result = verify_bundle(self.bundle(), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["source"], "node-1")
        self.assertEqual(result["S"], {
            "tip_hash": self.b2.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        })
        self.assertEqual(
            result["verified_tx_ids"],
            sorted([self.t1.tx_id, self.t2.tx_id, self.t3.tx_id]),
        )

    def test_export_format_candidate(self):
        bundle = self.bundle()
        bundle["candidate"] = {
            "tip_hash": self.b2.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
            "blocks": [b.to_dict() for b in self.blocks],
        }
        bundle["signature"] = sign_bundle(bundle, self.ka)
        self.assertTrue(verify_bundle(bundle, self.trust, now=NOW)["ok"])

    def test_proof_object_response(self):
        bundle = self.bundle(response=dict(self.p1, height=1))
        self.assertTrue(verify_bundle(bundle, self.trust, now=NOW)["ok"])

    def test_pending_tip_summary_verifies_but_no_proof(self):
        bp = Block.create(
            3, self.b2.block_hash, [make_tx(self.ka, self.A, self.B, 1)],
            status="pending",
        )
        blocks = self.blocks + [bp]
        response = {
            "height": 3,
            "block_hash": bp.block_hash,
            "prev_hash": self.b2.block_hash,
            "merkle_root": bp.merkle_root,
            "status": "pending",
            "transaction_ids": [tx.tx_id for tx in bp.transactions],
        }
        # A proof anchored at the pending tip is rejected as a proof error.
        bad = self.bundle(blocks=blocks, response=response, proofs=[
            {"height": 1, "proof": self.p1},
            {"height": 3, "proof": self._proof(
                [bp.transactions[0].tx_id], 0, bp)},
        ])
        self.assertEqual(verify_bundle(bad, self.trust, now=NOW)["error"], "proof")
        # Without that proof the chain and its pending-tip summary verify.
        ok = self.bundle(blocks=blocks, response=response, proofs=[
            {"height": 1, "proof": self.p1},
            {"height": 2, "proof": self.p2},
            {"height": 2, "proof": self.p3},
        ])
        result = verify_bundle(ok, self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["S"]["status"], "pending")
        self.assertEqual(result["S"]["height"], 3)

    # -- input ----------------------------------------------------------------

    def test_input_errors(self):
        good = self.bundle()
        cases = [
            ("nope", self.trust),
            ({}, self.trust),
            (good, {}),
            (good, {"genesis_hash": "z" * 64}),
            (good, {"genesis_hash": self.genesis.block_hash,
                    "sources": []}),
            (dict(good, expires_at="100"), self.trust),
            (dict(good, source=""), self.trust),
            (dict(good, response=[]), self.trust),
            (dict(good, candidate={}), self.trust),
            (dict(good, proofs={}), self.trust),
            (dict(good, signature=123), self.trust),
            (good, {"genesis_hash": self.genesis.block_hash,
                    "sources": {"node-1": ["short", FAR_FUTURE]}}),
        ]
        for bundle, trust in cases:
            self.assertEqual(
                verify_bundle(bundle, trust, now=NOW)["error"], "input",
                f"expected input for {bundle!r}",
            )

    # -- auth / expiry --------------------------------------------------------

    def test_unknown_source_is_auth(self):
        bundle = self.bundle(source="stranger")
        self.assertEqual(verify_bundle(bundle, self.trust, now=NOW)["error"], "auth")

    def test_unsigned_from_signing_source_is_auth(self):
        bundle = self.bundle(sign=False)
        self.assertEqual(verify_bundle(bundle, self.trust, now=NOW)["error"], "auth")

    def test_unsigned_allowlisted_source_ok(self):
        bundle = self.bundle(source="node-anon", sign=False)
        self.assertTrue(verify_bundle(bundle, self.trust, now=NOW)["ok"])

    def test_signed_without_registered_key_is_auth(self):
        bundle = self.bundle(source="node-anon")
        self.assertEqual(verify_bundle(bundle, self.trust, now=NOW)["error"], "auth")

    def test_expired_bundle_and_source(self):
        bundle = self.bundle()
        bundle["expires_at"] = NOW - 1
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "expired"
        )
        trust = dict(self.trust, sources={"node-1": [self.A, NOW - 10]})
        self.assertEqual(
            verify_bundle(self.bundle(), trust, now=NOW)["error"], "expired"
        )
        trust = dict(self.trust, allowlist={"node-anon": NOW - 10})
        bundle = self.bundle(source="node-anon", sign=False)
        self.assertEqual(
            verify_bundle(bundle, trust, now=NOW)["error"], "expired"
        )

    def test_signed_requires_live_source_entry(self):
        # Source expired in sources but alive in allowlist: a signature still
        # needs its registered key entry to be live, so it fails expired; the
        # unsigned variant is blocked by the registered-key policy.
        trust = {
            "genesis_hash": self.genesis.block_hash,
            "sources": {"node-x": [self.A, NOW - 10]},
            "allowlist": {"node-x": FAR_FUTURE},
        }
        self.assertEqual(
            verify_bundle(self.bundle(source="node-x"), trust, now=NOW)["error"],
            "expired",
        )
        self.assertEqual(
            verify_bundle(self.bundle(source="node-x", sign=False), trust, now=NOW)[
                "error"
            ],
            "auth",
        )

    def test_null_deadline_never_expires(self):
        trust = {
            "genesis_hash": self.genesis.block_hash,
            "sources": {"node-1": [self.A, None]},
            "allowlist": {},
        }
        self.assertTrue(verify_bundle(self.bundle(), trust, now=NOW)["ok"])

    def test_null_allowlist_deadline_never_expires(self):
        trust = {
            "genesis_hash": self.genesis.block_hash,
            "sources": {},
            "allowlist": {"node-anon": None},
        }
        bundle = self.bundle(source="node-anon", sign=False)
        self.assertTrue(verify_bundle(bundle, trust, now=NOW)["ok"])

    def test_registered_key_forces_signature_even_when_allowlisted(self):
        trust = {
            "genesis_hash": self.genesis.block_hash,
            "sources": {"node-1": [self.A, FAR_FUTURE]},
            "allowlist": {"node-1": FAR_FUTURE},
        }
        self.assertEqual(
            verify_bundle(self.bundle(sign=False), trust, now=NOW)["error"], "auth"
        )
        self.assertTrue(
            verify_bundle(self.bundle(), trust, now=NOW)["ok"]
        )

    # -- integrity ------------------------------------------------------------

    def test_bad_signature_is_integrity(self):
        bundle = self.bundle()
        bundle["signature"] = "00" * 64
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "integrity"
        )

    def test_wrong_signing_key_is_integrity(self):
        kc, C = keypair()
        trust = dict(self.trust, sources={"node-1": [C, FAR_FUTURE]})
        self.assertEqual(
            verify_bundle(self.bundle(), trust, now=NOW)["error"], "integrity"
        )

    def test_wrong_genesis_is_integrity(self):
        trust = dict(self.trust, genesis_hash="f" * 64)
        self.assertEqual(
            verify_bundle(self.bundle(), trust, now=NOW)["error"], "integrity"
        )

    def test_tampered_block_is_integrity(self):
        bundle = self.bundle()
        bundle["candidate"][1]["block_hash"] = "f" * 64
        bundle["signature"] = sign_bundle(bundle, self.ka)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "integrity"
        )

    def test_tampered_tx_signature_is_integrity(self):
        bundle = self.bundle()
        bundle["candidate"][1]["transactions"][0]["signature"] = "00" * 64
        bundle["signature"] = sign_bundle(bundle, self.ka)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "integrity"
        )

    def test_export_summary_lie_is_integrity(self):
        bundle = self.bundle()
        bundle["candidate"] = {
            "tip_hash": self.b2.block_hash,
            "height": 9,
            "length": 3,
            "status": "confirmed",
            "blocks": [b.to_dict() for b in self.blocks],
        }
        bundle["signature"] = sign_bundle(bundle, self.ka)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "integrity"
        )

    def test_tampered_response_is_integrity(self):
        bundle = self.bundle()
        bundle["response"]["items"][0]["amount"] = 999
        bundle["signature"] = sign_bundle(bundle, self.ka)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "integrity"
        )

    def test_claim_without_proof_is_integrity(self):
        bundle = self.bundle(proofs=[{"height": 1, "proof": self.p1}])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "integrity"
        )

    def test_bad_prev_hash_is_integrity(self):
        chain = json.loads(json.dumps([b.to_dict() for b in self.blocks]))
        chain[2]["prev_hash"] = "f" * 64
        bundle = self.bundle(blocks=[Block.from_dict(block) for block in chain])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "integrity"
        )

    # -- proofs ---------------------------------------------------------------

    def test_duplicate_proof_is_proof_error(self):
        proofs = [
            {"height": 1, "proof": self.p1},
            {"height": 2, "proof": self.p2},
            {"height": 2, "proof": self.p3},
            {"height": 1, "proof": self.p1},
        ]
        bundle = self.bundle(proofs=proofs)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "proof"
        )

    def test_proof_height_mismatch_is_proof_error(self):
        bundle = self.bundle(proofs=[
            {"height": 2, "proof": self.p1},
            {"height": 2, "proof": self.p2},
            {"height": 2, "proof": self.p3},
        ])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "proof"
        )

    def test_bad_sibling_is_proof_error(self):
        bundle = self.bundle()
        bundle["proofs"][1]["proof"]["siblings"][0]["hash"] = "a" * 64
        bundle["signature"] = sign_bundle(bundle, self.ka)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "proof"
        )

    def test_proof_index_out_of_range_is_proof_error(self):
        p = dict(self.p1, index=1)
        bundle = self.bundle(proofs=[{"height": 1, "proof": p}])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "proof"
        )

    def test_proof_block_field_mismatch_is_proof_error(self):
        p = dict(self.p1, block_hash=self.b2.block_hash)
        bundle = self.bundle(proofs=[{"height": 1, "proof": p}])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "proof"
        )

    def test_inner_proof_height_must_match_wrapper(self):
        p = dict(self.p1, height=2)
        bundle = self.bundle(proofs=[{"height": 1, "proof": p}])
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW)["error"], "proof"
        )

    # -- CLI ------------------------------------------------------------------

    def test_cli_file_success_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = os.path.join(directory, "bundle.json")
            trust_path = os.path.join(directory, "trust.json")
            with open(bundle_path, "w", encoding="utf-8") as fh:
                json.dump(self.bundle(), fh)
            with open(trust_path, "w", encoding="utf-8") as fh:
                json.dump(self.trust, fh)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["verify", "--bundle", bundle_path,
                               "--trust", trust_path])
            self.assertEqual(rc, 0)
            lines = buf.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertTrue(json.loads(lines[0])["ok"])

            bad = self.bundle(proofs=[
                {"height": 1, "proof": self.p1},
                {"height": 2, "proof": self.p2},
                {"height": 2, "proof": self.p3},
                {"height": 1, "proof": self.p1},
            ])
            with open(bundle_path, "w", encoding="utf-8") as fh:
                json.dump(bad, fh)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["verify", "--bundle", bundle_path,
                               "--trust", trust_path])
            self.assertEqual(rc, 1)
            self.assertEqual(json.loads(buf.getvalue())["error"], "proof")

    def test_cli_stdin_and_bad_input_file(self):
        with tempfile.TemporaryDirectory() as directory:
            trust_path = os.path.join(directory, "trust.json")
            with open(trust_path, "w", encoding="utf-8") as fh:
                json.dump(self.trust, fh)
            old_stdin = sys.stdin
            try:
                sys.stdin = io.StringIO(json.dumps(self.bundle()))
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main(["verify", "--bundle", "-",
                                   "--trust", trust_path])
                self.assertEqual(rc, 0)
                self.assertTrue(json.loads(buf.getvalue())["ok"])

                sys.stdin = io.StringIO("not json")
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main(["verify", "--bundle", "-",
                                   "--trust", trust_path])
                self.assertEqual(rc, 1)
                self.assertEqual(json.loads(buf.getvalue())["error"], "input")
            finally:
                sys.stdin = old_stdin


if __name__ == "__main__":
    unittest.main(verbosity=2)

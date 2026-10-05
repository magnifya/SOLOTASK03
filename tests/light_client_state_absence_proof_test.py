"""Tests for the account-absence extension of offline bundle verification.

Covers the optional ``state_absence_proofs`` field of
``ledger.light_client.verify_bundle``:

* combination rules with the four anchor fields (``state_root`` /
  ``state_height`` / ``state_block_hash`` / ``state_proofs``): the array
  alone or any missing anchor field is ``input``, and the bundle must carry
  at least one kind of state proof;
* strict per-item / per-document key sets and JSON types of the four-field
  absence document (``input``);
* anchor binding of every item height and embedded state document, target
  uniqueness, no overlap with inclusion proofs, absence from the rebuilt
  anchor account set and the full predecessor/successor, adjacency,
  boundary and empty-tree rules (``proof``);
* the success result gaining ascending ``verified_absent_accounts`` while
  legacy (inclusion-only and state-less) result shapes are unchanged, the
  new field being covered by the bundle signature, and the CLI verify
  command passing the result through with the existing exit codes.

Run: python3 tests/light_client_state_absence_proof_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from bisect import bisect_left
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_PROOF,
    bundle_signing_digest,
    verify_bundle,
)
from ledger.models import Block, Transaction
from ledger.store import LedgerStore

NOW = 1_000_000_000
FUTURE = NOW + 10_000
ENDOWMENT = 100_000


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction(
        sender, to, amount, key.sign(crypto.canonical_message(sender, to, amount)).hex()
    )


class AbsenceBundleFixture(unittest.TestCase):
    """A three-account chain (genesis + two confirmed blocks) with a keyed
    source; ``bundle()`` mirrors the legacy builder and adds the state
    extension (inclusion and/or absence proofs) anchored at height 2."""

    def setUp(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice = pub_hex(self.alice_key)
        self.carol_key = Ed25519PrivateKey.generate()
        self.carol = pub_hex(self.carol_key)
        self.bob = "b" * 64

        self.genesis = LedgerStore.create_genesis()
        self.tx1 = signed_tx(self.alice_key, self.alice, self.bob, 100)
        self.block1 = Block.create(1, self.genesis.block_hash, [self.tx1])
        self.tx2 = signed_tx(self.carol_key, self.carol, self.alice, 40)
        self.block2 = Block.create(2, self.block1.block_hash, [self.tx2])
        self.chain = [self.genesis, self.block1, self.block2]
        self.S = {
            "tip_hash": self.block2.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        self.trust = {
            "genesis_hash": self.genesis.block_hash,
            "sources": {
                "node-a": {"public_key": self.source_pub, "expires_at": FUTURE}
            },
        }
        # Absent targets framing the account set from every side: below the
        # first account, above the last (``z`` sorts past any hex name) and
        # between two neighbours.
        names = sorted([self.alice, self.bob, self.carol])
        self.target_before = "0" * 64
        self.target_after = "z" * 64
        middle = names[1]
        self.target_between = middle[:-1] + ("0" if middle[-1] != "0" else "1")
        self.assertNotIn(self.target_between, names)

    # -- state tree helpers --------------------------------------------------

    def state_rows(self, blocks: list[Block]) -> list[tuple[str, int, list[str]]]:
        return LedgerStore.account_state_rows(blocks, ENDOWMENT)

    def state_root(self, rows) -> tuple[str, list[str]]:
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        return crypto.account_state_root(leaves), leaves

    def account_proof(
        self, rows, leaves, root, height: int, block_hash: str, account: str
    ) -> dict:
        index = [name for name, _b, _t in rows].index(account)
        name, balance, transactions = rows[index]
        return {
            "account": name,
            "balance": balance,
            "confirmed_transactions": transactions,
            "index": index,
            "state_root": root,
            "height": height,
            "block_hash": block_hash,
            "siblings": crypto.merkle_proof(leaves, index),
        }

    def absence_proof(
        self, rows, leaves, root, height: int, block_hash: str, account: str
    ) -> dict:
        """The plain four-field absence document, built exactly like the
        server's ``GET /v1/accounts/{account}/absence-proof`` response."""
        names = [name for name, _b, _t in rows]
        state = {
            "state_root": root,
            "height": height,
            "block_hash": block_hash,
            "account_count": len(rows),
        }

        def neighbor(index: int | None) -> dict | None:
            if index is None:
                return None
            name, balance, transactions = rows[index]
            return {
                "account": name,
                "balance": balance,
                "confirmed_transactions": transactions,
                "index": index,
                "state_root": root,
                "height": height,
                "block_hash": block_hash,
                "siblings": crypto.merkle_proof(leaves, index),
            }

        position = bisect_left(names, account)
        lower_index = position - 1 if position > 0 else None
        upper_index = position if position < len(rows) else None
        return {
            "account": account,
            "state": state,
            "lower": neighbor(lower_index),
            "upper": neighbor(upper_index),
        }

    def state_extension(
        self, height: int = 2, accounts=(), absent=()
    ) -> dict:
        """A valid state extension anchored at ``height`` with inclusion
        proofs for ``accounts`` and absence proofs for ``absent``."""
        prefix = self.chain[: height + 1]
        rows = self.state_rows(prefix)
        root, leaves = self.state_root(rows)
        block = self.chain[height]
        extension = {
            "state_root": root,
            "state_height": height,
            "state_block_hash": block.block_hash,
            "state_proofs": [
                {
                    "height": height,
                    "proof": self.account_proof(
                        rows, leaves, root, height, block.block_hash, account
                    ),
                }
                for account in accounts
            ],
        }
        if absent is not None:
            extension["state_absence_proofs"] = [
                {
                    "height": height,
                    "proof": self.absence_proof(
                        rows, leaves, root, height, block.block_hash, account
                    ),
                }
                for account in absent
            ]
        return extension

    # -- bundle builder ------------------------------------------------------

    def bundle(self, *, state=None, blocks=None, response=None, proofs=None) -> dict:
        blocks = self.chain if blocks is None else blocks
        bundle = {
            "source": "node-a",
            "expires_at": FUTURE,
            "response": dict(self.S) if response is None else response,
            "candidate": [b.to_dict() for b in blocks],
            "proofs": [] if proofs is None else proofs,
        }
        if state is not None:
            bundle.update(state)
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


class AbsenceSuccessTests(AbsenceBundleFixture):
    def test_absence_only_extension(self) -> None:
        state = self.state_extension(
            absent=[self.target_after, self.target_before, self.target_between]
        )
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["verified_absent_accounts"],
            sorted([self.target_after, self.target_before, self.target_between]),
        )
        self.assertEqual(result["verified_accounts"], [])
        self.assertEqual(result["verified_tx_ids"], [])
        self.assertEqual(result["S"], self.S)

    def test_mixed_inclusion_and_absence(self) -> None:
        state = self.state_extension(
            accounts=[self.bob], absent=[self.target_between]
        )
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], [self.bob])
        self.assertEqual(result["verified_absent_accounts"], [self.target_between])

    def test_empty_absence_list_keeps_legacy_output(self) -> None:
        state = self.state_extension(accounts=[self.bob], absent=[])
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertNotIn("verified_absent_accounts", result)
        self.assertEqual(result["verified_accounts"], [self.bob])

    def test_boundary_targets(self) -> None:
        # Below the first account: lower is None; above the last: upper None.
        state = self.state_extension(
            absent=[self.target_before, self.target_after]
        )
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["verified_absent_accounts"],
            sorted([self.target_before, self.target_after]),
        )

    def test_empty_tree_anchor(self) -> None:
        # Anchored at genesis the account set is empty: both neighbors null.
        state = self.state_extension(height=0, absent=[self.bob])
        proof = state["state_absence_proofs"][0]["proof"]
        self.assertIsNone(proof["lower"])
        self.assertIsNone(proof["upper"])
        self.assertEqual(proof["state"]["account_count"], 0)
        self.assertEqual(proof["state"]["state_root"], crypto.EMPTY_MERKLE_ROOT)
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_absent_accounts"], [self.bob])

    def test_historical_anchor_height(self) -> None:
        # Anchored at height 1 the account set is only {alice, bob}; carol
        # is still absent there.
        state = self.state_extension(height=1, absent=[self.carol])
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_absent_accounts"], [self.carol])

    def test_legacy_result_shapes_unchanged(self) -> None:
        result = verify_bundle(self.bundle(), self.trust, now=NOW)
        self.assertEqual(
            result,
            {"ok": True, "source": "node-a", "S": self.S, "verified_tx_ids": []},
        )
        state = self.state_extension(accounts=[self.alice], absent=None)
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertNotIn("verified_absent_accounts", result)

    def test_signature_covers_absence_proofs(self) -> None:
        bundle = self.bundle(state=self.state_extension(absent=[self.target_before]))
        # Tampering with the signed absence section breaks the signature.
        bundle["state_absence_proofs"][0]["proof"]["account"] = self.target_after
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_deterministic_repeated_verification(self) -> None:
        bundle = self.bundle(
            state=self.state_extension(
                accounts=[self.bob], absent=[self.target_between]
            )
        )
        first = verify_bundle(bundle, self.trust, now=NOW)
        second = verify_bundle(bundle, self.trust, now=NOW)
        self.assertEqual(first, second)
        self.assertTrue(first["ok"])


class AbsenceInputTests(AbsenceBundleFixture):
    def test_absence_array_without_anchor_fields(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        absence = state["state_absence_proofs"]
        bundle = self.bundle()
        bundle["state_absence_proofs"] = absence
        bundle = self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_absence_array_with_partial_anchor_fields(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        for dropped in ("state_root", "state_height", "state_block_hash",
                        "state_proofs"):
            partial = {k: v for k, v in state.items() if k != dropped}
            bundle = self.bundle(state=partial)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                dropped,
            )

    def test_no_state_proof_of_any_kind(self) -> None:
        state = self.state_extension(absent=[])
        self.assertEqual(
            verify_bundle(self.bundle(state=state), self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )
        state.pop("state_absence_proofs")
        self.assertEqual(
            verify_bundle(self.bundle(state=state), self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_absence_field_wrong_type(self) -> None:
        for bad in ("x", 5, {}, None, True):
            state = self.state_extension(accounts=[self.bob], absent=[])
            state["state_absence_proofs"] = bad
            self.assertEqual(
                verify_bundle(self.bundle(state=state), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad,
            )

    def test_item_key_set_and_types(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        item = state["state_absence_proofs"][0]
        for bad_item in (
            {"height": 2},
            {"proof": item["proof"]},
            {**item, "extra": 1},
            {"height": "2", "proof": item["proof"]},
            {"height": True, "proof": item["proof"]},
            {"height": 2, "proof": None},
        ):
            bad = dict(state)
            bad["state_absence_proofs"] = [bad_item]
            self.assertEqual(
                verify_bundle(self.bundle(state=bad), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad_item,
            )

    def test_proof_document_key_set(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        proof = state["state_absence_proofs"][0]["proof"]
        variants = []
        for dropped in ("account", "state", "lower", "upper"):
            variants.append({k: v for k, v in proof.items() if k != dropped})
        variants.append({**proof, "auth": {"key_version": 1, "signature": "0" * 128}})
        variants.append({**proof, "extra": 1})
        for bad_proof in variants:
            bad = dict(state)
            bad["state_absence_proofs"] = [{"height": 2, "proof": bad_proof}]
            self.assertEqual(
                verify_bundle(self.bundle(state=bad), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad_proof,
            )

    def test_target_account_shape(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        for bad_account in ("", 5, None, True):
            bad = json.loads(json.dumps(state))
            bad["state_absence_proofs"][0]["proof"]["account"] = bad_account
            self.assertEqual(
                verify_bundle(self.bundle(state=bad), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad_account,
            )

    def test_embedded_state_document_shape(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        good = state["state_absence_proofs"][0]["proof"]["state"]
        variants = [
            {k: v for k, v in good.items() if k != "account_count"},
            {**good, "extra": 1},
            {**good, "state_root": "AB" * 32},
            {**good, "height": True},
            {**good, "account_count": -1},
        ]
        for bad_state in variants:
            bad = json.loads(json.dumps(state))
            bad["state_absence_proofs"][0]["proof"]["state"] = bad_state
            self.assertEqual(
                verify_bundle(self.bundle(state=bad), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad_state,
            )

    def test_neighbor_document_shape(self) -> None:
        state = self.state_extension(absent=[self.target_between])
        good = state["state_absence_proofs"][0]["proof"]["lower"]
        self.assertIsNotNone(good)
        variants = [
            {k: v for k, v in good.items() if k != "siblings"},
            {**good, "extra": 1},
            {**good, "balance": -1},
            {**good, "siblings": [{"direction": "up", "hash": "0" * 64}]},
            {**good, "siblings": [{"direction": "left"}]},
        ]
        for bad_neighbor in variants:
            bad = json.loads(json.dumps(state))
            bad["state_absence_proofs"][0]["proof"]["lower"] = bad_neighbor
            self.assertEqual(
                verify_bundle(self.bundle(state=bad), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad_neighbor,
            )


class AbsenceProofFailureTests(AbsenceBundleFixture):
    def assert_proof_failure(self, state) -> None:
        self.assertEqual(
            verify_bundle(self.bundle(state=state), self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_item_height_mismatch(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        state["state_absence_proofs"][0]["height"] = 1
        self.assert_proof_failure(state)

    def test_embedded_state_anchor_mismatch(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        for field, bad in (
            ("state_root", "0" * 64),
            ("height", 1),
            ("block_hash", "0" * 64),
            ("account_count", 99),
        ):
            tampered = json.loads(json.dumps(state))
            tampered["state_absence_proofs"][0]["proof"]["state"][field] = bad
            self.assert_proof_failure(tampered)

    def test_neighbor_anchor_mismatch(self) -> None:
        state = self.state_extension(absent=[self.target_between])
        tampered = json.loads(json.dumps(state))
        tampered["state_absence_proofs"][0]["proof"]["lower"]["height"] = 1
        self.assert_proof_failure(tampered)

    def test_target_exists_in_anchor_set(self) -> None:
        state = self.state_extension(absent=[self.bob])
        self.assert_proof_failure(state)

    def test_target_collides_with_inclusion_proof(self) -> None:
        # Carol is a member of the anchor set; proving her inclusion and her
        # absence in one bundle is contradictory.
        state = self.state_extension(
            accounts=[self.alice], absent=[self.alice]
        )
        self.assert_proof_failure(state)

    def test_duplicate_targets(self) -> None:
        state = self.state_extension(
            absent=[self.target_before, self.target_before]
        )
        self.assert_proof_failure(state)

    def test_swapped_neighbors(self) -> None:
        state = self.state_extension(absent=[self.target_between])
        proof = state["state_absence_proofs"][0]["proof"]
        proof["lower"], proof["upper"] = proof["upper"], proof["lower"]
        self.assert_proof_failure(state)

    def test_non_adjacent_neighbors(self) -> None:
        # Frame the target with the first and last accounts: the indices are
        # not adjacent around a single gap.
        rows = self.state_rows(self.chain)
        root, leaves = self.state_root(rows)
        block = self.chain[2]
        state = self.state_extension(absent=[self.target_between])
        proof = state["state_absence_proofs"][0]["proof"]
        proof["lower"] = self.account_proof(rows, leaves, root, 2, block.block_hash,
                                            sorted([self.alice, self.bob, self.carol])[0])
        proof["upper"] = self.account_proof(rows, leaves, root, 2, block.block_hash,
                                            sorted([self.alice, self.bob, self.carol])[2])
        self.assert_proof_failure(state)

    def test_tampered_sibling_hash(self) -> None:
        state = self.state_extension(absent=[self.target_between])
        proof = state["state_absence_proofs"][0]["proof"]
        sibling = proof["lower"]["siblings"][0]
        sibling["hash"] = ("0" if sibling["hash"][0] != "0" else "1") + sibling["hash"][1:]
        self.assert_proof_failure(state)

    def test_non_empty_tree_without_neighbors(self) -> None:
        state = self.state_extension(absent=[self.target_between])
        proof = state["state_absence_proofs"][0]["proof"]
        proof["lower"] = None
        proof["upper"] = None
        self.assert_proof_failure(state)

    def test_empty_tree_with_phantom_neighbor(self) -> None:
        # An empty anchor tree must have both neighbors null; a neighbor
        # against the empty root cannot recompute.
        state = self.state_extension(height=0, absent=[self.bob])
        rows = self.state_rows(self.chain)
        root, leaves = self.state_root(rows)
        proof = state["state_absence_proofs"][0]["proof"]
        proof["lower"] = self.account_proof(
            rows, leaves, root, 2, self.chain[2].block_hash, self.bob
        )
        self.assert_proof_failure(state)

    def test_candidate_chain_failure_stays_integrity(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        bundle = self.bundle(state=state)
        bundle["candidate"][1]["merkle_root"] = "0" * 64
        bundle = self.resign(bundle)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_unsigned_keyed_source_stays_auth(self) -> None:
        state = self.state_extension(absent=[self.target_before])
        bundle = self.bundle(state=state)
        bundle.pop("signature")
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": "auth"},
        )


class AbsenceCliTests(AbsenceBundleFixture):
    def run_verify_cli(self, bundle: dict, trust: dict) -> tuple[int, dict]:
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            bpath = Path(tmp) / "bundle.json"
            tpath = Path(tmp) / "trust.json"
            bpath.write_text(json.dumps(bundle))
            tpath.write_text(json.dumps(trust))
            env = dict(os.environ, PYTHONPATH=str(repo))
            proc = subprocess.run(
                [sys.executable, "-m", "ledger.cli", "verify",
                 "--bundle", str(bpath), "--trust", str(tpath)],
                capture_output=True,
                text=True,
                env=env,
            )
        return proc.returncode, json.loads(proc.stdout)

    def live_bundle(self, state) -> dict:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = live
        bundle = {
            "source": "node-a",
            "expires_at": live,
            "response": dict(self.S),
            "candidate": [b.to_dict() for b in self.chain],
            "proofs": [],
            **state,
        }
        bundle["signature"] = self.source_key.sign(
            bundle_signing_digest(bundle)
        ).hex()
        return bundle, trust

    def test_verify_cli_absence_bundle(self) -> None:
        state = self.state_extension(
            accounts=[self.bob], absent=[self.target_between]
        )
        bundle, trust = self.live_bundle(state)
        code, body = self.run_verify_cli(bundle, trust)
        self.assertEqual(code, 0, body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["verified_absent_accounts"], [self.target_between])
        self.assertEqual(body["verified_accounts"], [self.bob])

    def test_verify_cli_failing_absence_bundle(self) -> None:
        state = self.state_extension(absent=[self.bob])  # bob exists
        bundle, trust = self.live_bundle(state)
        code, body = self.run_verify_cli(bundle, trust)
        self.assertEqual(code, 1, body)
        self.assertEqual(body, {"ok": False, "error": "proof"})


if __name__ == "__main__":
    unittest.main()

"""Tests for bundled account-absence proofs in offline light-client bundles.

Covers the optional ``state_absence_proofs`` field of
``ledger.light_client.verify_bundle``:

* combination rules: the array is only valid together with the four anchor
  fields (``state_root`` / ``state_height`` / ``state_block_hash`` /
  ``state_proofs``), and the bundle must carry at least one kind of state
  proof (``input``);
* strict per-item / per-document key sets and JSON types, including the
  nested state-root and neighbor documents (``input``);
* anchor binding of every item height and embedded state field, target
  absence from the rebuilt account set, target uniqueness and disjointness
  from the inclusion proofs, and the full predecessor/successor, adjacency,
  boundary and empty-tree rules (``proof``);
* the success result gaining ascending ``verified_absent_accounts`` while
  the legacy and inclusion-only result shapes stay unchanged, and the new
  field being covered by the bundle signature;
* the CLI ``verify`` command emitting the extended result unchanged.

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
from ledger.models import STATUS_PENDING, Block, Transaction
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
    extension (with absence proofs) anchored at height 2 by default."""

    def setUp(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice = pub_hex(self.alice_key)
        self.carol_key = Ed25519PrivateKey.generate()
        self.carol = pub_hex(self.carol_key)
        self.bob = "b" * 64
        # Targets that never appear in the chain.
        self.mallory = "0" * 64
        self.trent = "c" * 64

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
        """The plain four-field absence document, mirroring the server's
        GET /v1/accounts/{account}/absence-proof response."""
        names = [name for name, _b, _t in rows]
        state = {
            "state_root": root,
            "height": height,
            "block_hash": block_hash,
            "account_count": len(rows),
        }

        def neighbor(index):
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
        self, height: int = 2, accounts=None, absent=None
    ) -> dict:
        """A valid state extension anchored at ``height`` with inclusion
        proofs for ``accounts`` (default: none) and absence proofs for
        ``absent`` (default: two missing accounts, deliberately scrambled)."""
        prefix = self.chain[: height + 1]
        rows = self.state_rows(prefix)
        root, leaves = self.state_root(rows)
        block = self.chain[height]
        if accounts is None:
            accounts = []
        if absent is None:
            absent = [self.trent, self.mallory]
        proofs = [
            {
                "height": height,
                "proof": self.account_proof(
                    rows, leaves, root, height, block.block_hash, account
                ),
            }
            for account in accounts
        ]
        absence = [
            {
                "height": height,
                "proof": self.absence_proof(
                    rows, leaves, root, height, block.block_hash, account
                ),
            }
            for account in absent
        ]
        return {
            "state_root": root,
            "state_height": height,
            "state_block_hash": block.block_hash,
            "state_proofs": proofs,
            "state_absence_proofs": absence,
        }

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


class AbsenceSuccessTests(AbsenceBundleFixture):
    def test_absence_only_bundle(self) -> None:
        state = self.state_extension()
        self.assertEqual(state["state_proofs"], [])
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], [])
        self.assertEqual(
            result["verified_absent_accounts"], sorted([self.mallory, self.trent])
        )
        self.assertEqual(result["verified_tx_ids"], [])
        self.assertEqual(result["S"], self.S)

    def test_mixed_inclusion_and_absence(self) -> None:
        state = self.state_extension(accounts=[self.bob, self.alice])
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], sorted([self.alice, self.bob]))
        self.assertEqual(
            result["verified_absent_accounts"], sorted([self.mallory, self.trent])
        )

    def test_single_absent_account(self) -> None:
        state = self.state_extension(absent=[self.trent])
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_absent_accounts"], [self.trent])

    def test_empty_tree_at_genesis_anchor(self) -> None:
        state = self.state_extension(height=0, absent=["nobody"])
        proof = state["state_absence_proofs"][0]["proof"]
        self.assertIsNone(proof["lower"])
        self.assertIsNone(proof["upper"])
        self.assertEqual(proof["state"]["account_count"], 0)
        self.assertEqual(proof["state"]["state_root"], crypto.EMPTY_MERKLE_ROOT)
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_absent_accounts"], ["nobody"])

    def test_historical_anchor_height(self) -> None:
        # Anchored at height 1 the account set is only {alice, bob}; carol is
        # still absent there.
        state = self.state_extension(height=1, absent=[self.carol])
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_absent_accounts"], [self.carol])

    def test_inclusion_only_result_shape_unchanged(self) -> None:
        state = self.state_extension(accounts=[self.bob])
        del state["state_absence_proofs"]
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertNotIn("verified_absent_accounts", result)
        self.assertEqual(result["verified_accounts"], [self.bob])

    def test_legacy_bundle_result_shape_unchanged(self) -> None:
        result = verify_bundle(self.bundle(), self.trust, now=NOW)
        self.assertEqual(
            result,
            {"ok": True, "source": "node-a", "S": self.S, "verified_tx_ids": []},
        )

    def test_signature_covers_absence_proofs(self) -> None:
        bundle = self.bundle(state=self.state_extension())
        # Tamper with a target after signing.
        bundle["state_absence_proofs"][0]["proof"]["account"] = "f" * 64
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )
        # Dropping the array after signing breaks the signature too (the
        # remaining bundle stays well-formed thanks to the inclusion proof).
        bundle = self.bundle(state=self.state_extension(accounts=[self.bob]))
        del bundle["state_absence_proofs"]
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )


class AbsenceCombinationTests(AbsenceBundleFixture):
    def test_absence_array_without_anchor_fields(self) -> None:
        state = self.state_extension()
        for kept in (
            {"state_absence_proofs": state["state_absence_proofs"]},
            {
                "state_root": state["state_root"],
                "state_absence_proofs": state["state_absence_proofs"],
            },
            {
                "state_root": state["state_root"],
                "state_height": state["state_height"],
                "state_block_hash": state["state_block_hash"],
                "state_absence_proofs": state["state_absence_proofs"],
            },
        ):
            bundle = self.bundle(state=kept)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                kept.keys(),
            )

    def test_missing_anchor_field_with_absence(self) -> None:
        state = self.state_extension()
        for field in ("state_root", "state_height", "state_block_hash", "state_proofs"):
            partial = {k: v for k, v in state.items() if k != field}
            bundle = self.bundle(state=partial)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                field,
            )

    def test_at_least_one_kind_of_state_proof(self) -> None:
        state = self.state_extension()
        state["state_proofs"] = []
        state["state_absence_proofs"] = []
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )
        # Legacy rule preserved: empty state_proofs without the absence
        # array is still an input error.
        del state["state_absence_proofs"]
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_absence_array_type(self) -> None:
        state = self.state_extension(accounts=[self.bob])
        for bad in ("x", None, 5, {"height": 2}):
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"] = bad
            bundle = self.bundle(state=bad_state)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad,
            )


class AbsenceInputTests(AbsenceBundleFixture):
    def run_bad(self, state) -> None:
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_item_shape(self) -> None:
        state = self.state_extension()
        good_item = state["state_absence_proofs"][0]
        variants = [
            "not-a-dict",
            {"height": 2},                              # missing proof
            {"proof": good_item["proof"]},              # missing height
            {**good_item, "extra": 1},                  # extra item key
            {"height": True, "proof": good_item["proof"]},
            {"height": "2", "proof": good_item["proof"]},
            {"height": 2, "proof": "not-a-dict"},
        ]
        for bad_item in variants:
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"] = [bad_item]
            self.run_bad(bad_state)

    def test_proof_document_shape(self) -> None:
        state = self.state_extension()
        good_proof = state["state_absence_proofs"][0]["proof"]
        for key in good_proof:
            bad_doc = {k: v for k, v in good_proof.items() if k != key}
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"] = [{"height": 2, "proof": bad_doc}]
            self.run_bad(bad_state)
        bad_state = json.loads(json.dumps(state))
        bad_state["state_absence_proofs"] = [
            {"height": 2, "proof": {**good_proof, "leaf": "0" * 64}}
        ]
        self.run_bad(bad_state)
        # Bad target accounts.
        for bad_account in ("", 7, None, True):
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"] = [
                {"height": 2, "proof": {**good_proof, "account": bad_account}}
            ]
            self.run_bad(bad_state)

    def test_state_document_shape(self) -> None:
        state = self.state_extension()
        good = state["state_absence_proofs"][0]["proof"]["state"]
        for key in good:
            bad_doc = {k: v for k, v in good.items() if k != key}
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"][0]["proof"]["state"] = bad_doc
            self.run_bad(bad_state)
        for field, bad in (
            ("state_root", "AB" * 32),
            ("state_root", 5),
            ("height", True),
            ("height", -1),
            ("block_hash", "zz"),
            ("account_count", True),
            ("account_count", -1),
            ("account_count", "3"),
        ):
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"][0]["proof"]["state"] = {
                **good,
                field: bad,
            }
            self.run_bad(bad_state)

    def test_neighbor_document_shape(self) -> None:
        state = self.state_extension(absent=[self.trent])
        good = state["state_absence_proofs"][0]["proof"]["lower"]
        self.assertIsNotNone(good)
        for key in good:
            bad_doc = {k: v for k, v in good.items() if k != key}
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"][0]["proof"]["lower"] = bad_doc
            self.run_bad(bad_state)
        for field, bad in (
            ("account", ""),
            ("balance", True),
            ("balance", -1),
            ("confirmed_transactions", "x"),
            ("confirmed_transactions", ["zz"]),
            ("index", True),
            ("index", -1),
            ("state_root", "zz"),
            ("height", True),
            ("block_hash", 5),
            ("siblings", "x"),
            ("siblings", [{"direction": "up", "hash": "a" * 64}]),
            ("siblings", [{"direction": "left", "hash": "zz"}]),
            ("siblings", [{"direction": "left"}]),
        ):
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"][0]["proof"]["lower"] = {
                **good,
                field: bad,
            }
            self.run_bad(bad_state)


class AbsenceIntegrityTests(AbsenceBundleFixture):
    def test_unknown_anchor_height(self) -> None:
        state = self.state_extension()
        state["state_height"] = 9
        state["state_block_hash"] = "0" * 64
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_pending_anchor(self) -> None:
        tx3 = signed_tx(self.alice_key, self.alice, self.bob, 5)
        pending = Block.create(3, self.block2.block_hash, [tx3], status=STATUS_PENDING)
        blocks = [*self.chain, pending]
        response = {
            "tip_hash": pending.block_hash,
            "height": 3,
            "length": 4,
            "status": "pending",
        }
        state = self.state_extension()
        state["state_height"] = 3
        state["state_block_hash"] = pending.block_hash
        bundle = self.bundle(state=state, blocks=blocks, response=response)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_anchor_block_hash_mismatch(self) -> None:
        state = self.state_extension()
        state["state_block_hash"] = "f" * 64
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )


class AbsenceProofFailureTests(AbsenceBundleFixture):
    def run_bad(self, state) -> None:
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_item_height_disagrees_with_anchor(self) -> None:
        state = self.state_extension()
        state["state_absence_proofs"][0]["height"] = 1
        self.run_bad(state)

    def test_state_document_anchor_fields_disagree(self) -> None:
        for field, bad in (
            ("height", 1),
            ("state_root", "0" * 64),
            ("block_hash", "0" * 64),
            ("account_count", 2),
            ("account_count", 4),
        ):
            state = self.state_extension()
            state["state_absence_proofs"][0]["proof"]["state"][field] = bad
            self.run_bad(state)

    def test_neighbor_anchor_fields_disagree(self) -> None:
        state = self.state_extension(absent=[self.trent])
        lower = state["state_absence_proofs"][0]["proof"]["lower"]
        self.assertIsNotNone(lower)
        for field, bad in (
            ("height", 1),
            ("state_root", "0" * 64),
            ("block_hash", "0" * 64),
        ):
            bad_state = json.loads(json.dumps(state))
            bad_state["state_absence_proofs"][0]["proof"]["lower"][field] = bad
            self.run_bad(bad_state)

    def test_target_exists_in_account_set(self) -> None:
        for existing in (self.alice, self.bob, self.carol):
            state = self.state_extension(absent=[existing])
            self.run_bad(state)

    def test_target_duplicates_inclusion_proof(self) -> None:
        # The inclusion proof is valid on its own; the absence claim for the
        # same account is what fails.
        state = self.state_extension(accounts=[self.bob], absent=[self.bob])
        self.run_bad(state)

    def test_duplicate_targets(self) -> None:
        state = self.state_extension(absent=[self.trent])
        item = state["state_absence_proofs"][0]
        state["state_absence_proofs"] = [item, json.loads(json.dumps(item))]
        self.run_bad(state)

    def test_tampered_neighbor_path(self) -> None:
        state = self.state_extension(absent=[self.trent])
        lower = state["state_absence_proofs"][0]["proof"]["lower"]
        self.assertTrue(lower["siblings"])
        bad = json.loads(json.dumps(state))
        bad["state_absence_proofs"][0]["proof"]["lower"]["siblings"][0]["hash"] = (
            "0" * 64
        )
        self.run_bad(bad)
        bad = json.loads(json.dumps(state))
        first = bad["state_absence_proofs"][0]["proof"]["lower"]["siblings"][0]
        first["direction"] = "left" if first["direction"] == "right" else "right"
        self.run_bad(bad)

    def test_forged_neighbor_leaf(self) -> None:
        state = self.state_extension(absent=[self.trent])
        bad = json.loads(json.dumps(state))
        bad["state_absence_proofs"][0]["proof"]["lower"]["balance"] += 1
        self.run_bad(bad)

    def test_non_adjacent_neighbors(self) -> None:
        # Frame the target with the first and last accounts (indices 0 and
        # 2): the gap in between breaks adjacency. The target sorts strictly
        # between the middle and last accounts.
        rows = self.state_rows(self.chain)
        target = rows[1][0] + "!"
        state = self.state_extension(absent=[target])
        root, leaves = self.state_root(rows)
        block = self.chain[2]
        proof = state["state_absence_proofs"][0]["proof"]
        proof["lower"] = self.account_proof(rows, leaves, root, 2, block.block_hash, rows[0][0])
        proof["upper"] = self.account_proof(rows, leaves, root, 2, block.block_hash, rows[2][0])
        self.run_bad(state)

    def test_boundary_rule_violation(self) -> None:
        # A target past the last account ("g" sorts after every lowercase
        # hex account) may only name the last row as its lower neighbor;
        # naming row 0 is illegal.
        state = self.state_extension(absent=["g" * 64])
        rows = self.state_rows(self.chain)
        root, leaves = self.state_root(rows)
        block = self.chain[2]
        proof = state["state_absence_proofs"][0]["proof"]
        self.assertIsNone(proof["upper"])  # the target sorts after every account
        proof["lower"] = self.account_proof(rows, leaves, root, 2, block.block_hash, rows[0][0])
        self.run_bad(state)

    def test_empty_tree_rule_violation(self) -> None:
        # At the genesis anchor the tree is empty: any neighbor is illegal.
        state = self.state_extension(height=0, absent=["nobody"])
        rows = self.state_rows(self.chain)
        root, leaves = self.state_root(rows)
        block = self.chain[2]
        proof = state["state_absence_proofs"][0]["proof"]
        proof["lower"] = self.account_proof(rows, leaves, root, 2, block.block_hash, rows[0][0])
        self.run_bad(state)
        # A non-empty root with a zero count is illegal too.
        state = self.state_extension(height=0, absent=["nobody"])
        state["state_absence_proofs"][0]["proof"]["state"]["state_root"] = root
        self.run_bad(state)


class AbsenceCliTests(AbsenceBundleFixture):
    def test_verify_cli_absence_bundle(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = live
        state = self.state_extension(accounts=[self.bob])
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
        self.assertEqual(proc.returncode, 0, proc.stderr)
        body = json.loads(proc.stdout)
        self.assertTrue(body["ok"])
        self.assertEqual(body["verified_accounts"], [self.bob])
        self.assertEqual(
            body["verified_absent_accounts"], sorted([self.mallory, self.trent])
        )

    def test_verify_cli_failure_exit_code(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = live
        state = self.state_extension(absent=[self.alice])  # alice exists
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
        self.assertEqual(proc.returncode, 1, proc.stderr)
        body = json.loads(proc.stdout)
        self.assertEqual(body, {"ok": False, "error": "proof"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

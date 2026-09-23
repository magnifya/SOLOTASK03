"""Tests for account-state proofs embedded in offline light-client bundles.

Covers the optional bundle anchor ``state_root`` / ``state_height`` /
``state_block_hash`` / ``state_proofs``:

* all-or-nothing presence and the non-empty list / closed field-set / strict
  type rules (everything structural is ``input``);
* anchor binding to a confirmed candidate block (unknown/pending/hash
  mismatch are ``integrity``);
* a single anchor height, ascending-account ``account``/``index`` checks
  against the confirmed prefix, unique ``(height, account)``, and every
  ``verify_account_proof`` failure category (all ``proof``);
* success adding ``verified_accounts`` ascending while ``verified_tx_ids``
  and the legacy (anchor-less) result stay unchanged, signature covering the
  extended bundle;
* the ``ledger verify`` CLI surfacing ``verified_accounts``.

Run: python3 tests/light_client_state_proof_test.py
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
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_PROOF,
    bundle_signing_digest,
    verify_bundle,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

NOW = 1_000_000_000
FUTURE = NOW + 10_000


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount,
            "signature": key.sign(msg).hex()}


class StateAnchorFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.ka = Ed25519PrivateKey.generate()
        self.A = pub_hex(self.ka)
        self.kb = Ed25519PrivateKey.generate()
        self.B = pub_hex(self.kb)
        self.kc = Ed25519PrivateKey.generate()
        self.C = pub_hex(self.kc)
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=100_000,
        )
        # A->B and C->A land in confirmed block 1: the account set is
        # {A, B, C} in ascending order.
        self.t1 = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 100))[1]["tx_id"]
        self.t2 = self.svc.submit_transaction(make_tx(self.kc, self.C, self.A, 40))[1]["tx_id"]
        self.svc.mine_block()
        self.svc.confirm_block(1)
        _, self.rootdoc = self.svc.get_state_root()
        self.rows = self.svc.store.account_state_rows(
            self.svc.store.chain, self.svc.initial_balance
        )
        self.accounts = [name for name, _b, _t in self.rows]
        self.state_proofs = [
            {"height": 1, "proof": self.svc.get_account_proof(name)[1]}
            for name in self.accounts
        ]
        self.trust = {
            "genesis_hash": self.svc.store.chain[0].block_hash,
            "sources": {
                "node-a": {"public_key": self.source_pub, "expires_at": FUTURE}
            },
            "allowlist": {},
        }

    def descriptor(self) -> dict:
        tip = self.svc.store.chain[-1]
        return {
            "tip_hash": tip.block_hash,
            "height": tip.height,
            "length": len(self.svc.store.chain),
            "status": tip.status,
        }

    def bundle(
        self,
        *,
        anchor: bool = True,
        proofs=None,
        response=None,
        blocks=None,
        mutate=None,
        sign=True,
        source="node-a",
        expires_at=FUTURE,
    ) -> dict:
        chain = blocks if blocks is not None else self.svc.store.chain
        candidate = [b.to_dict() for b in chain]
        bundle = {
            "source": source,
            "expires_at": expires_at,
            "response": dict(self.descriptor()) if response is None else response,
            "candidate": candidate,
            "proofs": proofs if proofs is not None else [],
        }
        if anchor:
            bundle["state_root"] = self.rootdoc["state_root"]
            bundle["state_height"] = self.rootdoc["height"]
            bundle["state_block_hash"] = self.rootdoc["block_hash"]
            bundle["state_proofs"] = json.loads(json.dumps(self.state_proofs))
        if mutate is not None:
            mutate(bundle)
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


class HappyPathTests(StateAnchorFixture):
    def test_state_anchor_success(self) -> None:
        result = verify_bundle(self.bundle(), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], self.accounts)
        self.assertEqual(self.accounts, sorted(self.accounts))
        # Tx proofs are unaffected: none supplied, so the list is empty but
        # the key is always present.
        self.assertEqual(result["verified_tx_ids"], [])

    def test_legacy_bundle_has_no_verified_accounts_key(self) -> None:
        result = verify_bundle(self.bundle(anchor=False), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertNotIn("verified_accounts", result)
        self.assertEqual(result["verified_tx_ids"], [])

    def test_tx_proofs_and_account_proofs_coexist(self) -> None:
        ids = [t.tx_id for t in self.svc.store.chain[1].transactions]
        tx_entry = {
            "height": 1,
            "proof": {
                "height": 1,
                "tx_id": ids[0],
                "index": 0,
                "merkle_root": self.svc.store.chain[1].merkle_root,
                "block_hash": self.svc.store.chain[1].block_hash,
                "siblings": crypto.merkle_proof(ids, 0),
            },
        }
        result = verify_bundle(self.bundle(proofs=[tx_entry]), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_tx_ids"], [ids[0]])
        self.assertEqual(result["verified_accounts"], self.accounts)

    def test_historical_anchor_below_tip(self) -> None:
        # Confirm a second block, then anchor the state proofs at height 1
        # while the candidate tip is height 2.
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.A, 5))
        self.svc.mine_block()
        self.svc.confirm_block(2)
        historical = [
            {"height": 1,
             "proof": self.svc.get_account_proof(name, {"height": "1"})[1]}
            for name in self.accounts
        ]

        def set_historical(b: dict) -> None:
            b["state_height"] = 1
            b["state_block_hash"] = self.svc.store.chain[1].block_hash
            b["state_proofs"] = historical

        result = verify_bundle(self.bundle(mutate=set_historical), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], self.accounts)

    def test_signature_covers_state_anchor(self) -> None:
        bundle = self.bundle()
        bundle["state_root"] = "f" * 64  # changed after signing
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )


class AnchorShapeTests(StateAnchorFixture):
    def _strip(self, field: str) -> dict:
        bundle = self.bundle()
        del bundle[field]
        return self.resign(bundle)

    def test_anchor_fields_all_or_nothing(self) -> None:
        for field in ("state_root", "state_height",
                      "state_block_hash", "state_proofs"):
            self.assertEqual(
                verify_bundle(self._strip(field), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                field,
            )

    def test_state_proofs_must_be_non_empty(self) -> None:
        bundle = self.bundle(mutate=lambda b: b.update(state_proofs=[]))
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_anchor_primitive_types(self) -> None:
        def expect(field, value):
            bundle = self.bundle(mutate=lambda b: b.update({field: value}))
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                (field, value),
            )

        expect("state_root", "z" * 64)
        expect("state_root", 123)
        expect("state_block_hash", "Z" * 64)
        expect("state_block_hash", None)
        expect("state_height", True)
        expect("state_height", -1)
        expect("state_height", "1")
        expect("state_height", 1.0)
        expect("state_proofs", {})
        expect("state_proofs", "x")

    def test_entry_must_be_height_and_proof_only(self) -> None:
        def extra(b):
            b["state_proofs"][0]["bogus"] = 1
        def missing(b):
            del b["state_proofs"][0]["proof"]
        def only_height(b):
            b["state_proofs"][0] = {"height": 1}
        for mutate in (extra, missing, only_height):
            self.assertEqual(
                verify_bundle(self.bundle(mutate=mutate), self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                mutate.__name__,
            )

    def test_entry_height_types(self) -> None:
        for bad in (True, -1, "1", 0.0, None):
            bundle = self.bundle(
                mutate=lambda b, v=bad: b["state_proofs"][0].update(height=v)
            )
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad,
            )

    def test_proof_document_closed_field_set(self) -> None:
        first = self.bundle(mutate=lambda b: b["state_proofs"][0]["proof"].pop("siblings"))
        second = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(extra=1)
        )
        for bundle in (first, second):
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
            )

    def test_proof_document_field_types(self) -> None:
        def case(field, value):
            bundle = self.bundle(
                mutate=lambda b: b["state_proofs"][0]["proof"].update({field: value})
            )
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                (field, value),
            )

        case("account", "")
        case("account", 7)
        case("balance", True)
        case("balance", -1)
        case("balance", "1")
        case("confirmed_transactions", "x")
        case("confirmed_transactions", ["nothex"])
        case("index", True)
        case("index", -1)
        case("index", "0")
        case("state_root", "abc")
        case("height", False)
        case("height", -2)
        case("block_hash", "z" * 64)
        case("siblings", None)


class AnchorIntegrityTests(StateAnchorFixture):
    def test_unknown_state_height(self) -> None:
        bundle = self.bundle(mutate=lambda b: b.update(state_height=99))
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_pending_anchor(self) -> None:
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.A, 5))
        _, pending = self.svc.mine_block()
        pending_tip = self.svc.store.chain[-1]

        def point(b):
            b["response"] = {
                "tip_hash": pending_tip.block_hash,
                "height": pending_tip.height,
                "length": len(self.svc.store.chain),
                "status": pending_tip.status,
            }
            b["state_height"] = 2
            b["state_block_hash"] = pending_tip.block_hash

        bundle = self.bundle(response={}, mutate=point)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_anchor_block_hash_mismatch(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b.update(state_block_hash="f" * 64)
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )


class StateProofFailureTests(StateAnchorFixture):
    def test_entry_height_differs_from_anchor(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0].update(height=0)
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_document_height_differs_from_anchor(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(height=0)
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_document_root_differs_from_anchor(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(
                state_root="f" * 64
            )
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_document_block_hash_differs_from_anchor(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(
                block_hash="9" * 64
            )
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_index_out_of_range(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(index=99)
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_account_not_in_confirmed_set(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(
                account="deadbeef"
            )
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_index_names_another_account(self) -> None:
        # Point proof 0's index at a different slot without touching the
        # account name: index/account disagree before hashing even starts.
        def swap(b):
            other_index = b["state_proofs"][1]["proof"]["index"]
            b["state_proofs"][0]["proof"]["index"] = other_index
        bundle = self.bundle(mutate=swap)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_duplicate_height_account(self) -> None:
        def dup(b):
            b["state_proofs"].append(json.loads(json.dumps(b["state_proofs"][0])))
        bundle = self.bundle(mutate=dup)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_forged_balance_leaf(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].__setitem__(
                "balance", b["state_proofs"][0]["proof"]["balance"] + 1
            )
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_forged_transaction_leaf(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(
                confirmed_transactions=["9" * 64]
            )
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_illegal_sibling_direction(self) -> None:
        def flip(b):
            siblings = b["state_proofs"][0]["proof"]["siblings"]
            if siblings:
                siblings[0]["direction"] = "up"
        bundle = self.bundle(mutate=flip)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_illegal_sibling_hash(self) -> None:
        def corrupt(b):
            siblings = b["state_proofs"][0]["proof"]["siblings"]
            if siblings:
                siblings[0]["hash"] = "Z" * 64
        bundle = self.bundle(mutate=corrupt)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_malformed_siblings_path(self) -> None:
        bundle = self.bundle(
            mutate=lambda b: b["state_proofs"][0]["proof"].update(
                siblings=[{"direction": "left", "hash": "b" * 64}] * 65
            )
        )
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_single_account_tree_self_pair_is_valid(self) -> None:
        # A fresh chain with one sender/recipient pair gives a two-account
        # tree; build a one-account scenario by reusing a one-proof service
        # through genesis-adjacent activity is impossible (no zero-account
        # proofs), so at minimum assert the multi-account path verifies and
        # that a genuine odd-node self-pair (3 accounts, rightmost proof)
        # succeeds rather than being rejected as an illegal self-pair.
        rightmost = self.accounts[-1]
        single = [
            {"height": 1, "proof": self.svc.get_account_proof(rightmost)[1]}
        ]
        bundle = self.bundle(mutate=lambda b: b.update(state_proofs=single))
        result = verify_bundle(bundle, self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], [rightmost])


class CliStateProofTests(StateAnchorFixture):
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
                capture_output=True, text=True, env=env,
            )

    def test_cli_emits_verified_accounts(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = live
        proc = self._run(json.dumps(self.bundle(expires_at=live)), trust)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
        body = json.loads(proc.stdout)
        self.assertTrue(body["ok"])
        self.assertEqual(body["verified_accounts"], self.accounts)
        self.assertEqual(body["verified_tx_ids"], [])

    def test_cli_legacy_bundle_omits_verified_accounts(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = live
        proc = self._run(
            json.dumps(self.bundle(anchor=False, expires_at=live)), trust
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("verified_accounts", json.loads(proc.stdout))


if __name__ == "__main__":
    unittest.main(verbosity=2)

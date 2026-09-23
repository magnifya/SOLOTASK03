"""Tests for the account-state extension of offline light-client verification.

Covers the optional ``state_root`` / ``state_height`` / ``state_block_hash`` /
``state_proofs`` bundle fields of ``ledger.light_client.verify_bundle``:

* all-or-none presence, non-empty ``state_proofs`` and strict per-item /
  per-document key sets and JSON types (``input``);
* anchor binding: unknown/pending/hash-mismatched anchor heights and any
  disagreement between the two heights, the state root or the block hash
  (``integrity``);
* proof checks against the anchor height's ascending confirmed-account set,
  ``height``+``account`` uniqueness and ``crypto.verify_account_proof``
  (``proof``);
* the success result gaining ascending ``verified_accounts`` while
  ``verified_tx_ids`` and the legacy (state-less) result shape are unchanged;
* the account-proof endpoint rejecting unknown or repeated query parameters
  with 400 while staying backwards compatible.

Run: python3 tests/light_client_state_proof_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
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
from ledger.server import build_handler
from ledger.service import LedgerService
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


class StateBundleFixture(unittest.TestCase):
    """A three-account chain (genesis + two confirmed blocks) with a keyed
    source; ``bundle()`` mirrors the legacy builder and adds the state
    extension anchored at height 2 by default."""

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

    def state_extension(self, height: int = 2, accounts=None) -> dict:
        """A valid state extension anchored at ``height`` with proofs for the
        given accounts (default: the whole ascending set, deliberately
        scrambled)."""
        prefix = self.chain[: height + 1]
        rows = self.state_rows(prefix)
        root, leaves = self.state_root(rows)
        block = self.chain[height]
        names = [name for name, _b, _t in rows]
        if accounts is None:
            accounts = list(reversed(names))
        proofs = [
            {
                "height": height,
                "proof": self.account_proof(
                    rows, leaves, root, height, block.block_hash, account
                ),
            }
            for account in accounts
        ]
        return {
            "state_root": root,
            "state_height": height,
            "state_block_hash": block.block_hash,
            "state_proofs": proofs,
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

    def resign(self, bundle: dict) -> dict:
        bundle.pop("signature", None)
        bundle["signature"] = self.source_key.sign(
            bundle_signing_digest(bundle)
        ).hex()
        return bundle


class StateSuccessTests(StateBundleFixture):
    def test_happy_path_all_accounts(self) -> None:
        result = verify_bundle(self.bundle(state=self.state_extension()), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["verified_accounts"], sorted([self.alice, self.bob, self.carol])
        )
        self.assertEqual(result["verified_tx_ids"], [])
        self.assertEqual(result["S"], self.S)

    def test_subset_of_accounts(self) -> None:
        state = self.state_extension(accounts=[self.bob])
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], [self.bob])

    def test_historical_anchor_height(self) -> None:
        # Anchored at height 1 the account set is only {alice, bob}.
        state = self.state_extension(height=1)
        result = verify_bundle(self.bundle(state=state), self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_accounts"], sorted([self.alice, self.bob]))

    def test_tx_proofs_still_verified_alongside(self) -> None:
        ids = [t.tx_id for t in self.block1.transactions]
        tx_proof = {
            "height": 1,
            "proof": {
                "height": 1,
                "tx_id": self.tx1.tx_id,
                "index": 0,
                "merkle_root": self.block1.merkle_root,
                "block_hash": self.block1.block_hash,
                "siblings": crypto.merkle_proof(ids, 0),
            },
        }
        result = verify_bundle(
            self.bundle(state=self.state_extension(), proofs=[tx_proof]),
            self.trust,
            now=NOW,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_tx_ids"], [self.tx1.tx_id])
        self.assertEqual(len(result["verified_accounts"]), 3)

    def test_legacy_bundle_result_shape_unchanged(self) -> None:
        result = verify_bundle(self.bundle(), self.trust, now=NOW)
        self.assertEqual(
            result,
            {"ok": True, "source": "node-a", "S": self.S, "verified_tx_ids": []},
        )

    def test_signature_covers_state_fields(self) -> None:
        bundle = self.bundle(state=self.state_extension())
        bundle["state_root"] = "0" * 64  # tampered after signing
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )


class StateInputTests(StateBundleFixture):
    def test_all_or_none(self) -> None:
        state = self.state_extension()
        for field in ("state_root", "state_height", "state_block_hash", "state_proofs"):
            partial = {k: v for k, v in state.items() if k != field}
            bundle = self.bundle(state=partial)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                field,
            )

    def test_anchor_field_types(self) -> None:
        state = self.state_extension()
        for field, bad in (
            ("state_root", "AB" * 32),      # uppercase hex
            ("state_root", "zz"),
            ("state_root", 5),
            ("state_height", True),
            ("state_height", "2"),
            ("state_height", -1),
            ("state_height", 2.0),
            ("state_block_hash", "zz"),
            ("state_block_hash", None),
            ("state_proofs", []),           # must be non-empty
            ("state_proofs", "x"),
            ("state_proofs", None),
        ):
            bad_state = json.loads(json.dumps(state))
            bad_state[field] = bad
            bundle = self.bundle(state=bad_state)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                (field, bad),
            )

    def test_item_shape(self) -> None:
        state = self.state_extension()
        good_item = state["state_proofs"][0]
        variants = [
            "not-a-dict",
            {"height": 2},                              # missing proof
            {**good_item, "extra": 1},                  # extra item key
            {"height": True, "proof": good_item["proof"]},
            {"height": "2", "proof": good_item["proof"]},
            {"height": 2, "proof": "not-a-dict"},
        ]
        for bad_item in variants:
            bad_state = json.loads(json.dumps(state))
            bad_state["state_proofs"] = [bad_item]
            bundle = self.bundle(state=bad_state)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                bad_item,
            )

    def test_proof_document_shape(self) -> None:
        state = self.state_extension()
        good_proof = state["state_proofs"][0]["proof"]
        template = {"height": 2, "proof": good_proof}
        # Missing and extra document keys.
        for key in good_proof:
            bad_doc = {k: v for k, v in good_proof.items() if k != key}
            bad_state = json.loads(json.dumps(state))
            bad_state["state_proofs"] = [{"height": 2, "proof": bad_doc}]
            bundle = self.bundle(state=bad_state)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                f"missing {key}",
            )
        bad_state = json.loads(json.dumps(state))
        bad_state["state_proofs"] = [
            {"height": 2, "proof": {**good_proof, "leaf": "0" * 64}}
        ]
        bundle = self.bundle(state=bad_state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INPUT},
        )
        # Wrong JSON types per field.
        for field, bad in (
            ("account", ""),
            ("account", 7),
            ("balance", True),
            ("balance", "100"),
            ("confirmed_transactions", "x"),
            ("confirmed_transactions", [5]),
            ("index", True),
            ("index", "0"),
            ("state_root", 5),
            ("height", True),
            ("block_hash", 5),
            ("siblings", "x"),
        ):
            bad_state = json.loads(json.dumps(state))
            bad_state["state_proofs"] = [
                {"height": 2, "proof": {**good_proof, field: bad}}
            ]
            bundle = self.bundle(state=bad_state)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INPUT},
                (field, bad),
            )
        self.assertEqual(template["height"], 2)  # silence unused-var style


class StateIntegrityTests(StateBundleFixture):
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

    def test_item_height_disagrees_with_anchor(self) -> None:
        state = self.state_extension()
        state["state_proofs"][0]["height"] = 1
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_proof_document_anchor_fields_disagree(self) -> None:
        for field, bad in (
            ("height", 1),
            ("state_root", "0" * 64),
            ("block_hash", "0" * 64),
        ):
            state = self.state_extension()
            state["state_proofs"][0]["proof"][field] = bad
            bundle = self.bundle(state=state)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_INTEGRITY},
                field,
            )


class StateProofFailureTests(StateBundleFixture):
    def test_account_not_in_set(self) -> None:
        state = self.state_extension()
        proof = state["state_proofs"][0]["proof"]
        evil = dict(proof)
        evil["account"] = "d" * 64
        state["state_proofs"] = [{"height": 2, "proof": evil}]
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_index_out_of_range_or_mismatched(self) -> None:
        for bad_index in (-1, 3, 99):
            state = self.state_extension(accounts=[self.alice])
            state["state_proofs"][0]["proof"]["index"] = bad_index
            bundle = self.bundle(state=state)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_PROOF},
                bad_index,
            )
        # A valid in-range index that names a different account's slot.
        state = self.state_extension(accounts=[self.alice])
        carol_index = 2  # carol sorts last among the three accounts? checked below
        rows = self.state_rows(self.chain)
        carol_index = [name for name, _b, _t in rows].index(self.carol)
        state["state_proofs"][0]["proof"]["index"] = carol_index
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_duplicate_height_account(self) -> None:
        state = self.state_extension(accounts=[self.bob])
        item = state["state_proofs"][0]
        state["state_proofs"] = [item, json.loads(json.dumps(item))]
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_forged_leaf(self) -> None:
        state = self.state_extension(accounts=[self.bob])
        proof = state["state_proofs"][0]["proof"]
        proof["balance"] = proof["balance"] + 1
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )
        state = self.state_extension(accounts=[self.bob])
        proof = state["state_proofs"][0]["proof"]
        proof["confirmed_transactions"] = []
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_illegal_direction_and_hash(self) -> None:
        # Find a proof with at least one sibling (three-account tree).
        state = self.state_extension(accounts=[self.alice])
        proof = state["state_proofs"][0]["proof"]
        self.assertTrue(proof["siblings"])
        flipped = json.loads(json.dumps(state))
        first = flipped["state_proofs"][0]["proof"]["siblings"][0]
        first["direction"] = "left" if first["direction"] == "right" else "right"
        bundle = self.bundle(state=flipped)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )
        bad_hash = json.loads(json.dumps(state))
        bad_hash["state_proofs"][0]["proof"]["siblings"][0]["hash"] = "0" * 64
        bundle = self.bundle(state=bad_hash)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_illegal_self_pair(self) -> None:
        # The last account in the three-leaf tree self-pairs at the leaf
        # level; flipping that right self-sibling to the left is illegal.
        rows = self.state_rows(self.chain)
        last = rows[-1][0]
        state = self.state_extension(accounts=[last])
        proof = state["state_proofs"][0]["proof"]
        self.assertEqual(proof["siblings"][0]["direction"], "right")
        leaf = crypto.account_state_leaf(
            proof["account"], proof["balance"], proof["confirmed_transactions"]
        )
        self.assertEqual(proof["siblings"][0]["hash"], leaf)
        proof["siblings"][0]["direction"] = "left"
        bundle = self.bundle(state=state)
        self.assertEqual(
            verify_bundle(bundle, self.trust, now=NOW),
            {"ok": False, "error": ERR_PROOF},
        )

    def test_malformed_siblings(self) -> None:
        state = self.state_extension(accounts=[self.alice])
        for bad_siblings in (
            ["nope"],                       # non-dict entry
            [{"direction": "up", "hash": "a" * 64}],
            [{"direction": "left", "hash": "zz"}],
            [{"direction": "left", "hash": "b" * 64}] * 65,  # excessive depth
        ):
            bad = json.loads(json.dumps(state))
            bad["state_proofs"][0]["proof"]["siblings"] = bad_siblings
            bundle = self.bundle(state=bad)
            self.assertEqual(
                verify_bundle(bundle, self.trust, now=NOW),
                {"ok": False, "error": ERR_PROOF},
                bad_siblings,
            )


class StateCliTests(StateBundleFixture):
    def test_verify_cli_extended_bundle(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-a"]["expires_at"] = live
        state = self.state_extension()
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
        self.assertEqual(
            body["verified_accounts"], sorted([self.alice, self.bob, self.carol])
        )


class AccountProofParamTests(unittest.TestCase):
    """The account-proof endpoint accepts only a single optional ``height``
    query parameter; unknown or repeated parameters are 400."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.key = Ed25519PrivateKey.generate()
        cls.account = pub_hex(cls.key)
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=ENDOWMENT
        )
        tx = signed_tx(cls.key, cls.account, "b" * 64, 10)
        cls.service.submit_transaction(
            {"from": tx.sender, "to": tx.recipient, "amount": tx.amount,
             "signature": tx.signature}
        )
        _, block = cls.service.mine_block()
        cls.service.confirm_block(block["height"])
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, path: str):
        req = urllib.request.Request(f"{self.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_unknown_parameter_400(self) -> None:
        status, body = self.request(f"/v1/accounts/{self.account}/proof?foo=1")
        self.assertEqual(status, 400, body)
        status, body = self.request(
            f"/v1/accounts/{self.account}/proof?height=1&foo=1"
        )
        self.assertEqual(status, 400, body)
        # Service level, without HTTP.
        status, _ = self.service.get_account_proof(self.account, {"foo": "1"})
        self.assertEqual(status, 400)

    def test_repeated_height_400(self) -> None:
        status, body = self.request(
            f"/v1/accounts/{self.account}/proof?height=1&height=1"
        )
        self.assertEqual(status, 400, body)

    def test_height_still_accepted(self) -> None:
        status, body = self.request(f"/v1/accounts/{self.account}/proof?height=1")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["account"], self.account)
        status, body = self.request(f"/v1/accounts/{self.account}/proof")
        self.assertEqual(status, 200, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for historical-height account-state roots and inclusion proofs.

Covers GET /v1/state/root/{height} and
GET /v1/accounts/{account}/proof?height=H:

* strict unsigned-decimal height parsing (no signs, whitespace or leading
  zeros): path heights fail 404, query heights fail 400, repeated query
  parameters fail 400 at the HTTP layer;
* unknown / non-canonical / pending anchor heights are 404, while a missing
  height keeps anchoring the highest confirmed block;
* the historical state is deterministically replayed from the canonical
  confirmed prefix genesis..H: root, block_hash, height, account_count,
  balance, index, siblings and the original-order transaction list all match
  an independent prefix replay, and pending income is never counted;
* the offline crypto.verify_account_proof verifies a historical proof with
  the historical root/anchor without any signature change;
* the state-root / state-proof CLI subcommands forward --height verbatim;
* results stay identical across restart, fork adoption and a mine/rollback
  cycle, historical reads never mutate current indexes/balances/snapshots,
  and concurrent reads against a mutating chain stay consistent.

Run: python3 tests/history_state_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
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
from ledger.models import STATUS_CONFIRMED, Block
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


class HistoryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "history.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.endowment = 100_000
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=self.endowment
        )

    def send(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine_and_confirm(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        status, confirmed = self.svc.confirm_block(block["height"])
        self.assertEqual(status, 200, confirmed)
        return block

    def expected_prefix_view(self, height: int) -> tuple[str, int, list]:
        """Independently replay genesis..height and return (root, count, rows)."""
        prefix = self.svc.store.chain[: height + 1]
        rows = self.svc.store.account_state_rows(prefix, self.svc.initial_balance)
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        return crypto.account_state_root(leaves), len(rows), rows

    # -- historical state root ----------------------------------------------

    def test_historical_root_at_every_confirmed_height(self) -> None:
        # Block 1: A -> B 100 and C -> A 40. Block 2: B -> A 5.
        t1 = self.send(self.ka, self.A, self.B, 100)
        t2 = self.send(self.kc, self.C, self.A, 40)
        blk1 = self.mine_and_confirm()
        t3 = self.send(self.kb, self.B, self.A, 5)
        blk2 = self.mine_and_confirm()

        # Height 0 (genesis): empty tree, identical to the unanchored shape.
        status, body = self.svc.get_state_root("0")
        self.assertEqual(status, 200, body)
        self.assertEqual(
            set(body), {"state_root", "height", "block_hash", "account_count"}
        )
        self.assertEqual(body["height"], 0)
        self.assertEqual(body["account_count"], 0)
        self.assertEqual(body["state_root"], crypto.EMPTY_MERKLE_ROOT)
        genesis_hash = self.svc.store.chain[0].block_hash
        self.assertEqual(body["block_hash"], genesis_hash)

        for height, blk in ((1, blk1), (2, blk2)):
            status, body = self.svc.get_state_root(str(height))
            self.assertEqual(status, 200, body)
            root, count, _rows = self.expected_prefix_view(height)
            self.assertEqual(body["height"], height)
            self.assertEqual(body["block_hash"], blk["block_hash"])
            self.assertEqual(body["account_count"], count)
            self.assertEqual(body["state_root"], root)

        # The latest historical root equals the unanchored endpoint.
        status, current = self.svc.get_state_root()
        self.assertEqual(status, 200)
        _, body2 = self.svc.get_state_root("2")
        self.assertEqual(current, body2)

        # Roots genuinely differ across heights.
        _, r0 = self.svc.get_state_root("0")
        _, r1 = self.svc.get_state_root("1")
        _, r2 = self.svc.get_state_root("2")
        self.assertNotEqual(r0["state_root"], r1["state_root"])
        self.assertNotEqual(r1["state_root"], r2["state_root"])

    def test_historical_root_404_semantics(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        _, blk = self.svc.mine_block()  # pending tip at height 1
        # Malformed/unknown/pending path heights are all 404 with one-line JSON.
        for bad in ("01", "00", "-1", "1.0", " 1", "1 ", "abc", "", "99"):
            status, body = self.svc.get_state_root(bad)
            self.assertEqual(status, 404, (bad, body))
            self.assertEqual(set(body), {"error"})
        # The pending tip height itself is 404.
        self.assertEqual(self.svc.get_state_root(str(blk["height"]))[0], 404)
        # The last confirmed prefix (genesis) is still served.
        self.assertEqual(self.svc.get_state_root("0")[0], 200)

    # -- historical account proof -------------------------------------------

    def test_historical_proof_fields_and_prefix_replay(self) -> None:
        t1 = self.send(self.ka, self.A, self.B, 100)
        t2 = self.send(self.kc, self.C, self.A, 40)
        blk1 = self.mine_and_confirm()
        t3 = self.send(self.kb, self.B, self.A, 5)
        blk2 = self.mine_and_confirm()

        def check(height: int, blk: dict) -> None:
            root, _count, rows = self.expected_prefix_view(height)
            for index, (account, balance, txs) in enumerate(rows):
                status, proof = self.svc.get_account_proof(
                    account, {"height": str(height)}
                )
                self.assertEqual(status, 200, (height, account, proof))
                self.assertEqual(
                    set(proof),
                    {"account", "balance", "confirmed_transactions", "index",
                     "state_root", "height", "block_hash", "siblings"},
                )
                self.assertEqual(proof["account"], account)
                self.assertEqual(proof["balance"], balance)
                self.assertEqual(proof["confirmed_transactions"], txs)
                self.assertEqual(proof["index"], index)
                self.assertEqual(proof["height"], height)
                self.assertEqual(proof["block_hash"], blk["block_hash"])
                self.assertEqual(proof["state_root"], root)
                # Offline verification against the historical anchor, using the
                # unchanged verify_account_proof signature.
                self.assertTrue(
                    crypto.verify_account_proof(proof, root, height, blk["block_hash"]),
                    (height, account),
                )
                # A historical anchor must not verify against another height.
                if height > 0:
                    self.assertFalse(
                        crypto.verify_account_proof(proof, root, height - 1, blk["block_hash"])
                    )

        check(1, blk1)
        check(2, blk2)

        # A does not exist at genesis, exists from block 1; balances track the
        # prefix only.
        self.assertEqual(self.svc.get_account_proof(self.A, {"height": "0"})[0], 404)
        _, pa1 = self.svc.get_account_proof(self.A, {"height": "1"})
        self.assertEqual(pa1["balance"], self.endowment - 100 + 40)
        self.assertEqual(pa1["confirmed_transactions"], sorted([t1, t2]))
        _, pa2 = self.svc.get_account_proof(self.A, {"height": "2"})
        self.assertEqual(pa2["balance"], self.endowment - 100 + 40 + 5)
        # T keeps chain order across blocks: block-1 txs (ascending id) then
        # the block-2 tx.
        self.assertEqual(pa2["confirmed_transactions"], sorted([t1, t2]) + [t3])
        # Index/siblings are stable per (height, account).
        self.assertEqual(pa1["index"], pa2["index"])  # A's sort position unchanged

        # B first appears in block 1 with only t1.
        _, pb1 = self.svc.get_account_proof(self.B, {"height": "1"})
        self.assertEqual(pb1["confirmed_transactions"], [t1])
        self.assertEqual(pb1["balance"], self.endowment + 100)

        # No height: highest confirmed block, identical to explicit height 2.
        _, default_proof = self.svc.get_account_proof(self.A)
        self.assertEqual(default_proof, pa2)

    def test_historical_proof_400_and_404_semantics(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_and_confirm()
        # Malformed query heights: 400.
        for bad in ("01", "-1", "1.0", "abc", " 1", ""):
            status, body = self.svc.get_account_proof(self.A, {"height": bad})
            self.assertEqual(status, 400, (bad, body))
        # Well-formed but unknown canonical height: 404.
        status, body = self.svc.get_account_proof(self.A, {"height": "99"})
        self.assertEqual(status, 404, body)
        # Account absent from that historical state: 404.
        status, body = self.svc.get_account_proof("d" * 64, {"height": "0"})
        self.assertEqual(status, 404, body)
        # Pending tip anchor: 404 (not 400).
        self.send(self.kb, self.B, self.A, 2)
        _, blk = self.svc.mine_block()
        status, body = self.svc.get_account_proof(self.A, {"height": str(blk["height"])})
        self.assertEqual(status, 404, body)
        # Earlier confirmed prefix still served while the tip is pending.
        status, _ = self.svc.get_account_proof(self.A, {"height": "1"})
        self.assertEqual(status, 200)
        # Default (no height) stays 404 while pending.
        self.assertEqual(self.svc.get_account_proof(self.A)[0], 404)

    def test_pending_income_never_counted_historical(self) -> None:
        # Block 1 confirmed: A -> B 100.
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        _, root_after_1 = self.svc.get_state_root("1")
        # Block 2 pending credits B with another 500: it must not enter any
        # historical view.
        self.send(self.ka, self.A, self.B, 500)
        _, pending = self.svc.mine_block()
        self.assertEqual(pending["status"], "pending")
        _, root_still = self.svc.get_state_root("1")
        self.assertEqual(root_still, root_after_1)
        _, pb = self.svc.get_account_proof(self.B, {"height": "1"})
        self.assertEqual(pb["balance"], self.endowment + 100)
        # Roll back: views are byte-identical.
        self.assertEqual(self.svc.rollback_block(pending["height"])[0], 200)
        _, root_rolled = self.svc.get_state_root("1")
        self.assertEqual(root_rolled, root_after_1)
        _, current = self.svc.get_state_root()
        self.assertEqual(current, root_after_1)

    def test_historical_reads_do_not_mutate_current_state(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.send(self.kc, self.C, self.A, 10)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 3)
        self.mine_and_confirm()
        before_accounts = json.dumps(self.svc.store.accounts, sort_keys=True)
        before_index = json.dumps(self.svc.store.tx_index, sort_keys=True)
        for h in range(3):
            self.svc.get_state_root(str(h))
            for acct in (self.A, self.B, self.C, "f" * 64):
                self.svc.get_account_proof(acct, {"height": str(h)})
        self.assertEqual(json.dumps(self.svc.store.accounts, sort_keys=True), before_accounts)
        self.assertEqual(json.dumps(self.svc.store.tx_index, sort_keys=True), before_index)
        # Current balance endpoint and current proof are the tip view.
        _, acct = self.svc.get_account(self.A)
        _, proof = self.svc.get_account_proof(self.A)
        self.assertEqual(acct["balance"], proof["balance"])
        self.assertEqual(acct["confirmed_transactions"], proof["confirmed_transactions"])

    def test_restart_recomputes_identical_historical_views(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 7)
        self.send(self.kc, self.C, self.A, 3)
        self.mine_and_confirm()
        snapshot = {}
        for h in range(3):
            _, snapshot[("root", h)] = self.svc.get_state_root(str(h))
            for acct in (self.A, self.B, self.C):
                status, proof = self.svc.get_account_proof(acct, {"height": str(h)})
                if status == 200:
                    snapshot[("proof", h, acct)] = proof
        reopened = LedgerService(LedgerStore(self.path), initial_balance=self.endowment)
        for h in range(3):
            _, body = reopened.get_state_root(str(h))
            self.assertEqual(body, snapshot[("root", h)])
            for acct in (self.A, self.B, self.C):
                status, proof = reopened.get_account_proof(acct, {"height": str(h)})
                if ("proof", h, acct) in snapshot:
                    self.assertEqual(status, 200)
                    self.assertEqual(proof, snapshot[("proof", h, acct)])
                else:
                    self.assertEqual(status, 404)

    def test_fork_adoption_rebases_historical_views(self) -> None:
        # Canonical chain: two confirmed blocks involving A/B/C.
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        self.send(self.kb, self.B, self.A, 5)
        self.mine_and_confirm()
        old_root_1 = self.svc.get_state_root("1")[1]

        # Build a strictly longer competing fork from the shared genesis with
        # fresh transactions (unique tx ids, endowment replay valid).
        kx, X = keypair()
        ky, Y = keypair()
        kz, Z = keypair()
        genesis = self.svc.store.chain[0]

        def fork_tx(key, s, t, amt):
            from ledger.models import Transaction
            msg = crypto.canonical_message(s, t, amt)
            return Transaction(s, t, amt, key.sign(msg).hex())

        fb1 = Block.create(1, genesis.block_hash, [fork_tx(kx, X, Y, 11)], STATUS_CONFIRMED)
        fb2 = Block.create(2, fb1.block_hash, [fork_tx(ky, Y, Z, 7)], STATUS_CONFIRMED)
        fb3 = Block.create(3, fb2.block_hash, [fork_tx(kz, Z, X, 1)], STATUS_CONFIRMED)
        payload = {"blocks": [b.to_dict() for b in (genesis, fb1, fb2, fb3)]}
        status, body = self.svc.submit_fork_candidate(payload)
        self.assertEqual(status, 201, body)
        status, adopted = self.svc.adopt_fork(fb3.block_hash)
        self.assertEqual(status, 200, adopted)

        # Historical views now follow the adopted canonical prefix.
        status, root1 = self.svc.get_state_root("1")
        self.assertEqual(status, 200)
        self.assertEqual(root1["block_hash"], fb1.block_hash)
        self.assertNotEqual(root1, old_root_1)
        prefix = self.svc.store.chain[:2]
        rows = self.svc.store.account_state_rows(prefix, self.svc.initial_balance)
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        self.assertEqual(root1["state_root"], crypto.account_state_root(leaves))
        self.assertEqual(root1["account_count"], 2)
        # Old-chain accounts are absent from the new history; new ones verify.
        self.assertEqual(self.svc.get_account_proof(self.A, {"height": "1"})[0], 404)
        status, px = self.svc.get_account_proof(X, {"height": "1"})
        self.assertEqual(status, 200)
        self.assertTrue(
            crypto.verify_account_proof(px, root1["state_root"], 1, fb1.block_hash)
        )
        # The persisted snapshot keeps the adopted history after restart.
        reopened = LedgerService(LedgerStore(self.path), initial_balance=self.endowment)
        self.assertEqual(reopened.get_state_root("1")[1], root1)

    def test_concurrent_historical_reads_are_consistent(self) -> None:
        self.send(self.ka, self.A, self.B, 100)
        self.mine_and_confirm()
        # Once confirmed, the root at height 1 is immutable under later
        # mine/confirm/rollback activity.
        _, frozen = self.svc.get_state_root("1")
        errors: list[Exception] = []

        def reader() -> None:
            try:
                for _ in range(200):
                    status, body = self.svc.get_state_root("1")
                    if status != 200 or body != frozen:
                        errors.append(AssertionError((status, body)))
                    status, proof = self.svc.get_account_proof(
                        self.A, {"height": "1"}
                    )
                    if status != 200:
                        errors.append(AssertionError(("proof", status)))
                    elif not crypto.verify_account_proof(
                        proof, frozen["state_root"], 1, frozen["block_hash"]
                    ):
                        errors.append(AssertionError("proof does not verify"))
            except Exception as exc:  # pragma: no cover - test-only failure path
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        # Mutating activity on the main thread: block 2 confirms, block 3 is
        # mined pending and rolled back; none touches the confirmed height-1
        # prefix.
        self.send(self.kb, self.B, self.A, 9)
        self.mine_and_confirm()
        self.send(self.kc, self.C, self.A, 1)
        _, pending = self.svc.mine_block()
        self.svc.rollback_block(pending["height"])
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


class HistoryHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=100_000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 77))
        _, cls.blk = cls.service.mine_block()
        cls.service.confirm_block(cls.blk["height"])

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

    def test_historical_root_route(self) -> None:
        status, body = self.request("/v1/state/root/0")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["state_root"], crypto.EMPTY_MERKLE_ROOT)
        status, body = self.request(f"/v1/state/root/{self.blk['height']}")
        self.assertEqual(status, 200)
        self.assertEqual(body["block_hash"], self.blk["block_hash"])
        for bad in ("01", "-1", "abc", "99", "1.0"):
            self.assertEqual(self.request(f"/v1/state/root/{bad}")[0], 404, bad)

    def test_historical_proof_route_and_repeated_params(self) -> None:
        status, rootdoc = self.request(f"/v1/state/root/{self.blk['height']}")
        self.assertEqual(status, 200)
        status, proof = self.request(f"/v1/accounts/{self.B}/proof?height={self.blk['height']}")
        self.assertEqual(status, 200, proof)
        self.assertEqual(proof["height"], self.blk["height"])
        self.assertTrue(
            crypto.verify_account_proof(
                proof, rootdoc["state_root"],
                rootdoc["height"], rootdoc["block_hash"],
            )
        )
        # Strict query handling: 400 for malformed/repeated, 404 for unknown.
        self.assertEqual(self.request(f"/v1/accounts/{self.B}/proof?height=01")[0], 400)
        self.assertEqual(self.request(f"/v1/accounts/{self.B}/proof?height=x")[0], 400)
        self.assertEqual(
            self.request(f"/v1/accounts/{self.B}/proof?height=1&height=1")[0], 400
        )
        self.assertEqual(self.request(f"/v1/accounts/{self.B}/proof?height=99")[0], 404)
        # A single unknown parameter is rejected 400 too — it must not be
        # silently ignored and fall back to the tip-anchored view.
        self.assertEqual(
            self.request(f"/v1/accounts/{self.B}/proof?foo=1")[0], 400
        )
        self.assertEqual(
            self.request(f"/v1/accounts/{self.B}/proof?height=1&foo=1")[0], 400
        )
        # An unrelated repeated parameter is rejected too.
        self.assertEqual(
            self.request(f"/v1/accounts/{self.B}/proof?height=1&foo=1&foo=2")[0], 400
        )
        # No parameter still anchors the tip.
        status, default_proof = self.request(f"/v1/accounts/{self.B}/proof")
        self.assertEqual(status, 200)
        self.assertEqual(default_proof, proof)


class HistoryCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=100_000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 9))
        _, cls.blk = cls.service.mine_block()
        cls.service.confirm_block(cls.blk["height"])

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

    def test_state_root_height_verbatim(self) -> None:
        rc, body, raw = self.run_cli("state-root", "--height", "0")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["height"], 0)
        self.assertEqual(body["state_root"], crypto.EMPTY_MERKLE_ROOT)
        rc, body, raw = self.run_cli("state-root", "--height", "1")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body, {
            "state_root": body["state_root"],
            "height": 1,
            "block_hash": self.blk["block_hash"],
            "account_count": 2,
        })
        # Unknown height: non-2xx, single error line, exit 1.
        rc, body, _ = self.run_cli("state-root", "--height", "99")
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        # Malformed height is a path-shaped 404 forwarded verbatim.
        rc, body, _ = self.run_cli("state-root", "--height", "01")
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        # Omitting --height preserves the original output exactly.
        rc, default, raw = self.run_cli("state-root")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(default["height"], 1)

    def test_state_proof_height_verbatim(self) -> None:
        rc, proof, raw = self.run_cli("state-proof", self.B, "--height", "1")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(proof["account"], self.B)
        self.assertEqual(proof["height"], 1)
        self.assertEqual(proof["block_hash"], self.blk["block_hash"])
        # Account absent at genesis history.
        rc, body, _ = self.run_cli("state-proof", self.B, "--height", "0")
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        # Malformed query height: 400 forwarded verbatim.
        rc, body, _ = self.run_cli("state-proof", self.B, "--height", "01")
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        # No --height: unchanged invocation.
        rc, default, raw = self.run_cli("state-proof", self.B)
        self.assertEqual(rc, 0, raw)
        self.assertEqual(default, proof)


if __name__ == "__main__":
    unittest.main()

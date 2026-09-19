"""Tests for fork candidates: submission, comparison and atomic adoption.

Covers POST /v1/forks/candidates (201/400/409), GET /v1/chain ordering and
``adoptable`` (longest wins, smallest tip_hash on a tie), and
POST /v1/forks/{tip_hash}/adopt (404/409/200) at the service, HTTP and CLI
levels. Adoption replaces the chain atomically, bumps ``generation``,
rebuilds the indexes, returns transactions unique to the old (confirmed)
chain to the mempool de-duplicated, and keeps pending-tip transactions out
of the pool. Restart retains valid candidates, drops invalid candidates,
and raises StateRecoveryError when the canonical snapshot is invalid.

Run: python3 tests/fork_test.py
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
from ledger.models import STATUS_CONFIRMED, STATUS_PENDING, Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import GENESIS_PREV_HASH, LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def make_block(prev_hash: str, height: int, tx_dicts: list[dict], status: str) -> Block:
    txs = [Transaction.from_dict(tx) for tx in tx_dicts]
    return Block.create(height, prev_hash, txs, status)


class ForkServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.genesis_hash = self.svc.store.chain[0].block_hash

    def fork(self, tx_dicts: list[dict], status: str = STATUS_CONFIRMED) -> Block:
        return make_block(self.genesis_hash, 1, tx_dicts, status)

    def test_valid_candidate_and_summary(self) -> None:
        block = self.fork([make_tx(self.ka, self.A, self.B, 100)])
        status, body = self.svc.submit_candidates({"blocks": [block.to_dict()]})
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "tip_hash": block.block_hash,
                "height": 1,
                "length": 2,  # includes the genesis block
                "status": STATUS_CONFIRMED,
            },
        )
        self.assertIn(block.block_hash, self.svc.store.forks)

    def test_submission_accepts_full_chain_and_height_one_prefix(self) -> None:
        block = self.fork([make_tx(self.kb, self.B, self.A, 5)])
        genesis_dict = self.svc.store.chain[0].to_dict()
        status, _ = self.svc.submit_candidates(
            {"blocks": [genesis_dict, block.to_dict()]}
        )
        self.assertEqual(status, 201)
        # The same tip presented as a height-1-only prefix is a duplicate.
        self.assertEqual(
            self.svc.submit_candidates({"blocks": [block.to_dict()]})[0], 409
        )

    def test_duplicate_candidate_is_409(self) -> None:
        block = self.fork([make_tx(self.ka, self.A, self.B, 10)])
        self.assertEqual(self.svc.submit_candidates({"blocks": [block.to_dict()]})[0], 201)
        status, body = self.svc.submit_candidates({"blocks": [block.to_dict()]})
        self.assertEqual(status, 409)
        self.assertEqual(body["tip_hash"], block.block_hash)

    def test_resubmitting_a_canonical_prefix_is_409(self) -> None:
        # After adoption the adopted tip is canonical; re-offering it is 409.
        block = self.fork([make_tx(self.ka, self.A, self.B, 10)])
        self.svc.submit_candidates({"blocks": [block.to_dict()]})
        self.svc.adopt_fork(block.block_hash)
        self.assertEqual(
            self.svc.submit_candidates({"blocks": [block.to_dict()]})[0], 409
        )

    def test_invalid_candidates_are_400(self) -> None:
        good_tx = make_tx(self.ka, self.A, self.B, 10)
        cases = []

        # Not an object / missing or empty blocks.
        cases.append({})
        cases.append({"blocks": []})
        cases.append({"blocks": "x"})

        # Bad signature.
        bad_sig = {**good_tx, "signature": "00" * 64}
        cases.append({"blocks": [self.fork([bad_sig]).to_dict()]})

        # Tampered block hash.
        tampered = self.fork([good_tx]).to_dict()
        tampered["block_hash"] = "ab" * 32
        cases.append({"blocks": [tampered]})

        # prev_hash does not connect to the canonical genesis.
        wrong_prev = make_block("11" * 64, 1, [good_tx], STATUS_CONFIRMED).to_dict()
        cases.append({"blocks": [wrong_prev]})

        # Non-consecutive / non-genesis-anchored start height.
        high = self.fork([good_tx]).to_dict()
        high["height"] = 2
        cases.append({"blocks": [high]})

        # Wrong genesis block supplied in a full-chain submission.
        wrong_genesis = Block.create(
            0, GENESIS_PREV_HASH, [], STATUS_CONFIRMED
        ).to_dict()
        wrong_genesis["merkle_root"] = "cd" * 32
        wrong_genesis["block_hash"] = "ef" * 32
        cases.append(
            {"blocks": [wrong_genesis, self.fork([good_tx]).to_dict()]}
        )

        # Pending block anywhere except the tip (here: pending height 1 plus a
        # confirmed height 2 on top).
        pending_first = self.fork([good_tx], STATUS_PENDING)
        second = make_block(
            pending_first.block_hash,
            2,
            [make_tx(self.kb, self.B, self.A, 1)],
            STATUS_CONFIRMED,
        )
        cases.append({"blocks": [pending_first.to_dict(), second.to_dict()]})

        # Replay overspend: two blocks drain the sender below zero.
        over1 = make_block(
            self.genesis_hash,
            1,
            [make_tx(self.ka, self.A, self.B, 600)],
            STATUS_CONFIRMED,
        )
        over2 = make_block(
            over1.block_hash,
            2,
            [make_tx(self.ka, self.A, self.B, 600)],
            STATUS_CONFIRMED,
        )
        cases.append({"blocks": [over1.to_dict(), over2.to_dict()]})

        # Duplicate tx_id across two blocks of the fork.
        dup_tx = make_tx(self.ka, self.A, self.B, 7)
        d1 = make_block(self.genesis_hash, 1, [dup_tx], STATUS_CONFIRMED)
        d2 = make_block(d1.block_hash, 2, [dict(dup_tx)], STATUS_CONFIRMED)
        cases.append({"blocks": [d1.to_dict(), d2.to_dict()]})

        for i, payload in enumerate(cases):
            status, body = self.svc.submit_candidates(payload)
            self.assertEqual(status, 400, f"case {i}: {body}")

    def test_pending_tip_candidate_is_accepted(self) -> None:
        confirmed = make_block(
            self.genesis_hash, 1, [make_tx(self.ka, self.A, self.B, 10)], STATUS_CONFIRMED
        )
        pending = make_block(
            confirmed.block_hash,
            2,
            [make_tx(self.kb, self.B, self.A, 4)],
            STATUS_PENDING,
        )
        status, body = self.svc.submit_candidates(
            {"blocks": [confirmed.to_dict(), pending.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], STATUS_PENDING)
        self.assertEqual(body["height"], 2)
        self.assertEqual(body["length"], 3)

    def test_chain_view_ordering_and_adoptable(self) -> None:
        # Extend the canonical chain to length 2 so same-height (length-2)
        # candidates genuinely tie with it on the longest-chain rule.
        base = make_block(
            self.genesis_hash,
            1,
            [make_tx(self.ka, self.A, self.B, 1)],
            STATUS_CONFIRMED,
        )
        self.svc.submit_candidates({"blocks": [base.to_dict()]})
        self.svc.adopt_fork(base.block_hash)
        canonical_tip = base.block_hash

        f1 = make_block(
            self.genesis_hash, 1, [make_tx(self.kb, self.B, self.A, 1)], STATUS_CONFIRMED
        )
        f2 = make_block(
            self.genesis_hash, 1, [make_tx(self.kc, self.C, self.B, 1)], STATUS_CONFIRMED
        )
        self.svc.submit_candidates({"blocks": [f1.to_dict()]})
        self.svc.submit_candidates({"blocks": [f2.to_dict()]})

        status, view = self.svc.get_chain()
        self.assertEqual(status, 200)
        self.assertEqual(
            view["canonical"],
            {
                "tip_hash": canonical_tip,
                "height": 1,
                "length": 2,
                "status": STATUS_CONFIRMED,
            },
        )
        # Candidates sorted by ascending tip_hash.
        candidate_tips = [c["tip_hash"] for c in view["candidates"]]
        self.assertEqual(candidate_tips, sorted(candidate_tips))
        self.assertEqual(set(candidate_tips), {f1.block_hash, f2.block_hash})
        # All three length-2 chains tie: the single smallest tip wins. It is
        # adoptable only when that winner is a candidate (not the canonical).
        all_tips = sorted([canonical_tip, f1.block_hash, f2.block_hash])
        adoptable = [c["tip_hash"] for c in view["candidates"] if c["adoptable"]]
        if all_tips[0] == canonical_tip:
            self.assertEqual(adoptable, [])
        else:
            self.assertEqual(adoptable, [all_tips[0]])

    def test_longest_chain_beats_shorter(self) -> None:
        short = self.fork([make_tx(self.ka, self.A, self.B, 1)])
        first = make_block(
            self.genesis_hash,
            1,
            [make_tx(self.kb, self.B, self.A, 1)],
            STATUS_CONFIRMED,
        )
        long_tip = make_block(
            first.block_hash,
            2,
            [make_tx(self.kc, self.C, self.A, 1)],
            STATUS_CONFIRMED,
        )
        self.svc.submit_candidates({"blocks": [short.to_dict()]})
        self.svc.submit_candidates(
            {"blocks": [first.to_dict(), long_tip.to_dict()]}
        )
        _, view = self.svc.get_chain()
        by_tip = {c["tip_hash"]: c["adoptable"] for c in view["candidates"]}
        self.assertFalse(by_tip[short.block_hash])
        self.assertTrue(by_tip[long_tip.block_hash])
        # Short (non-winner) cannot be adopted.
        self.assertEqual(self.svc.adopt_fork(short.block_hash)[0], 409)
        # Unknown tip is 404 (also covers malformed hashes).
        self.assertEqual(self.svc.adopt_fork("z" * 64)[0], 404)
        self.assertEqual(self.svc.adopt_fork("nope")[0], 404)

    def test_adopt_winner_replaces_chain_and_returns_old_txs(self) -> None:
        # Canonical chain: height 1 confirmed (tx1), height 2 pending (tx2).
        tx1 = make_tx(self.ka, self.A, self.B, 100)
        c1 = make_block(self.genesis_hash, 1, [tx1], STATUS_CONFIRMED)
        self.svc.submit_candidates({"blocks": [c1.to_dict()]})
        self.svc.adopt_fork(c1.block_hash)
        tx2 = make_tx(self.ka, self.A, self.C, 50)
        c2 = make_block(c1.block_hash, 2, [tx2], STATUS_PENDING)
        self.svc.store.chain.append(c2)
        self.svc.store.save()
        self.svc.store.rebuild_derived()

        # Winning fork (length 4, strictly longer than the length-3 canonical)
        # reuses tx1 on its confirmed path, adds tx3, and has a pending tip
        # carrying tx4.
        tx1_obj = Transaction.from_dict(tx1)
        f1 = make_block(self.genesis_hash, 1, [tx1], STATUS_CONFIRMED)
        tx3 = make_tx(self.kc, self.C, self.A, 8)
        f2 = make_block(
            f1.block_hash, 2, [tx3], STATUS_CONFIRMED
        )
        tx4 = make_tx(self.ka, self.A, self.B, 20)
        f3 = make_block(f2.block_hash, 3, [tx4], STATUS_PENDING)
        status, summary = self.svc.submit_candidates(
            {"blocks": [f1.to_dict(), f2.to_dict(), f3.to_dict()]}
        )
        self.assertEqual(status, 201)
        gen_before = self.svc.store.generation

        status, body = self.svc.adopt_fork(f3.block_hash)
        self.assertEqual(status, 200)
        self.assertEqual(body["tip_hash"], f3.block_hash)
        self.assertEqual(body["status"], STATUS_PENDING)
        self.assertEqual(self.svc.store.generation, gen_before + 1)

        chain = self.svc.store.chain
        self.assertEqual(
            [b.block_hash for b in chain],
            [self.genesis_hash, f1.block_hash, f2.block_hash, f3.block_hash],
        )
        # The adopted candidate is removed from the candidate set.
        self.assertNotIn(f3.block_hash, self.svc.store.forks)

        # tx1 is also confirmed on the new chain so it is not returned; the
        # old pending tx2 never re-enters the pool.
        pending_ids = set(self.svc.store.pending)
        self.assertNotIn(Transaction.from_dict(tx2).tx_id, pending_ids)
        self.assertNotIn(tx1_obj.tx_id, pending_ids)
        # Indexes rebuilt from confirmed blocks only (f3 pending excluded).
        self.assertEqual(
            self.svc.store.tx_index, {tx1_obj.tx_id: 1, Transaction.from_dict(tx3).tx_id: 2}
        )

    def test_adopt_returns_only_old_chain_unique_confirmed_txs(self) -> None:
        # Canonical height-1 with old_tx.
        old_tx = make_tx(self.ka, self.A, self.B, 40)
        c1 = make_block(self.genesis_hash, 1, [old_tx], STATUS_CONFIRMED)
        self.svc.submit_candidates({"blocks": [c1.to_dict()]})
        self.svc.adopt_fork(c1.block_hash)
        # A pre-existing mempool entry must be preserved de-duplicated.
        mem_tx_dict = make_tx(self.kb, self.B, self.A, 3)
        self.svc.submit_transaction(mem_tx_dict)
        mem_tx = Transaction.from_dict(mem_tx_dict)

        # Winning fork spends a completely different coin (old_tx not present).
        new_tx = make_tx(self.kc, self.C, self.B, 9)
        f1 = make_block(self.genesis_hash, 1, [new_tx], STATUS_CONFIRMED)
        f2_dict = make_block(
            f1.block_hash, 2,
            [make_tx(self.kb, self.B, self.A, 2)], STATUS_CONFIRMED,
        )
        self.svc.submit_candidates(
            {"blocks": [f1.to_dict(), f2_dict.to_dict()]}
        )
        status, _ = self.svc.adopt_fork(f2_dict.block_hash)
        self.assertEqual(status, 200)
        pending_ids = set(self.svc.store.pending)
        # old_tx is unique to the old confirmed chain -> back in the pool.
        self.assertIn(Transaction.from_dict(old_tx).tx_id, pending_ids)
        # Pre-existing mempool tx preserved.
        self.assertIn(mem_tx.tx_id, pending_ids)
        # New chain transactions never enter the pool.
        self.assertNotIn(Transaction.from_dict(new_tx).tx_id, pending_ids)
        # Accounts rebuilt for the new chain.
        _, acc_c = self.svc.get_account(self.C)
        self.assertEqual(acc_c["balance"], 1000 - 9)

    def test_adopt_prunes_prefix_candidates_keeps_diverging(self) -> None:
        w1 = make_block(
            self.genesis_hash, 1, [make_tx(self.kb, self.B, self.A, 1)], STATUS_CONFIRMED
        )
        w2 = make_block(
            w1.block_hash, 2, [make_tx(self.kc, self.C, self.A, 1)], STATUS_CONFIRMED
        )
        w3 = make_block(
            w2.block_hash, 3, [make_tx(self.ka, self.A, self.C, 1)], STATUS_CONFIRMED
        )
        diverge1 = make_block(
            self.genesis_hash, 1, [make_tx(self.kc, self.C, self.B, 2)], STATUS_CONFIRMED
        )
        diverge2 = make_block(
            diverge1.block_hash, 2, [make_tx(self.ka, self.A, self.B, 2)], STATUS_CONFIRMED
        )
        # A strict prefix of the winner (its height-1 block), the winner itself
        # (length 4), and a diverging length-3 competitor.
        self.assertEqual(self.svc.submit_candidates({"blocks": [w1.to_dict()]})[0], 201)
        self.assertEqual(
            self.svc.submit_candidates(
                {"blocks": [w1.to_dict(), w2.to_dict(), w3.to_dict()]}
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.submit_candidates(
                {"blocks": [diverge1.to_dict(), diverge2.to_dict()]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(w3.block_hash)[0], 200)
        tips = set(self.svc.store.forks)
        self.assertNotIn(w1.block_hash, tips)  # prefix now sits on canonical
        self.assertIn(diverge2.block_hash, tips)  # diverging competitor stays

    def test_restart_keeps_valid_forks_and_generation(self) -> None:
        block = self.fork([make_tx(self.ka, self.A, self.B, 10)])
        self.svc.submit_candidates({"blocks": [block.to_dict()]})
        gen = self.svc.store.generation

        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.assertEqual(set(reopened.store.forks), {block.block_hash})
        self.assertEqual(reopened.store.generation, gen)
        _, view = reopened.get_chain()
        self.assertEqual(len(view["candidates"]), 1)

    def test_restart_rejects_invalid_canonical_snapshot(self) -> None:
        self.fork and self.svc.submit_candidates(
            {"blocks": [self.fork([make_tx(self.ka, self.A, self.B, 1)]).to_dict()]}
        )
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["chain"][0]["block_hash"] = "99" * 32  # corrupt canonical chain
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.path)

    def test_restart_drops_invalid_temp_candidate(self) -> None:
        block = self.fork([make_tx(self.ka, self.A, self.B, 10)])
        self.svc.submit_candidates({"blocks": [block.to_dict()]})
        tip = block.block_hash

        # Leave an older, corrupt .ledger-* snapshot next to the valid main.
        with open(self.path, encoding="utf-8") as fh:
            stale = json.load(fh)
        stale["state"]["generation"] -= 1
        stale["forks"][0]["blocks"][1]["merkle_root"] = "00" * 32
        tmp_path = os.path.join(self.tmp, ".ledger-stale")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(stale, fh)

        reopened = LedgerStore(self.path)
        self.assertIn(tip, reopened.forks)  # valid main wins; stale dropped
        self.assertFalse(
            any(n.startswith(".ledger-") for n in os.listdir(self.tmp))
        )

    def test_same_generation_conflicting_snapshots_raise(self) -> None:
        # Two independently valid snapshots at the same generation with
        # different content (one carries a fork candidate) must conflict.
        other_dir = tempfile.mkdtemp()
        other_path = os.path.join(other_dir, "other.json")
        other_svc = LedgerService(LedgerStore(other_path), initial_balance=1000)
        other_genesis = other_svc.store.chain[0].block_hash
        other_block = make_block(
            other_genesis,
            1,
            [make_tx(self.ka, self.A, self.B, 1)],
            STATUS_CONFIRMED,
        )
        self.assertEqual(
            other_svc.submit_candidates({"blocks": [other_block.to_dict()]})[0], 201
        )
        with open(other_path, encoding="utf-8") as fh:
            other = json.load(fh)

        # Self store is a fresh genesis-only snapshot (generation 1).
        fresh_dir = tempfile.mkdtemp()
        fresh_path = os.path.join(fresh_dir, "fresh.json")
        LedgerStore(fresh_path)
        with open(fresh_path, encoding="utf-8") as fh:
            main = json.load(fh)
        # Rewrite the other snapshot to the same generation but keep its
        # (valid) differing content.
        other["state"]["generation"] = main["state"]["generation"]
        with open(os.path.join(fresh_dir, ".ledger-conflict"), "w") as fh:
            json.dump(other, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(fresh_path)


class ForkHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
        )
        cls.genesis_hash = cls.service.store.chain[0].block_hash
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method: str, path: str, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_fork_endpoints_over_http(self) -> None:
        status, view = self.request("GET", "/v1/chain")
        self.assertEqual(status, 200)
        self.assertEqual(view["candidates"], [])

        block = make_block(
            self.genesis_hash,
            1,
            [make_tx(self.ka, self.A, self.B, 100)],
            STATUS_CONFIRMED,
        )
        status, body = self.request(
            "POST", "/v1/forks/candidates", {"blocks": [block.to_dict()]}
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["tip_hash"], block.block_hash)
        self.assertEqual(self.request("POST", "/v1/forks/candidates", {"blocks": [block.to_dict()]})[0], 409)
        self.assertEqual(self.request("POST", "/v1/forks/candidates", {"blocks": []})[0], 400)

        # Unknown / non-winner adopt.
        self.assertEqual(self.request("POST", f"/v1/forks/{'a'*64}/adopt", {})[0], 404)
        # Winner adopt.
        status, adopted = self.request("POST", f"/v1/forks/{block.block_hash}/adopt", {})
        self.assertEqual(status, 200)
        self.assertEqual(adopted["tip_hash"], block.block_hash)
        # Unknown again after adoption.
        self.assertEqual(self.request("POST", f"/v1/forks/{block.block_hash}/adopt", {})[0], 404)


class ForkCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=1000
        )
        cls.genesis_hash = cls.service.store.chain[0].block_hash
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args, stdin: str | None = None) -> tuple[int, dict, str]:
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
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw), raw

    def test_candidates_chain_adopt_cli(self) -> None:
        block = make_block(
            self.genesis_hash,
            1,
            [make_tx(self.ka, self.A, self.B, 77)],
            STATUS_CONFIRMED,
        )
        payload = json.dumps({"blocks": [block.to_dict()]})

        # Submit via stdin.
        rc, body, _ = self.run_cli("candidates", "-", stdin=payload)
        self.assertEqual(rc, 0)
        self.assertEqual(body["tip_hash"], block.block_hash)
        # Inline JSON string.
        rc, body, _ = self.run_cli("candidates", payload)
        self.assertEqual(rc, 1)  # duplicate -> 409
        # @file.
        fixture = os.path.join(self.tmp, "cand.json")
        with open(fixture, "w", encoding="utf-8") as fh:
            fh.write(payload)
        rc, _, _ = self.run_cli("candidates", f"@{fixture}")
        self.assertEqual(rc, 1)  # still a duplicate

        # chain.
        rc, view, _ = self.run_cli("chain")
        self.assertEqual(rc, 0)
        self.assertEqual(view["candidates"][0]["tip_hash"], block.block_hash)

        # adopt unknown exits 1; winner exits 0.
        rc, _, _ = self.run_cli("adopt", "b" * 64)
        self.assertEqual(rc, 1)
        rc, adopted, _ = self.run_cli("adopt", block.block_hash)
        self.assertEqual(rc, 0)
        self.assertEqual(adopted["tip_hash"], block.block_hash)


if __name__ == "__main__":
    unittest.main()

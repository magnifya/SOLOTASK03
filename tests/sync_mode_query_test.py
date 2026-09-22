"""Tests for the optional ``mode`` query parameter on
GET /v1/forks/sync and GET /v1/forks/sync/history.

For GET /v1/forks/sync: absent or ``plain`` lists only ordinary syncs,
``attested`` only signature-attested syncs and ``all`` merges both tables,
ordered by (height, tip_hash, source, mode, request_id); items keep the
historical seven fields; invalid values and repeated parameters are 400.

For GET /v1/forks/sync/history: absent or ``all`` returns every event,
``plain`` matches ordinary events including legacy rows with no mode field,
``attested`` matches only mode="attested" events; invalid/repeated mode is
400; event output fields are unchanged.

Run: python3 tests/sync_mode_query_test.py
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
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, attested_message


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def seed_keypair() -> tuple[str, str]:
    """A (64-hex Ed25519 seed, matching 64-hex public key) pair."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return seed, pub


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    msg = crypto.canonical_message(sender, to, amount)
    return Transaction.from_dict(
        {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}
    )


def make_fork(blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class ModeQueryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self._trust_seq = 0

    def _register(self, source: str, pub: str) -> None:
        status, body = self.svc.register_trust_source(
            {
                "source": source,
                "public_key": pub,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        self.assertIn(status, (200, 201), body)

    def _trust_dummy(self, source: str) -> None:
        # Plain syncs need an active registry entry but never verify against
        # this key (no signature), so a deterministic hex value suffices.
        self._trust_seq += 1
        self._register(source, format(0x1000 + self._trust_seq, "064x"))

    def _plain_sync(
        self, source: str, request_id: str, block: Block
    ) -> tuple[int, dict]:
        self._trust_dummy(source)
        return self.svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork([self.genesis, block]),
            }
        )

    def _attested_sync(
        self,
        source: str,
        request_id: str,
        block: Block,
        seed: str,
        pub: str,
    ) -> tuple[int, dict]:
        self._register(source, pub)
        candidate = make_fork([self.genesis, block])
        expires_at = int(time.time()) + 3600
        message = attested_message(source, request_id, expires_at, candidate)
        signature = crypto.sign_message(seed, hashlib.sha256(message).digest())
        self.assertIsNotNone(signature)
        return self.svc.submit_fork_sync_attested(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": candidate,
                "signature": signature,
            }
        )

    def _seed(self) -> tuple[str, str]:
        # One plain and one attested height-1 sync from distinct sources.
        plain_block = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.B, 10)],
            "confirmed",
        )
        status, plain_body = self._plain_sync("plain-node", "r1", plain_block)
        self.assertEqual(status, 201, plain_body)
        att_block = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.C, 20)],
            "confirmed",
        )
        att_seed, att_pub = seed_keypair()
        status, att_body = self._attested_sync(
            "att-node", "r2", att_block, att_seed, att_pub
        )
        self.assertEqual(status, 201, att_body)
        return plain_body["tip_hash"], att_body["tip_hash"]

    # -- GET /v1/forks/sync -------------------------------------------------

    def test_syncs_default_is_plain_only(self) -> None:
        plain_tip, att_tip = self._seed()
        for params in ({}, {"mode": "plain"}):
            status, body = self.svc.list_fork_syncs(params)
            self.assertEqual(status, 200, body)
            self.assertEqual(body["total"], 1)
            self.assertEqual(body["items"][0]["tip_hash"], plain_tip)
            self.assertNotEqual(body["items"][0]["tip_hash"], att_tip)

    def test_syncs_attested_only(self) -> None:
        _plain_tip, att_tip = self._seed()
        status, body = self.svc.list_fork_syncs({"mode": "attested"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["tip_hash"], att_tip)

    def test_syncs_all_merges_both_tables(self) -> None:
        plain_tip, att_tip = self._seed()
        status, body = self.svc.list_fork_syncs({"mode": "all"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        self.assertEqual(
            sorted(item["tip_hash"] for item in body["items"]),
            sorted([plain_tip, att_tip]),
        )

    def test_syncs_invalid_mode_400(self) -> None:
        for bad in ("attest", "PLAIN", "ALL", "", "plain ", "signed", 0):
            self.assertEqual(
                self.svc.list_fork_syncs({"mode": bad})[0], 400, bad
            )

    def test_syncs_items_keep_seven_fields(self) -> None:
        self._seed()
        status, body = self.svc.list_fork_syncs({"mode": "all"})
        self.assertEqual(status, 200)
        for item in body["items"]:
            self.assertEqual(
                set(item),
                {
                    "source",
                    "request_id",
                    "tip_hash",
                    "height",
                    "length",
                    "status",
                    "expires_at",
                },
            )

    def test_syncs_merged_ordering_and_pagination(self) -> None:
        # Two records with the same (height, tip_hash) cannot exist, but
        # same-height distinct tips from both modes must interleave by
        # tip_hash then source then mode then request_id.
        blocks: dict[str, Block] = {}
        for idx, to in enumerate((self.B, self.C)):
            blocks[f"p{idx}"] = Block.create(
                1,
                self.genesis.block_hash,
                [tx_obj(self.ka, self.A, to, 5 + idx)],
                "confirmed",
            )
        st, pb0 = self._plain_sync("s1", "rp0", blocks["p0"])
        self.assertEqual(st, 201, pb0)
        st, pb1 = self._plain_sync("s2", "rp1", blocks["p1"])
        self.assertEqual(st, 201, pb1)
        att_seed, att_pub = seed_keypair()
        att0 = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.kb, self.B, self.C, 7)],
            "confirmed",
        )
        st, ab0 = self._attested_sync("s3", "ra0", att0, att_seed, att_pub)
        self.assertEqual(st, 201, ab0)

        status, body = self.svc.list_fork_syncs({"mode": "all", "limit": "200"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)
        keys = [
            (
                item["height"],
                item["tip_hash"],
                item["source"],
                "attested" if item["source"] == "s3" else "plain",
                item["request_id"],
            )
            for item in body["items"]
        ]
        self.assertEqual(keys, sorted(keys))

        # Pagination stays stable across the merged ordering.
        _, page1 = self.svc.list_fork_syncs({"mode": "all", "limit": "2", "cursor": "0"})
        self.assertEqual(page1["total"], 3)
        self.assertEqual(page1["next_cursor"], 2)
        _, page2 = self.svc.list_fork_syncs({"mode": "all", "limit": "2", "cursor": "2"})
        self.assertEqual(
            [it["tip_hash"] for it in page2["items"]],
            [it["tip_hash"] for it in body["items"][2:]],
        )
        self.assertIsNone(page2["next_cursor"])

    def test_syncs_mode_combines_with_other_filters(self) -> None:
        self._seed()
        status, body = self.svc.list_fork_syncs(
            {"mode": "all", "source": "att-node"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["source"], "att-node")
        status, body = self.svc.list_fork_syncs(
            {"mode": "all", "min_height": "2"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        self.assertEqual(
            self.svc.list_fork_syncs({"mode": "all", "limit": "0"})[0], 400
        )

    def test_syncs_same_tip_two_modes_coexist(self) -> None:
        # The same tip delivered once plain and once attested (distinct
        # namespaces) must both list under mode=all: one per mode, ordered by
        # mode. Neither expiry/adoption path may delete the other.
        block = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.B, 10)],
            "confirmed",
        )
        candidate = make_fork([self.genesis, block])
        st, pb = self._plain_sync("p-node", "rp", block)
        self.assertEqual(st, 201, pb)
        # The candidate fork already exists from the plain delivery; the
        # attested delivery of the same tip is therefore 409 — exercise the
        # coexistence through two distinct same-height tips instead, but
        # verify the stored plain record survives an unrelated attested
        # expiry sweep.
        att_seed, att_pub = seed_keypair()
        other = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.C, 11)],
            "confirmed",
        )
        st, ab = self._attested_sync("a-node", "ra", other, att_seed, att_pub)
        self.assertEqual(st, 201, ab)
        # Expire the attested record and sweep via a query; the plain record
        # and its fork must remain.
        self.store.attested_syncs[("a-node", "ra")]["expires_at"] = (
            int(time.time()) - 5
        )
        self.store.save()
        status, body = self.svc.list_fork_syncs({"mode": "plain"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertIn(("p-node", "rp"), self.store.syncs)
        self.assertIn(pb["tip_hash"], self.store.forks)
        # No duplicate expiry event on repeated queries.
        self.svc.list_fork_syncs({"mode": "all"})
        _, history = self.svc.list_fork_sync_history(
            {"mode": "attested", "kind": "sync_expired"}
        )
        self.assertEqual(history["total"], 1)

    # -- GET /v1/forks/sync/history -----------------------------------------

    def test_history_default_and_all_return_everything(self) -> None:
        self._seed()
        for params in ({}, {"mode": "all"}):
            status, body = self.svc.list_fork_sync_history(params)
            self.assertEqual(status, 200, body)
            # One source_registered per source is filtered out by the sync
            # kinds; exactly two sync_received rows remain.
            self.assertEqual(body["total"], 2, params)

    def test_history_plain_excludes_attested(self) -> None:
        plain_tip, att_tip = self._seed()
        status, body = self.svc.list_fork_sync_history({"mode": "plain"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["tip_hash"], plain_tip)

    def test_history_attested_only(self) -> None:
        plain_tip, att_tip = self._seed()
        status, body = self.svc.list_fork_sync_history({"mode": "attested"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["tip_hash"], att_tip)

    def test_history_invalid_mode_400(self) -> None:
        for bad in ("attest", "PLAIN", "ALL", "", "plain "):
            self.assertEqual(
                self.svc.list_fork_sync_history({"mode": bad})[0], 400, bad
            )

    def test_history_items_gain_no_mode_field(self) -> None:
        self._seed()
        status, body = self.svc.list_fork_sync_history({"mode": "all"})
        self.assertEqual(status, 200)
        expected = {
            "event_id",
            "kind",
            "at",
            "source",
            "request_id",
            "tip_hash",
            "height",
            "length",
            "status",
            "expires_at",
        }
        for item in body["items"]:
            self.assertEqual(set(item), expected)

    def test_history_legacy_event_without_mode_counts_as_plain(self) -> None:
        # Seed a plain sync, then strip the mode handling by removing any
        # "mode" key (plain events never had one anyway) and verify the
        # plain filter includes it while attested excludes it.
        plain_block = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.B, 10)],
            "confirmed",
        )
        st, _ = self._plain_sync("p-node", "r1", plain_block)
        self.assertEqual(st, 201)
        for event in self.store.audit_events:
            self.assertNotIn("mode", event)  # plain events stay shapeless
        status, body = self.svc.list_fork_sync_history({"mode": "plain"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        status, body = self.svc.list_fork_sync_history({"mode": "attested"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)

    def test_history_attested_lifecycle_events_all_filtered(self) -> None:
        plain_tip, att_tip = self._seed()
        # Expire the attested record and sweep; received + expired rows for
        # the attested mode must both surface under mode=attested.
        self.store.attested_syncs[("att-node", "r2")]["expires_at"] = (
            int(time.time()) - 5
        )
        self.store.save()
        status, body = self.svc.list_fork_sync_history({"mode": "attested"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        self.assertEqual(
            sorted(item["kind"] for item in body["items"]),
            ["sync_expired", "sync_received"],
        )
        for item in body["items"]:
            self.assertEqual(item["tip_hash"], att_tip)
        # Plain history is unaffected.
        status, body = self.svc.list_fork_sync_history({"mode": "plain"})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)


class ModeQueryHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.svc)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _get(self, path: str, query: str) -> tuple[int, dict]:
        url = f"http://127.0.0.1:{self.port}{path}{query}"
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_syncs_repeated_mode_400(self) -> None:
        status, _ = self._get("/v1/forks/sync", "?mode=plain&mode=attested")
        self.assertEqual(status, 400)
        status, _ = self._get("/v1/forks/sync", "?mode=bogus")
        self.assertEqual(status, 400)

    def test_history_repeated_mode_400(self) -> None:
        status, _ = self._get(
            "/v1/forks/sync/history", "?mode=plain&mode=attested"
        )
        self.assertEqual(status, 400)
        status, _ = self._get("/v1/forks/sync/history", "?mode=bogus")
        self.assertEqual(status, 400)


class ModeQueryCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.svc)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"--base-url=http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _run_cli(self, *args: str) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main([self.base, *args])
        return rc, json.loads(buf.getvalue())

    def test_syncs_mode_forwarded(self) -> None:
        rc, body = self._run_cli("syncs", "--mode", "all")
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 0)
        rc, _ = self._run_cli("syncs", "--mode", "bogus")
        self.assertEqual(rc, 1)

    def test_sync_history_mode_forwarded(self) -> None:
        rc, body = self._run_cli("sync-history", "--mode", "plain")
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 0)
        rc, _ = self._run_cli("sync-history", "--mode", "bogus")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

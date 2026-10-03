"""Regression tests for strict ASCII-decimal height validation.

Covers the historical state root, plain and signed single-account
inclusion/absence proofs, and the batch signed account proofs:

* service methods: a height must be the literal string ``"0"`` or a string
  of ASCII digits starting with 1-9; the empty string, leading zeros,
  signs, whitespace, decimal/scientific forms, full-width/Arabic-Indic/
  superscript/mixed digits and non-string JSON values (numbers, booleans,
  null) are rejected without normalization or truncation. Malformed path
  heights are 404 ``block not found``; malformed query/body heights are 400
  ``height must be a non-negative decimal``. A well-formed over-long height
  folds to an unknown height (404) instead of hitting the interpreter's
  integer digit cap or returning 400/500;
* HTTP routes: the decoded URL value is judged, bodies are judged by their
  original JSON string, repeated/unknown query parameters stay 400, the
  default anchor/pending/404/409 semantics are unchanged, and an over-long
  path height answers a complete JSON 404 over a raw socket;
* CLI: state-root/state-proof forward the height verbatim and print the
  server's one-line JSON (exit 1 on non-2xx); state-proofs rejects a
  malformed height locally with the ordered ``{"ok", "error"}`` input body,
  exit 1 and no request, while forwarding well-formed (even over-long)
  heights;
* error requests mutate no ledger/snapshot/generation/index/audit state and
  a normal historical proof still succeeds afterwards.

Run: python3 tests/height_validation_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto, light_client
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import (
    LedgerService,
    _parse_height_decimal,
)
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount,
            "signature": key.sign(msg).hex()}


# Every malformed string form named in the contract. None may be accepted
# after Unicode normalization or truncation.
MALFORMED_HEIGHTS = [
    "",            # empty string
    "00", "01",    # leading zeros
    "-1", "+1",    # signs
    " ", " 1", "1 ", "\t1", "1\n",  # whitespace
    "1.0", ".5", "1.",              # decimal forms
    "1e3", "1E3", "0e0",            # scientific notation
    "１２",        # full-width digits
    "١٢٣",        # Arabic-Indic digits
    "²",           # superscript digit
    "1١", "１0",  # mixed-script digits
    "０１",        # full-width leading-zero pair
]

# A syntactically valid height far longer than CPython's 4300-digit integer
# conversion cap and far beyond any real chain: it must stay a well-formed
# unknown height, never raise or turn into a format error.
LONG_HEIGHT = "1" + "0" * 4999
assert len(LONG_HEIGHT) == 5000


class HeightParserTests(unittest.TestCase):
    def test_accepts_only_canonical_ascii_decimal(self) -> None:
        self.assertEqual(_parse_height_decimal("0"), 0)
        self.assertEqual(_parse_height_decimal("1"), 1)
        self.assertEqual(_parse_height_decimal("1234567890"), 1234567890)
        for bad in MALFORMED_HEIGHTS:
            self.assertIsNone(_parse_height_decimal(bad), repr(bad))
        for non_string in (None, True, False, 0, 1, -1, 1.0, [], {}, b"1"):
            self.assertIsNone(_parse_height_decimal(non_string), repr(non_string))

    def test_over_long_valid_string_folds_without_raising(self) -> None:
        # The largest 18-digit value converts normally.
        self.assertEqual(_parse_height_decimal("9" * 18), 10**18 - 1)
        # Anything longer folds to the beyond-chain sentinel: independent of
        # sys.set_int_max_str_digits and never an exception.
        self.assertEqual(_parse_height_decimal("1" + "0" * 18), 10**18)
        self.assertEqual(_parse_height_decimal("9" * 5000), 10**18)
        self.assertEqual(_parse_height_decimal(LONG_HEIGHT), 10**18)

    def test_over_long_malformed_string_still_rejected(self) -> None:
        # Length never rescues a malformed form.
        self.assertIsNone(_parse_height_decimal("0" + "0" * 5000))
        self.assertIsNone(_parse_height_decimal("1" * 4999 + "١"))
        self.assertIsNone(_parse_height_decimal(" " + "1" * 5000))


class HeightServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
        )
        # Two confirmed blocks: block 1 A->B 100 and C->A 40; block 2
        # B->A 5; block 3 left pending.
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 100))
        self.svc.submit_transaction(make_tx(self.kc, self.C, self.A, 40))
        _, self.blk1 = self.svc.mine_block()
        self.assertEqual(self.svc.confirm_block(1)[0], 200)
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.A, 5))
        _, self.blk2 = self.svc.mine_block()
        self.assertEqual(self.svc.confirm_block(2)[0], 200)
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.A, 2))
        _, self.pending = self.svc.mine_block()  # height 3, pending
        self.ghost = "0" * 64

    def snapshot(self) -> tuple:
        with open(self.path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        return (
            self.svc.store.generation,
            json.dumps(self.svc.store.accounts, sort_keys=True, default=str),
            json.dumps(self.svc.store.tx_index, sort_keys=True, default=str),
            json.dumps(list(self.svc.store.audit_events), sort_keys=True,
                       default=str),
            digest,
        )

    # -- state root ----------------------------------------------------------

    def test_state_root_malformed_is_404_block_not_found(self) -> None:
        for bad in MALFORMED_HEIGHTS:
            status, body = self.svc.get_state_root(bad)
            self.assertEqual(status, 404, repr(bad))
            self.assertEqual(body, {"error": "block not found"}, repr(bad))
        # Non-string heights are equally unknown.
        for bad in (1, True, False, 1.0, [], {}):
            status, body = self.svc.get_state_root(bad)
            self.assertEqual(status, 404, repr(bad))
            self.assertEqual(body, {"error": "block not found"})

    def test_state_root_pending_and_unknown_are_404(self) -> None:
        self.assertEqual(
            self.svc.get_state_root("3")[0], 404
        )  # pending tip height
        self.assertEqual(self.svc.get_state_root("99")[0], 404)
        self.assertEqual(
            self.svc.get_state_root(LONG_HEIGHT),
            (404, {"error": "block not found"}),
        )

    def test_state_root_valid_historical_heights_still_served(self) -> None:
        status, body = self.svc.get_state_root("0")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["height"], 0)
        self.assertEqual(body["state_root"], crypto.EMPTY_MERKLE_ROOT)
        for height, blk in ((1, self.blk1), (2, self.blk2)):
            status, body = self.svc.get_state_root(str(height))
            self.assertEqual(status, 200)
            self.assertEqual(body["height"], height)
            self.assertEqual(body["block_hash"], blk["block_hash"])
        # Default anchor keeps the tip semantics: tip is pending -> 404.
        self.assertEqual(self.svc.get_state_root()[0], 404)

    # -- single-account proofs ----------------------------------------------

    def test_inclusion_proof_malformed_height_is_400(self) -> None:
        for method in (
            self.svc.get_account_proof,
            self.svc.get_attested_account_proof,
        ):
            for bad in MALFORMED_HEIGHTS:
                status, body = method(self.A, {"height": bad})
                self.assertEqual(status, 400, (method.__name__, repr(bad)))
                self.assertEqual(
                    body,
                    {"error": "height must be a non-negative decimal"},
                    repr(bad),
                )
            # Non-string query values (HTTP query strings are always strings;
            # this documents the defensive service contract).
            for bad in (1, True, False):
                status, body = method(self.A, {"height": bad})
                self.assertEqual(status, 400, (method.__name__, bad))
                self.assertEqual(
                    body, {"error": "height must be a non-negative decimal"}
                )

    def test_absence_proof_malformed_height_is_400(self) -> None:
        for method in (
            self.svc.get_account_absence_proof,
            self.svc.get_attested_account_absence_proof,
        ):
            for bad in MALFORMED_HEIGHTS:
                status, body = method(self.ghost, {"height": bad})
                self.assertEqual(status, 400, (method.__name__, repr(bad)))
                self.assertEqual(
                    body,
                    {"error": "height must be a non-negative decimal"},
                )
            for bad in (1, True, False):
                status, body = method(self.ghost, {"height": bad})
                self.assertEqual(status, 400)
                self.assertEqual(
                    body, {"error": "height must be a non-negative decimal"}
                )

    def test_proofs_unknown_pending_and_missing_account_404(self) -> None:
        for method in (
            self.svc.get_account_proof,
            self.svc.get_attested_account_proof,
        ):
            # Well-formed but beyond the chain (also over the int digit cap).
            self.assertEqual(
                method(self.A, {"height": LONG_HEIGHT})[0], 404
            )
            self.assertEqual(method(self.A, {"height": "99"})[0], 404)
            # Pending anchor.
            self.assertEqual(method(self.A, {"height": "3"})[0], 404)
            # Account missing from a historical view.
            self.assertEqual(
                method(self.ghost, {"height": "2"})[0], 404
            )
        # Pending default tip.
        self.assertEqual(self.svc.get_account_proof(self.A)[0], 404)

    def test_absence_proof_existing_account_is_409(self) -> None:
        for method in (
            self.svc.get_account_absence_proof,
            self.svc.get_attested_account_absence_proof,
        ):
            status, body = method(self.A, {"height": "2"})
            self.assertEqual(status, 409, body)
            # Well-formed unknown height still beats the 409: 404.
            self.assertEqual(
                method(self.A, {"height": LONG_HEIGHT})[0], 404
            )
            # Malformed height is 400, not the 409.
            self.assertEqual(method(self.A, {"height": "01"})[0], 400)

    # -- batch signed proofs -------------------------------------------------

    def test_batch_malformed_height_is_400(self) -> None:
        for bad in MALFORMED_HEIGHTS:
            status, body = self.svc.get_attested_account_proofs(
                {"accounts": [self.A], "height": bad}
            )
            self.assertEqual(status, 400, repr(bad))
            self.assertEqual(
                body, {"error": "height must be a non-negative decimal"}
            )
        # Numeric, boolean and null JSON values use the same 400 body.
        for bad in (1, 0, True, False, None, 1.0):
            status, body = self.svc.get_attested_account_proofs(
                {"accounts": [self.A], "height": bad}
            )
            self.assertEqual(status, 400, repr(bad))
            self.assertEqual(
                body, {"error": "height must be a non-negative decimal"}
            )

    def test_batch_unknown_pending_missing_are_404(self) -> None:
        batch = self.svc.get_attested_account_proofs
        self.assertEqual(
            batch({"accounts": [self.A], "height": LONG_HEIGHT})[0], 404
        )
        self.assertEqual(
            batch({"accounts": [self.A], "height": "99"})[0], 404
        )
        self.assertEqual(
            batch({"accounts": [self.A], "height": "3"})[0], 404
        )
        self.assertEqual(batch({"accounts": [self.ghost]})[0], 404)

    # -- successful historical views keep their shape ------------------------

    def test_normal_historical_proofs_unchanged(self) -> None:
        # Inclusion proof at a confirmed historical height.
        status, proof = self.svc.get_account_proof(self.A, {"height": "1"})
        self.assertEqual(status, 200, proof)
        self.assertEqual(proof["height"], 1)
        self.assertEqual(proof["balance"], 100_000 - 100 + 40)
        _, rootdoc = self.svc.get_state_root("1")
        self.assertTrue(
            crypto.verify_account_proof(
                proof, rootdoc["state_root"], 1, self.blk1["block_hash"]
            )
        )
        # Signed single proof keeps state/proof/auth key order and verifies.
        status, doc = self.svc.get_attested_account_proof(
            self.B, {"height": "1"}
        )
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["state", "proof", "auth"])
        _, trust = self.svc.get_trust_document()
        self.assertTrue(
            light_client.verify_state_proof(doc, self.B, trust)["ok"]
        )
        # Signed absence proof at genesis.
        status, absence = self.svc.get_attested_account_absence_proof(
            self.ghost, {"height": "0"}
        )
        self.assertEqual(status, 200, absence)
        self.assertEqual(list(absence), ["account", "state", "lower", "upper",
                                         "auth"])
        self.assertTrue(
            light_client.verify_state_absence_proof(absence, self.ghost, trust)[
                "ok"
            ]
        )
        # Batch signed proof at height 1: ascending accounts, shared anchor.
        status, batch = self.svc.get_attested_account_proofs(
            {"accounts": [self.C, self.A, self.B], "height": "1"}
        )
        self.assertEqual(status, 200, batch)
        self.assertEqual(list(batch), ["state", "proofs", "auth"])
        self.assertEqual(
            [p["account"] for p in batch["proofs"]],
            sorted([self.A, self.B, self.C]),
        )
        self.assertTrue(
            light_client.verify_state_proofs(
                batch, [self.A, self.B, self.C], trust
            )["ok"]
        )

    # -- no side effects ------------------------------------------------------

    def test_error_requests_change_nothing_and_queries_recover(self) -> None:
        before = self.snapshot()
        for bad in MALFORMED_HEIGHTS:
            self.svc.get_state_root(bad)
            self.svc.get_account_proof(self.A, {"height": bad})
            self.svc.get_account_absence_proof(self.ghost, {"height": bad})
            self.svc.get_attested_account_proof(self.A, {"height": bad})
            self.svc.get_attested_account_absence_proof(
                self.ghost, {"height": bad}
            )
            self.svc.get_attested_account_proofs(
                {"accounts": [self.A], "height": bad}
            )
        for bad in (True, False, None, 1, LONG_HEIGHT, "99", "3"):
            self.svc.get_attested_account_proofs(
                {"accounts": [self.A], "height": bad}
            )
            self.svc.get_account_proof(self.A, {"height": bad})
        after = self.snapshot()
        self.assertEqual(after, before)
        # Normal historical queries still succeed.
        self.assertEqual(self.svc.get_state_root("0")[0], 200)
        self.assertEqual(
            self.svc.get_account_proof(self.B, {"height": "1"})[0], 200
        )
        self.assertEqual(
            self.svc.get_attested_account_proofs(
                {"accounts": [self.A, self.B, self.C], "height": "2"}
            )[0],
            200,
        )


class HeightHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")),
            initial_balance=100_000,
        )
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 100))
        cls.service.submit_transaction(make_tx(cls.kc, cls.C, cls.A, 40))
        _, cls.blk1 = cls.service.mine_block()
        cls.service.confirm_block(1)
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.ghost = "0" * 64

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method: str, path: str, payload=None, raw_body=None):
        if raw_body is not None:
            data = raw_body.encode("utf-8")
        elif payload is not None:
            data = json.dumps(payload).encode("utf-8")
        else:
            data = None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                text = resp.read().decode("utf-8")
                return resp.status, json.loads(text), text
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8")
            return exc.code, json.loads(text), text

    def raw_get(self, path: str) -> tuple[int, bytes]:
        """Issue one GET over a raw socket; return (status, full body)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(
                f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()
            )
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        raw = b"".join(chunks)
        head, _, body = raw.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode()
        status = int(status_line.split()[1])
        return status, body

    # -- state root path ------------------------------------------------------

    def test_state_root_route_malformed_404_json(self) -> None:
        # Plain and percent-encoded malformed segments; the decoded value is
        # what gets judged.
        encoded_paths = [
            "/v1/state/root/01",
            "/v1/state/root/00",
            "/v1/state/root/-1",
            "/v1/state/root/%2D1",        # "-1"
            "/v1/state/root/1%20",        # "1 "
            "/v1/state/root/%201",        # " 1"
            "/v1/state/root/1%2e0",       # "1.0"
            "/v1/state/root/%EF%BC%90%EF%BC%91",   # full-width "０１"
            "/v1/state/root/%D9%A1%D9%A2%D9%A3",   # Arabic-Indic "١٢٣"
            "/v1/state/root/1%D9%A1",     # mixed "1١"
            "/v1/state/root/",            # empty
            "/v1/state/root/99",
        ]
        for path in encoded_paths:
            status, body, text = self.request("GET", path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body, {"error": "block not found"}, path)
            self.assertNotIn("\n", text, path)

    def test_state_root_over_long_valid_height_is_complete_404(self) -> None:
        # Via the ordinary client first.
        status, body, _ = self.request("GET", f"/v1/state/root/{LONG_HEIGHT}")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "block not found"})
        # And over a raw socket: the response must arrive complete (no
        # interrupted stream, no 500) despite the 5000-character path.
        status, raw_body = self.raw_get(f"/v1/state/root/{LONG_HEIGHT}")
        self.assertEqual(status, 404)
        self.assertEqual(
            json.loads(raw_body.decode("utf-8")),
            {"error": "block not found"},
        )

    def test_state_root_valid_historical_route(self) -> None:
        status, body, _ = self.request("GET", "/v1/state/root/0")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["height"], 0)
        status, body, _ = self.request("GET", f"/v1/state/root/{self.blk1['height']}")
        self.assertEqual(status, 200)
        self.assertEqual(body["block_hash"], self.blk1["block_hash"])
        # Missing height keeps the anchor semantics (tip confirmed -> 200).
        status, body, _ = self.request("GET", "/v1/state/root")
        self.assertEqual(status, 200)
        self.assertEqual(body["height"], 1)

    # -- single-account query routes -----------------------------------------

    def test_single_account_routes_malformed_height_400(self) -> None:
        routes = [
            f"/v1/accounts/{self.A}/proof",
            f"/v1/accounts/{self.A}/attested-proof",
            f"/v1/accounts/{self.ghost}/absence-proof",
            f"/v1/accounts/{self.ghost}/attested-absence-proof",
        ]
        encoded_queries = [
            "height=01",
            "height=00",
            "height=-1",
            "height=%2D1",
            "height=",                    # empty
            "height=1%20",
            "height=%201",
            "height=1.0",
            "height=1e3",
            "height=%EF%BC%91%EF%BC%92",  # full-width １２
            "height=%D9%A1%D9%A2%D9%A3",  # Arabic-Indic
            "height=%C2%B2",              # superscript ²
            "height=1%D9%A1",             # mixed
        ]
        for route in routes:
            for query in encoded_queries:
                status, body, _ = self.request("GET", f"{route}?{query}")
                self.assertEqual(status, 400, (route, query))
                self.assertEqual(
                    body, {"error": "height must be a non-negative decimal"},
                    (route, query),
                )

    def test_single_account_routes_repeated_and_unknown_params_400(self) -> None:
        routes = [
            f"/v1/accounts/{self.A}/proof",
            f"/v1/accounts/{self.A}/attested-proof",
            f"/v1/accounts/{self.ghost}/absence-proof",
            f"/v1/accounts/{self.ghost}/attested-absence-proof",
        ]
        for route in routes:
            status, _, _ = self.request("GET", f"{route}?height=1&height=1")
            self.assertEqual(status, 400, route)
            status, body, _ = self.request("GET", f"{route}?height=1&foo=2")
            self.assertEqual(status, 400, route)
            self.assertEqual(body, {"error": "unknown query parameter"})
            status, _, _ = self.request("GET", f"{route}?foo=2")
            self.assertEqual(status, 400, route)

    def test_single_account_routes_unknown_and_semantic_404_409(self) -> None:
        # Over-long valid unknown height: 404, not 400/500.
        for route in (
            f"/v1/accounts/{self.A}/proof",
            f"/v1/accounts/{self.A}/attested-proof",
            f"/v1/accounts/{self.ghost}/absence-proof",
            f"/v1/accounts/{self.ghost}/attested-absence-proof",
        ):
            status, _, _ = self.request("GET", f"{route}?height={LONG_HEIGHT}")
            self.assertEqual(status, 404, route)
            status, _, _ = self.request("GET", f"{route}?height=99")
            self.assertEqual(status, 404, route)
        # Inclusion for an account absent at genesis.
        status, _, _ = self.request(
            "GET", f"/v1/accounts/{self.ghost}/proof?height=0"
        )
        self.assertEqual(status, 404)
        # Absence proof for an existing account is 409.
        status, body, _ = self.request(
            "GET", f"/v1/accounts/{self.A}/absence-proof?height=1"
        )
        self.assertEqual(status, 409, body)
        status, _, _ = self.request(
            "GET", f"/v1/accounts/{self.A}/attested-absence-proof?height=1"
        )
        self.assertEqual(status, 409)
        # Default (no height) still anchors the tip.
        status, body, _ = self.request("GET", f"/v1/accounts/{self.B}/proof")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["height"], 1)

    # -- batch route ----------------------------------------------------------

    def test_batch_route_malformed_height_400(self) -> None:
        for bad in MALFORMED_HEIGHTS:
            status, body, _ = self.request(
                "POST",
                "/v1/accounts/attested-proofs",
                {"accounts": [self.A], "height": bad},
            )
            self.assertEqual(status, 400, repr(bad))
            self.assertEqual(
                body, {"error": "height must be a non-negative decimal"}
            )
        # Numeric, boolean and null JSON heights: judged by the original JSON
        # value, never coerced.
        for literal in ("1", "0", "true", "false", "null", "1.0"):
            status, body, text = self.request(
                "POST",
                "/v1/accounts/attested-proofs",
                raw_body=f'{{"accounts": ["{self.A}"], "height": {literal}}}',
            )
            self.assertEqual(status, 400, literal)
            self.assertEqual(
                body, {"error": "height must be a non-negative decimal"},
                literal,
            )
            self.assertNotIn("\n", text)

    def test_batch_route_over_long_unknown_height_404(self) -> None:
        status, body, _ = self.request(
            "POST",
            "/v1/accounts/attested-proofs",
            {"accounts": [self.A], "height": LONG_HEIGHT},
        )
        self.assertEqual(status, 404, body)
        self.assertEqual(body, {"error": "anchor block not found"})

    def test_batch_route_success_unchanged(self) -> None:
        status, doc, _ = self.request(
            "POST",
            "/v1/accounts/attested-proofs",
            {"accounts": [self.C, self.A, self.B], "height": "1"},
        )
        self.assertEqual(status, 200, doc)
        self.assertEqual(list(doc), ["state", "proofs", "auth"])
        self.assertEqual(
            [p["account"] for p in doc["proofs"]],
            sorted([self.A, self.B, self.C]),
        )

    def test_error_requests_append_no_audit_events(self) -> None:
        def audit_total() -> int:
            status, body, _ = self.request(
                "GET", "/v1/audit/events?limit=200"
            )
            self.assertEqual(status, 200, body)
            return body["total"]

        before = audit_total()
        for bad in MALFORMED_HEIGHTS[:8]:
            encoded = urllib.parse.quote(bad, safe="")
            self.request("GET", f"/v1/state/root/{encoded}")
            self.request(
                "GET",
                f"/v1/accounts/{self.A}/proof?height={encoded}",
            )
            self.request(
                "POST",
                "/v1/accounts/attested-proofs",
                {"accounts": [self.A], "height": bad},
            )
        self.request(
            "POST",
            "/v1/accounts/attested-proofs",
            raw_body=f'{{"accounts": ["{self.A}"], "height": true}}',
        )
        self.request("GET", f"/v1/state/root/{LONG_HEIGHT}")
        self.assertEqual(audit_total(), before)
        # A normal read still works afterwards.
        status, _, _ = self.request(
            "GET", f"/v1/accounts/{self.B}/proof?height=1"
        )
        self.assertEqual(status, 200)


class HeightCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=100_000
        )
        cls.service.submit_transaction(make_tx(cls.ka, cls.A, cls.B, 9))
        _, cls.blk = cls.service.mine_block()
        cls.service.confirm_block(cls.blk["height"])
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        # A port that refuses connections: proves the CLI rejected input
        # locally without sending any request.
        cls.unreachable = "http://127.0.0.1:1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, base_url: str, *args) -> tuple[int, dict, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, raw)
        return rc, json.loads(raw), raw

    def test_state_root_forwards_height_verbatim(self) -> None:
        rc, body, raw = self.run_cli(self.base_url, "state-root", "--height", "0")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["height"], 0)
        rc, body, raw = self.run_cli(self.base_url, "state-root", "--height", "1")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["block_hash"], self.blk["block_hash"])
        # Malformed path height: server 404 forwarded as one-line JSON, rc 1.
        for bad in ("01", "１２"):
            rc, body, raw = self.run_cli(
                self.base_url, "state-root", "--height", bad
            )
            self.assertEqual(rc, 1, (bad, raw))
            self.assertEqual(body, {"error": "block not found"}, bad)
        # Unknown, well-formed.
        rc, body, _ = self.run_cli(self.base_url, "state-root", "--height", "99")
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "block not found"})
        # Default anchor unchanged.
        rc, body, raw = self.run_cli(self.base_url, "state-root")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["height"], 1)

    def test_state_proof_forwards_height_verbatim(self) -> None:
        rc, proof, raw = self.run_cli(
            self.base_url, "state-proof", self.B, "--height", "1"
        )
        self.assertEqual(rc, 0, raw)
        self.assertEqual(proof["account"], self.B)
        # Malformed (incl. non-ASCII) query heights come back as the server's
        # 400 JSON, one line, exit 1 — the CLI never normalizes them.
        for bad in ("01", "-1", "1 ", "１２", "١٢٣"):
            rc, body, raw = self.run_cli(
                self.base_url, "state-proof", self.B, "--height", bad
            )
            self.assertEqual(rc, 1, (bad, raw))
            self.assertEqual(
                body, {"error": "height must be a non-negative decimal"}, bad
            )
        # Unknown height -> 404 forwarded.
        rc, body, _ = self.run_cli(
            self.base_url, "state-proof", self.B, "--height", "99"
        )
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "anchor block not found"})

    def test_state_proofs_rejects_bad_height_locally_without_request(self) -> None:
        for bad in ("", "01", "-1", "+1", "1 ", "1.0", "1e3",
                    "１２", "١٢٣", "²", "1١"):
            rc, body, raw = self.run_cli(
                self.unreachable,
                "state-proofs", self.A, "--height", bad,
            )
            self.assertEqual(rc, 1, (bad, raw))
            self.assertEqual(
                raw.strip(), '{"ok": false, "error": "input"}', (bad, raw)
            )
            self.assertEqual(body, {"ok": False, "error": "input"})
        # A bad account is the same local rejection even with a good height.
        rc, body, raw = self.run_cli(
            self.unreachable, "state-proofs", "not-hex", "--height", "1"
        )
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"ok": False, "error": "input"})

    def test_state_proofs_forwards_well_formed_heights(self) -> None:
        # Normal historical batch.
        rc, body, raw = self.run_cli(
            self.base_url,
            "state-proofs", self.B, self.A, "--height", "1",
        )
        self.assertEqual(rc, 0, raw)
        self.assertEqual(list(body), ["state", "proofs", "auth"])
        self.assertEqual(
            [p["account"] for p in body["proofs"]], sorted([self.A, self.B])
        )
        # An over-long well-formed height is forwarded (not rejected locally)
        # and the server answers a one-line JSON 404, exit 1.
        rc, body, raw = self.run_cli(
            self.base_url,
            "state-proofs", self.A, "--height", LONG_HEIGHT,
        )
        self.assertEqual(rc, 1, raw)
        self.assertEqual(body, {"error": "anchor block not found"})
        # Default height keeps working.
        rc, body, raw = self.run_cli(
            self.base_url, "state-proofs", self.A
        )
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["state"]["height"], 1)


if __name__ == "__main__":
    unittest.main()

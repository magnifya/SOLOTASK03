"""Tests for the receipt-proofs audit HTTP endpoint and CLI subcommand.

``POST /v1/transactions/receipt-proofs/audit`` exposes the offline
``ledger.light_client.receipt_proofs_audit`` core function (itself
unchanged) and ``ledger receipt-proofs-audit FILE|- --expected-root ROOT``
drives it over HTTP:

* the request body is strictly ``{"documents", "expected_root"}`` in that
  order — ``documents`` a non-empty array audited item by item under the
  ``receipt_proof`` contract, ``expected_root`` 64 lowercase hex. An empty
  body, non-UTF-8 bytes, a JSON error, missing/extra/out-of-order keys, an
  empty array or an illegal root are all 400 with the ordered body
  ``{"ok": false, "error": "input"}`` and never touch state;
* a legal batch is answered 200 with the core function's result in the
  contract key order ``ok, root, total, succeeded, errors, entries,
  digest`` (``errors`` ordered ``input, integrity``; ``entries`` aligned
  with the input, successes carrying only ``tx_id``, failures only
  ``error``; ``digest`` the SHA-256 lowercase hex of the canonical
  sorted/compact/unescaped UTF-8 JSON of the summary minus ``digest``);
* the audit is a pure function of the body: concurrent requests and
  restarts yield identical results;
* the CLI reads the documents array from a file or stdin (``-``), reports
  read/JSON/argument errors as the ``input`` body with exit 1 without
  contacting the server, prints the response as one JSON line in key
  order and exits 0 only when the response is 2xx with ``ok`` true.

Run: python3 tests/receipt_proofs_audit_http_test.py
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.light_client import advance_receipts, receipt_proof
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

AUDIT_KEYS = ["ok", "root", "total", "succeeded", "errors", "entries", "digest"]
INPUT_BODY = {"ok": False, "error": "input"}
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def canonical_digest(summary: dict) -> str:
    body = {key: value for key, value in summary.items() if key != "digest"}
    return hashlib.sha256(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


class AuditHttpFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "ledger.json")
        self.start_service()
        self.key = Ed25519PrivateKey.generate()
        self.sender = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.bob = "b" * 64
        self.trust = self.service.get_trust_document()[1]
        self.index_path = os.path.join(self.tmp, "receipts.json")
        self.ids = self.populate()
        self.docs = [receipt_proof(self.index_path, tx_id) for tx_id in self.ids]
        self.root = self.docs[0]["root"]

    def start_service(self) -> None:
        self.service = LedgerService(LedgerStore(self.state_path))
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def populate(self) -> list[str]:
        ids = []
        for amount in (10, 20, 30):
            message = crypto.canonical_message(self.sender, self.bob, amount)
            status, body = self.service.submit_transaction(
                {
                    "from": self.sender,
                    "to": self.bob,
                    "amount": amount,
                    "signature": self.key.sign(message).hex(),
                }
            )
            self.assertEqual(status, 202, body)
            ids.append(body["tx_id"])
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("1")[0], 200)
        ids = sorted(ids)
        status, document = self.service.get_finalized_receipts({"tx_ids": ids})
        self.assertEqual(status, 200, document)
        result = advance_receipts(self.index_path, document, ids, self.trust)
        self.assertTrue(result["ok"], result)
        return ids

    def post(self, raw: bytes) -> tuple[int, str]:
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port)
        connection.request(
            "POST",
            "/v1/transactions/receipt-proofs/audit",
            body=raw,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        text = response.read().decode("utf-8")
        connection.close()
        return response.status, text

    def post_json(self, payload: object) -> tuple[int, dict]:
        status, text = self.post(json.dumps(payload).encode("utf-8"))
        return status, json.loads(text)

    def state_bytes(self) -> bytes:
        with open(self.state_path, "rb") as fh:
            return fh.read()


class HttpContractTests(AuditHttpFixture):
    def test_all_success_contract(self) -> None:
        status, text = self.post(
            json.dumps({"documents": self.docs, "expected_root": self.root}).encode()
        )
        self.assertEqual(status, 200, text)
        body = json.loads(text)
        self.assertEqual(list(body), AUDIT_KEYS)
        # The wire bytes themselves carry the contract key order.
        positions = [text.index(f'"{key}"') for key in AUDIT_KEYS]
        self.assertEqual(positions, sorted(positions))
        self.assertIs(body["ok"], True)
        self.assertEqual(body["root"], self.root)
        self.assertEqual(body["total"], 3)
        self.assertEqual(body["succeeded"], 3)
        self.assertEqual(list(body["errors"]), ["input", "integrity"])
        self.assertEqual(body["errors"], {"input": 0, "integrity": 0})
        self.assertEqual(body["entries"], [{"tx_id": tx_id} for tx_id in self.ids])
        self.assertEqual(body["digest"], canonical_digest(body))
        self.assertRegex(body["digest"], r"^[0-9a-f]{64}$")

    def test_mixed_batch_does_not_short_circuit(self) -> None:
        documents = [{"ok": False}, self.docs[0], self.docs[0], self.docs[1]]
        status, body = self.post_json(
            {"documents": documents, "expected_root": self.root}
        )
        self.assertEqual(status, 200)
        self.assertIs(body["ok"], False)
        self.assertEqual(body["total"], 4)
        self.assertEqual(body["succeeded"], 2)
        self.assertEqual(body["errors"], {"input": 1, "integrity": 1})
        self.assertEqual(
            body["entries"],
            [
                {"error": "input"},
                {"tx_id": self.ids[0]},
                {"error": "integrity"},  # duplicate id of the first claim
                {"tx_id": self.ids[1]},
            ],
        )
        self.assertEqual(body["digest"], canonical_digest(body))

    def test_root_mismatch_is_200_with_integrity_entries(self) -> None:
        status, body = self.post_json(
            {"documents": self.docs, "expected_root": "01" * 32}
        )
        self.assertEqual(status, 200)
        self.assertIs(body["ok"], False)
        self.assertEqual(body["root"], "01" * 32)
        self.assertEqual(body["errors"], {"input": 0, "integrity": 3})
        self.assertEqual(body["entries"], [{"error": "integrity"}] * 3)

    def test_malformed_bodies_are_400_and_keep_state(self) -> None:
        before_events = len(self.service.store.audit_events)
        before_state = self.state_bytes()
        good_root = self.root
        cases = [
            b"",  # empty body
            b"{not json",  # JSON error
            b"\xff\xfe{}",  # non-UTF-8
            json.dumps(["not", "an", "object"]).encode(),
            json.dumps({"documents": self.docs}).encode(),  # missing key
            json.dumps({"expected_root": good_root}).encode(),  # missing key
            json.dumps(
                {"documents": self.docs, "expected_root": good_root, "x": 1}
            ).encode(),  # extra key
            json.dumps({"expected_root": good_root, "documents": self.docs}).encode(),
            # ^ out-of-order keys
            json.dumps({"documents": [], "expected_root": good_root}).encode(),
            json.dumps({"documents": "nope", "expected_root": good_root}).encode(),
            json.dumps({"documents": self.docs, "expected_root": "A" * 64}).encode(),
            json.dumps({"documents": self.docs, "expected_root": "0" * 63}).encode(),
            json.dumps({"documents": self.docs, "expected_root": 7}).encode(),
        ]
        for raw in cases:
            status, text = self.post(raw)
            self.assertEqual(status, 400, (raw, text))
            body = json.loads(text)
            self.assertEqual(body, INPUT_BODY, (raw, text))
            self.assertEqual(list(body), ["ok", "error"])
            self.assertLess(text.index('"ok"'), text.index('"error"'))
        self.assertEqual(len(self.service.store.audit_events), before_events)
        self.assertEqual(self.state_bytes(), before_state)

    def test_concurrent_requests_are_identical(self) -> None:
        raw = json.dumps(
            {"documents": self.docs, "expected_root": self.root}
        ).encode()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.post(raw), range(16)))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(results[0][0], 200)

    def test_restart_gives_identical_result(self) -> None:
        raw = json.dumps(
            {"documents": self.docs, "expected_root": self.root}
        ).encode()
        first = self.post(raw)
        self.httpd.shutdown()
        self.httpd.server_close()
        self.start_service()
        second = self.post(raw)
        self.assertEqual(first, second)
        self.assertEqual(second[0], 200)


class AuditCliTests(AuditHttpFixture):
    def _cli(self, *argv: str, stdin: str | None = None) -> tuple[int, str]:
        if stdin is None:
            out = StringIO()
            with redirect_stdout(out):
                rc = cli_main(["--base-url", self.base, *argv])
            return rc, out.getvalue().strip()
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from ledger.cli import main; sys.exit(main())",
                "--base-url",
                self.base,
                *argv,
            ],
            input=stdin,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": REPO_ROOT},
        )
        return proc.returncode, proc.stdout.strip()

    def write_docs(self, documents: object) -> str:
        path = os.path.join(self.tmp, "docs.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(documents, fh)
        return path

    def test_file_success_exits_zero(self) -> None:
        rc, line = self._cli(
            "receipt-proofs-audit",
            self.write_docs(self.docs),
            "--expected-root",
            self.root,
        )
        self.assertEqual(rc, 0, line)
        body = json.loads(line)
        self.assertEqual(list(body), AUDIT_KEYS)
        positions = [line.index(f'"{key}"') for key in AUDIT_KEYS]
        self.assertEqual(positions, sorted(positions))
        self.assertIs(body["ok"], True)
        self.assertEqual(body["succeeded"], 3)
        self.assertEqual(body["digest"], canonical_digest(body))

    def test_stdin_ok_false_exits_one(self) -> None:
        rc, line = self._cli(
            "receipt-proofs-audit",
            "-",
            "--expected-root",
            self.root,
            stdin=json.dumps([{"ok": False}, self.docs[0], self.docs[0]]),
        )
        self.assertEqual(rc, 1, line)
        body = json.loads(line)
        self.assertEqual(list(body), AUDIT_KEYS)
        self.assertIs(body["ok"], False)
        self.assertEqual(body["errors"], {"input": 1, "integrity": 1})

    def test_server_400_is_printed_and_exits_one(self) -> None:
        rc, line = self._cli(
            "receipt-proofs-audit",
            self.write_docs([]),
            "--expected-root",
            self.root,
        )
        self.assertEqual(rc, 1, line)
        self.assertEqual(json.loads(line), INPUT_BODY)
        self.assertEqual(list(json.loads(line)), ["ok", "error"])

    def test_input_failures_do_not_contact_the_server(self) -> None:
        # A dead base URL proves no request is attempted: read, JSON and
        # argument errors all report the input body and exit 1.
        dead = "http://127.0.0.1:1"
        cases = [
            (os.path.join(self.tmp, "missing.json"), None, self.root),
            (self.write_docs(self.docs), None, "zz"),  # illegal root argument
            (self.write_docs(self.docs), None, "A" * 64),
            ("-", "not json{", self.root),
            ("-", "", self.root),
        ]
        for target, stdin, root in cases:
            argv = ["--base-url", dead, "receipt-proofs-audit", target,
                    "--expected-root", root]
            if stdin is None:
                out = StringIO()
                with redirect_stdout(out):
                    rc = cli_main(argv)
                line = out.getvalue().strip()
            else:
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "import sys; from ledger.cli import main; sys.exit(main())",
                        *argv,
                    ],
                    input=stdin,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "PYTHONPATH": REPO_ROOT},
                )
                rc, line = proc.returncode, proc.stdout.strip()
            self.assertEqual(rc, 1, (target, stdin, root, line))
            self.assertEqual(json.loads(line), INPUT_BODY, (target, stdin, root))
            self.assertEqual(list(json.loads(line)), ["ok", "error"])

    def test_missing_required_arguments_are_input_without_request(self) -> None:
        # A missing FILE positional or --expected-root must print the ordered
        # input body and exit 1 instead of argparse's usage/exit-2 path, and
        # must never contact the server (a dead base URL proves it).
        dead = "http://127.0.0.1:1"
        missing_cases = [
            [],  # neither argument
            [self.write_docs(self.docs)],  # FILE but no --expected-root
            ["--expected-root", self.root],  # root but no FILE
        ]
        for extra in missing_cases:
            argv = ["--base-url", dead, "receipt-proofs-audit", *extra]
            proc = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from ledger.cli import main; sys.exit(main())",
                    *argv,
                ],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": REPO_ROOT},
            )
            self.assertEqual(proc.returncode, 1, (extra, proc.stderr))
            line = proc.stdout.strip()
            self.assertEqual(json.loads(line), INPUT_BODY, extra)
            self.assertEqual(list(json.loads(line)), ["ok", "error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

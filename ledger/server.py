"""HTTP server exposing the ledger REST API using the Python standard library."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from .service import LedgerService

MAX_BODY_BYTES = 1 << 20  # 1 MiB cap on request bodies


def build_handler(service: LedgerService) -> type[BaseHTTPRequestHandler]:
    """Create a handler class closed over the given ledger service."""

    class LedgerHandler(BaseHTTPRequestHandler):
        server_version = "VerifiableLedger/1.0"

        # -- helpers --------------------------------------------------------

        def _send_json(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> tuple[bool, object]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return False, {"error": "invalid Content-Length"}
            if length <= 0:
                return False, {"error": "request body must be JSON"}
            if length > MAX_BODY_BYTES:
                return False, {"error": "request body too large"}
            raw = self.rfile.read(length)
            try:
                return True, json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return False, {"error": "request body must be valid JSON"}

        # -- routing --------------------------------------------------------

        def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path == "/v1/transactions":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.submit_transaction(payload)
                self._send_json(status, body)
            elif path == "/v1/blocks":
                # A body is not required; drain one if present.
                if self.headers.get("Content-Length"):
                    self._read_json()
                status, body = service.mine_block()
                self._send_json(status, body)
            else:
                self._send_json(404, {"error": "not found"})

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path.startswith("/v1/blocks/"):
                rest = unquote(path[len("/v1/blocks/") :])
                if "/proof/" in rest:
                    height, tx_id = rest.split("/proof/", 1)
                    status, body = service.get_transaction_proof(height, tx_id)
                else:
                    status, body = service.get_block(rest)
                self._send_json(status, body)
            elif path.startswith("/v1/accounts/"):
                account = unquote(path[len("/v1/accounts/") :])
                if not account:
                    self._send_json(404, {"error": "account not found"})
                    return
                status, body = service.get_account(account)
                self._send_json(status, body)
            else:
                self._send_json(404, {"error": "not found"})

    return LedgerHandler


def serve(service: LedgerService, host: str, port: int) -> ThreadingHTTPServer:
    """Create and run the HTTP server (blocks until interrupted)."""
    httpd = ThreadingHTTPServer((host, port), build_handler(service))
    httpd.serve_forever()
    return httpd

"""HTTP server exposing the ledger REST API using the Python standard library."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

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
            elif path == "/v1/forks/candidates":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.submit_fork_candidate(payload)
                self._send_json(status, body)
            elif path == "/v1/forks/sync/range":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.submit_fork_sync_range(payload)
                self._send_json(status, body)
            elif path == "/v1/forks/sync":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.submit_fork_sync(payload)
                self._send_json(status, body)
            elif path == "/v1/audit/signer/rotate":
                # POST /v1/audit/signer/rotate — rotate the Ed25519 key that
                # authenticates audit export checkpoints.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.rotate_audit_signer(payload)
                self._send_json(status, body)
            elif path == "/v1/trust/sources":
                # POST /v1/trust/sources — register a trusted source.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.register_trust_source(payload)
                self._send_json(status, body)
            elif (
                path.startswith("/v1/trust/sources/")
                and (path.endswith("/rotate") or path.endswith("/revoke"))
            ):
                # POST /v1/trust/sources/{source}/rotate | /revoke
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                remainder = path[len("/v1/trust/sources/") :]
                if remainder.endswith("/rotate"):
                    source = unquote(remainder[: -len("/rotate")])
                    status, body = service.rotate_trust_source(source, payload)
                else:
                    source = unquote(remainder[: -len("/revoke")])
                    status, body = service.revoke_trust_source(source, payload)
                self._send_json(status, body)
            elif path == "/v1/trust/allowlist":
                # POST /v1/trust/allowlist — add a keyless offline-verify entry.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.add_allowlist_entry(payload)
                self._send_json(status, body)
            elif path.startswith("/v1/forks/") and path.endswith("/adopt"):
                # POST /v1/forks/{tip_hash}/adopt — a body is not required.
                if self.headers.get("Content-Length"):
                    self._read_json()
                tip_hash = unquote(path[len("/v1/forks/") : -len("/adopt")])
                status, body = service.adopt_fork(tip_hash)
                self._send_json(status, body)
            elif path == "/v1/blocks":
                # A body is not required; drain one if present.
                if self.headers.get("Content-Length"):
                    self._read_json()
                status, body = service.mine_block()
                self._send_json(status, body)
            elif path.startswith("/v1/blocks/"):
                remainder = path[len("/v1/blocks/") :]
                # POST /v1/blocks/{height}/confirm | /v1/blocks/{height}/rollback
                if self.headers.get("Content-Length"):
                    self._read_json()
                if remainder.endswith("/confirm"):
                    height = unquote(remainder[: -len("/confirm")])
                    status, body = service.confirm_block(height)
                elif remainder.endswith("/rollback"):
                    height = unquote(remainder[: -len("/rollback")])
                    status, body = service.rollback_block(height)
                else:
                    status, body = 404, {"error": "not found"}
                self._send_json(status, body)
            else:
                self._send_json(404, {"error": "not found"})

        def do_DELETE(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path.startswith("/v1/trust/allowlist/"):
                # DELETE /v1/trust/allowlist/{source}
                source = unquote(path[len("/v1/trust/allowlist/") :])
                status, body = service.remove_allowlist_entry(source)
                self._send_json(status, body)
            else:
                self._send_json(404, {"error": "not found"})

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            path, _, query = self.path.partition("?")
            if path == "/v1/state/root":
                # GET /v1/state/root — confirmed account-state Merkle root.
                status, body = service.get_state_root()
                self._send_json(status, body)
            elif path == "/v1/trust":
                status, body = service.get_trust_document()
                self._send_json(status, body)
            elif path == "/v1/audit/events":
                # GET /v1/audit/events?source=&kind=&cursor=&limit=
                params = {
                    key: values[0]
                    for key, values in parse_qs(query, keep_blank_values=True).items()
                }
                status, body = service.list_audit_events(params)
                self._send_json(status, body)
            elif path == "/v1/audit/export":
                # GET /v1/audit/export?cursor=&limit= — hash-anchored export
                # pages for offline audit verification. Repeated query
                # parameters are rejected 400 like the other strict endpoints.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.export_audit_events(params)
                self._send_json(status, body)
            elif path == "/v1/chain/range":
                # GET /v1/chain/range?after_height=&after_hash=&limit=
                # Incremental canonical-chain page after an anchor. Repeated
                # query parameters are rejected 400 like the strict endpoints.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.get_chain_range(params)
                self._send_json(status, body)
            elif path == "/v1/chain":
                status, body = service.get_chain()
                self._send_json(status, body)
            elif path == "/v1/forks/sync/history":
                # GET /v1/forks/sync/history?source=&tip_hash=&kind=&
                # min_height=&max_height=&limit=&cursor=
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.list_fork_sync_history(params)
                self._send_json(status, body)
            elif path == "/v1/forks/sync":
                # GET /v1/forks/sync?source=&min_height=&max_height=&limit=&cursor=
                params = {
                    key: values[0]
                    for key, values in parse_qs(query, keep_blank_values=True).items()
                }
                status, body = service.list_fork_syncs(params)
                self._send_json(status, body)
            elif path == "/v1/index/transactions":
                # GET /v1/index/transactions?tx_id=&account=&height=&limit=&cursor=
                params = {
                    key: values[0]
                    for key, values in parse_qs(query, keep_blank_values=True).items()
                }
                status, body = service.list_transactions(params)
                self._send_json(status, body)
            elif path.startswith("/v1/forks/") and path.endswith("/export"):
                # GET /v1/forks/{tip_hash}/export
                tip_hash = unquote(path[len("/v1/forks/") : -len("/export")])
                status, body = service.export_fork(tip_hash)
                self._send_json(status, body)
            elif path.startswith("/v1/blocks/"):
                remainder = path[len("/v1/blocks/") :]
                if "/proof/" in remainder:
                    # GET /v1/blocks/{height}/proof/{tx_id}
                    height_raw, tx_raw = remainder.split("/proof/", 1)
                    if not height_raw or not tx_raw:
                        self._send_json(404, {"error": "not found"})
                        return
                    status, body = service.get_proof(unquote(height_raw), unquote(tx_raw))
                    self._send_json(status, body)
                elif remainder.endswith("/status"):
                    # GET /v1/blocks/{height}/status
                    height = unquote(remainder[: -len("/status")])
                    status, body = service.get_block_status(height)
                    self._send_json(status, body)
                else:
                    height = unquote(remainder)
                    status, body = service.get_block(height)
                    self._send_json(status, body)
            elif path.startswith("/v1/accounts/"):
                remainder = path[len("/v1/accounts/") :]
                if remainder.endswith("/proof"):
                    # GET /v1/accounts/{account}/proof
                    account = unquote(remainder[: -len("/proof")])
                    if not account:
                        self._send_json(404, {"error": "account not found"})
                        return
                    status, body = service.get_account_proof(account)
                    self._send_json(status, body)
                else:
                    account = unquote(remainder)
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

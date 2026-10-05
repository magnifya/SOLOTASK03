"""HTTP server exposing the ledger REST API using the Python standard library."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

from .service import LedgerService
from .store import valid_idempotency_key

MAX_BODY_BYTES = 1 << 20  # 1 MiB cap on request bodies

# Token-gated checkpoint-history routes. Every request to one of these is
# rejected before the body is read or any state is touched unless the node was
# started with --history* and the request authenticates: the configured static
# bearer token is full-power, or the active persisted credential presents a
# token hash covering the route's permission. POST /v1/history/access manages
# that credential and is reserved for the static token.
HISTORY_ROUTES = {
    ("GET", "/v1/history/trust"),
    ("POST", "/v1/history/trust"),
    ("POST", "/v1/history/export"),
    ("POST", "/v1/history/access"),
}


def build_handler(service: LedgerService) -> type[BaseHTTPRequestHandler]:
    """Create a handler class closed over the given ledger service."""

    class LedgerHandler(BaseHTTPRequestHandler):
        server_version = "VerifiableLedger/1.0"

        # -- helpers --------------------------------------------------------

        def _send_json(
            self, status: int, body: dict, sort_keys: bool = True
        ) -> None:
            data = json.dumps(
                body, ensure_ascii=False, sort_keys=sort_keys
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _history_authorized(self, method: str, path: str) -> bool:
            """Bearer-token gate for the /v1/history/* routes.

            Returns True when the request may proceed. When the feature is
            disabled the gate is open (the service answers 404); otherwise the
            request is authenticated before the body is read or any state is
            touched. The configured static token is full-power; an active
            persisted credential whose token hash matches is admitted only for
            routes covered by its permission set. A missing/malformed/unknown
            bearer is answered 401 (``unauthorized``); an authenticated
            credential lacking the route's permission is answered 403
            (``forbidden``). Both failures happen without reading the body,
            appending an audit event or touching any file.
            """
            if (method, path) not in HISTORY_ROUTES:
                return True
            if not getattr(service, "history_enabled", False):
                return True
            required = service.history_route_permission(method, path)
            provided = self.headers.get("Authorization")
            outcome = service.authorize_history(provided, required)
            if outcome == "ok":
                return True
            error = "unauthorized" if outcome == "unauthorized" else "forbidden"
            self._send_json(
                401 if error == "unauthorized" else 403,
                {"ok": False, "error": error},
                sort_keys=False,
            )
            # The body was deliberately not consumed: close the connection so
            # an unread Content-Length body cannot desync the next pipelined
            # request on a keep-alive socket.
            self.close_connection = True
            return False


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

        # -- uniform request idempotency ------------------------------------

        def _idempotency_key(self) -> "str | bool | None":
            """Resolve the Idempotency-Key header.

            Returns None when the header is absent (verbatim legacy behavior),
            False when it is malformed (repeated header or a value outside
            1..128 visible ASCII characters), otherwise the key string.
            """
            values = self.headers.get_all("Idempotency-Key")
            if not values:
                return None
            if len(values) != 1 or not valid_idempotency_key(values[0]):
                return False
            return values[0]

        def _drain_mutation_body(
            self, has_key: bool
        ) -> tuple[bool, object]:
            """Drain (and, with a key, parse) a body on a body-less mutation.

            Without an Idempotency-Key the behavior is verbatim legacy: any
            present body is drained through the same reader as before and its
            parse result is ignored. With a key the body is part of the
            request fingerprint, so it must be valid JSON (empty -> None);
            invalid JSON or an oversized body is a 400 sentinel.
            """
            if not has_key:
                if self.headers.get("Content-Length"):
                    self._read_json()
                return True, None
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return False, {"error": "invalid Content-Length"}
            if length <= 0:
                return True, None
            if length > MAX_BODY_BYTES:
                return False, {"error": "request body too large"}
            raw = self.rfile.read(length)
            try:
                return True, json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return False, {"error": "request body must be valid JSON"}

        def _send_mutation_result(
            self,
            status: int,
            body: dict,
            key: str,
            replayed: bool,
            cached_text: str | None,
            sort_keys: bool,
        ) -> None:
            """Send an idempotent mutation response.

            On the first 2xx and on every replay the cached text is the exact
            on-wire JSON (first and replay are byte-identical) and both
            Idempotency-Key and Idempotency-Replayed (false/true) are echoed.
            Any other answer (business 4xx/5xx, conflict) is sent verbatim
            with no idempotency headers, exactly like a keyless request.
            """
            if cached_text is None:
                self._send_json(status, body, sort_keys=sort_keys)
                return
            data = cached_text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Idempotency-Key", key)
            self.send_header(
                "Idempotency-Replayed", "true" if replayed else "false"
            )
            self.end_headers()
            self.wfile.write(data)

        def _mutation(
            self,
            method: str,
            key: "str | bool | None",
            action,
            body: object,
            sort_keys: bool = True,
        ) -> None:
            """Dispatch one state-changing route with uniform idempotency.

            No header: the action runs and answers exactly as before. A
            malformed header is 400 with no state touched. A valid key runs
            the request through the service idempotency gateway, which
            serializes same-key concurrency on the store lock, replays the
            cached 2xx on a matching fingerprint, answers 409 on a changed
            method/target/body, and never occupies the key on a non-2xx answer.
            """
            if key is False:
                # The body may still be unread on a body-less mutation route:
                # close the connection so it cannot desync the next pipelined
                # request on a keep-alive socket.
                self.close_connection = True
                self._send_json(400, {"error": "invalid Idempotency-Key"})
                return
            if key is None:
                status, result = action()
                self._send_json(status, result, sort_keys=sort_keys)
                return
            status, result, replayed, cached_text = service.execute_idempotent(
                method, self.path, key, body, action, sort_keys=sort_keys
            )
            self._send_mutation_result(
                status, result, key, replayed, cached_text, sort_keys
            )

        def _json_mutation(
            self, method: str, action, payload: object, sort_keys: bool = True
        ) -> None:
            """Resolve the key for a JSON-body mutation route and dispatch it."""
            key = self._idempotency_key()
            self._mutation(method, key, action, payload, sort_keys=sort_keys)

        # -- routing --------------------------------------------------------

        def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            # Bearer gate first: a 401 must be returned before the body is
            # read and without any state or file side effects.
            if not self._history_authorized("POST", path):
                return
            if path == "/v1/history/access":
                # POST /v1/history/access — rotate/revoke the persistent
                # permissioned credential. Reserved for the static full-power
                # token by the gate above; the success body has the contract
                # key order version, token_hash, permissions, status.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.manage_history_credential(payload),
                    payload,
                    sort_keys=False,
                )
            elif path == "/v1/history/trust":
                # POST /v1/history/trust — append one signer certificate; the
                # success document is the contract-ordered
                # {root, records, head} log.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.update_history_trust(payload),
                    payload,
                    sort_keys=False,
                )
            elif path == "/v1/history/export":
                # POST /v1/history/export — one signed page; the success
                # document has the contract key order
                # base, records, next, head, checkpoint, auth. The page export
                # itself is read-only but every call appends a durable
                # history_access audit event, so it is a state-changing route
                # covered by uniform idempotency.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.export_history_page(payload),
                    payload,
                    sort_keys=False,
                )
            elif path == "/v1/chain/headers/locate":
                # POST /v1/chain/headers/locate — fork location by ordered
                # block locators; the success document has the contract key
                # order anchor, headers, tip, auth (same signed header page
                # shape as GET /v1/chain/headers), so it is serialized in
                # insertion order rather than alphabetically.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.locate_header_fork(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/chain/finalities/locate":
                # POST /v1/chain/finalities/locate — fork location for the
                # signed finality history by ordered block locators; the
                # success document reuses the GET /v1/chain/finalities
                # contract key order anchor, finalities, next, head (only
                # anchor names the matched locator), so it is serialized in
                # insertion order rather than alphabetically.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.locate_finality_fork(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/chain/sync-plan":
                # POST /v1/chain/sync-plan — read-only sync precheck. The
                # body is strictly the ordered {"locators", "tip",
                # "finalized"} document (400 with the ordered {"ok",
                # "error"} input body otherwise, never touching state); no
                # shared ancestor is 409. The success document has the
                # contract key order ok, ancestor, relation, pull, error,
                # so it is serialized in insertion order rather than
                # alphabetically.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                status, body = service.build_sync_plan(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/transactions/receipt-proofs/audit":
                # POST /v1/transactions/receipt-proofs/audit — offline audit
                # summary for a batch of receipt_proof documents. The body is
                # strictly {"documents", "expected_root"} in that order (400
                # with the ordered {"ok", "error"} body otherwise, never
                # touching state). The success document has the contract key
                # order ok, root, total, succeeded, errors, entries, digest,
                # so it is serialized in insertion order rather than
                # alphabetically.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                status, body = service.audit_receipt_proofs(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/transactions/receipts":
                # POST /v1/transactions/receipts — a batch of ordinary
                # transaction receipts resolved against one persisted ledger
                # snapshot. The endpoint takes no query parameters: any
                # parameter (including a blank one) is 400 {"error":
                # "input"}; a bare trailing "?" carries none and is accepted.
                # The body is strictly {"tx_ids": [...]} with 1-200 distinct
                # 64-lowercase-hex ids; every parse/shape/type/range defect
                # is the same 400 body. A legal batch answers 200 even when
                # ids are unknown (receipt null, error "not_found"). The
                # query is read-only (no idempotency wrapper, no state
                # touched) and the success body has a contract-fixed key
                # order (items, total; each item tx_id, receipt, error), so
                # it is serialized in insertion order rather than
                # alphabetically.
                _route, _has_query, query_string = self.path.partition("?")
                if _has_query and parse_qs(
                    query_string, keep_blank_values=True
                ):
                    # The body is deliberately unread: close the connection
                    # so it cannot desync the next pipelined request.
                    self.close_connection = True
                    self._send_json(400, {"error": "input"})
                    return
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, {"error": "input"})
                    return
                status, body = service.get_transaction_receipts(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/transactions/finalized-receipts":
                # POST /v1/transactions/finalized-receipts — a batch of
                # finalized receipts sharing one signed chain snapshot. The
                # body is strictly {"tx_ids": [...]} (400), existence is
                # 404 and any unconfirmed item 409. The success document has
                # a contract-fixed key order (items, headers, finality), so
                # it is serialized in insertion order rather than
                # alphabetically.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.get_finalized_receipts(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/accounts/attested-proofs":
                # POST /v1/accounts/attested-proofs — a batch of signed
                # account-state inclusion proofs sharing one state anchor and
                # one audit signature. The body is strictly {"accounts":
                # [...], optional "height"} (400), anchor/account existence is
                # 404 and a pending tip anchors nothing (404). The success
                # document has the contract-fixed key order state, proofs,
                # auth, so it is serialized in insertion order rather than
                # alphabetically.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.get_attested_account_proofs(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/transactions/sequenced":
                # POST /v1/transactions/sequenced — a retryable, nonce-ordered
                # sequenced transfer. The first valid request returns 202 with
                # tx_id and nonce; an identical retry returns 200 with the
                # same result and no new state. Input/type/signature/balance
                # defects are 400 {"error": "input"}; a stale, skipping or
                # conflicting nonce is 409 {"error": "sequence_conflict",
                # "next_sequence": N}.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, {"error": "input"})
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_sequenced_transaction(payload),
                    payload,
                )
            elif path == "/v1/transactions/sequenced/batch":
                # POST /v1/transactions/sequenced/batch — an atomic batch of
                # nonce-ordered sequenced transfers, body strictly
                # {"transactions": [...]} (non-empty; each item carries
                # exactly the single-entry fields). The first valid batch
                # returns 202 with the contract key order items,total; an
                # exact whole-batch replay returns 200 with each item's
                # location appended. Field/signature defects and batch gaps
                # or duplicates are 400; start/reservation conflicts,
                # insufficient total balance and partial overlaps are 409;
                # every error names the first offending item index. The
                # ordered bodies are serialized in insertion order.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, {"error": "input"})
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_sequenced_batch(payload),
                    payload,
                    sort_keys=False,
                )
            elif path == "/v1/transactions":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_transaction(payload),
                    payload,
                )
            elif path.startswith("/v1/transactions/") and path.endswith(
                "/cancel"
            ):
                # POST /v1/transactions/{tx_id}/cancel — sender-signed
                # cancellation of a mempool transaction. The endpoint takes
                # no query parameters: any parameter (including a blank one)
                # is 400 {"error": "input"}; a bare trailing "?" carries
                # none and is accepted. The tx_id must be 64 lowercase hex
                # and the body exactly {"signature": "<128 lowercase hex>"};
                # every format or JSON defect is 400 {"error": "input"}.
                # Unknown ids are 404 {"error": "not_found"}, a bad sender
                # signature 403 {"error": "unauthorized"}, a packed or
                # confirmed transaction 409 {"error": "not_cancellable"} and
                # a non-top reserved sequenced nonce 409 {"error":
                # "sequence_conflict"}. The route is state-changing, so the
                # uniform Idempotency-Key rules apply.
                _route, _has_query, query_string = self.path.partition("?")
                if _has_query and parse_qs(
                    query_string, keep_blank_values=True
                ):
                    # The body is deliberately unread: close the connection
                    # so it cannot desync the next pipelined request.
                    self.close_connection = True
                    self._send_json(400, {"error": "input"})
                    return
                tx_id = unquote(
                    path[len("/v1/transactions/") : -len("/cancel")]
                )
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, {"error": "input"})
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.cancel_transaction(tx_id, payload),
                    payload,
                )
            elif path == "/v1/forks/candidates":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_fork_candidate(payload),
                    payload,
                )
            elif path == "/v1/forks/sync/range":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_fork_sync_range(payload),
                    payload,
                )
            elif path == "/v1/forks/sync/range/attested":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_fork_sync_range_attested(payload),
                    payload,
                )
            elif path == "/v1/forks/sync/attested":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_fork_sync_attested(payload),
                    payload,
                )
            elif path == "/v1/forks/sync":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.submit_fork_sync(payload),
                    payload,
                )
            elif path == "/v1/audit/signer/rotate":
                # POST /v1/audit/signer/rotate — rotate the Ed25519 key that
                # authenticates audit export checkpoints.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.rotate_audit_signer(payload),
                    payload,
                )
            elif path == "/v1/trust/sources":
                # POST /v1/trust/sources — register a trusted source.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.register_trust_source(payload),
                    payload,
                )
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
                    action = lambda: service.rotate_trust_source(source, payload)
                else:
                    source = unquote(remainder[: -len("/revoke")])
                    action = lambda: service.revoke_trust_source(source, payload)
                self._json_mutation("POST", action, payload)
            elif path == "/v1/trust/allowlist":
                # POST /v1/trust/allowlist — add a keyless offline-verify entry.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._json_mutation(
                    "POST",
                    lambda: service.add_allowlist_entry(payload),
                    payload,
                )
            elif path.startswith("/v1/forks/") and path.endswith("/adopt"):
                # POST /v1/forks/{tip_hash}/adopt — a body is not required.
                key = self._idempotency_key()
                ok_drain, body_value = self._drain_mutation_body(isinstance(key, str))
                if not ok_drain:
                    self._send_json(400, body_value)  # type: ignore[arg-type]
                    return
                tip_hash = unquote(path[len("/v1/forks/") : -len("/adopt")])
                self._mutation(
                    "POST",
                    key,
                    lambda: service.adopt_fork(tip_hash),
                    body_value,
                )
            elif path == "/v1/blocks":
                # A body is not required; drain one if present.
                key = self._idempotency_key()
                ok_drain, body_value = self._drain_mutation_body(isinstance(key, str))
                if not ok_drain:
                    self._send_json(400, body_value)  # type: ignore[arg-type]
                    return
                self._mutation(
                    "POST", key, lambda: service.mine_block(), body_value
                )
            elif path.startswith("/v1/blocks/"):
                remainder = path[len("/v1/blocks/") :]
                if remainder.endswith("/proofs"):
                    # POST /v1/blocks/{height}/proofs — batch Merkle proofs.
                    # Read-only: no ledger/admin state changes, so it is not
                    # covered by uniform idempotency. The body is
                    # {"tx_ids": [...]} and is strictly validated by the
                    # service (400), before any state is read. The success
                    # document has a contract-fixed key order (height,
                    # block_hash, merkle_root, transaction_ids, proofs), so it
                    # is serialized in insertion order rather than
                    # alphabetically.
                    height = unquote(remainder[: -len("/proofs")])
                    ok, payload = self._read_json()
                    if not ok:
                        self._send_json(400, payload)  # type: ignore[arg-type]
                        return
                    status, body = service.get_proofs(height, payload)
                    self._send_json(status, body, sort_keys=False)
                elif remainder.endswith("/multiproof"):
                    # POST /v1/blocks/{height}/multiproof — compact
                    # multi-leaf Merkle inclusion proof. Read-only like
                    # /proofs. The body is {"tx_ids": [...]} and is strictly
                    # validated by the service (400) before the height is
                    # parsed; a malformed/unknown height is 404, a pending
                    # block 409 and a missing leaf a whole-batch 404. The
                    # success document has a contract-fixed key order
                    # (height, block_hash, merkle_root, leaf_count, leaves,
                    # nodes), so it is serialized in insertion order rather
                    # than alphabetically.
                    height = unquote(remainder[: -len("/multiproof")])
                    ok, payload = self._read_json()
                    if not ok:
                        self._send_json(400, payload)  # type: ignore[arg-type]
                        return
                    status, body = service.get_multiproof(height, payload)
                    self._send_json(status, body, sort_keys=False)
                else:
                    # POST /v1/blocks/{height}/confirm | /v1/blocks/{height}/rollback
                    key = self._idempotency_key()
                    ok_drain, body_value = self._drain_mutation_body(
                        isinstance(key, str)
                    )
                    if not ok_drain:
                        self._send_json(400, body_value)  # type: ignore[arg-type]
                        return
                    if remainder.endswith("/confirm"):
                        height = unquote(remainder[: -len("/confirm")])
                        action = lambda: service.confirm_block(height)
                    elif remainder.endswith("/rollback"):
                        height = unquote(remainder[: -len("/rollback")])
                        action = lambda: service.rollback_block(height)
                    else:
                        self._send_json(404, {"error": "not found"})
                        return
                    self._mutation("POST", key, action, body_value)
            else:
                self._send_json(404, {"error": "not found"})

        def do_DELETE(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path.startswith("/v1/trust/allowlist/"):
                # DELETE /v1/trust/allowlist/{source} — a body is not part of
                # the route; without an Idempotency-Key the request behaves
                # verbatim (no body is read, as before). With a key the body
                # is drained and parsed so it can form the fingerprint.
                key = self._idempotency_key()
                if key is None:
                    source = unquote(path[len("/v1/trust/allowlist/") :])
                    status, body = service.remove_allowlist_entry(source)
                    self._send_json(status, body)
                    return
                if key is False:
                    self._send_json(400, {"error": "invalid Idempotency-Key"})
                    return
                ok_drain, body_value = self._drain_mutation_body(True)
                if not ok_drain:
                    self._send_json(400, body_value)  # type: ignore[arg-type]
                    return
                source = unquote(path[len("/v1/trust/allowlist/") :])
                self._mutation(
                    "DELETE",
                    key,
                    lambda: service.remove_allowlist_entry(source),
                    body_value,
                )
            else:
                self._send_json(404, {"error": "not found"})

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            path, _, query = self.path.partition("?")
            # Bearer gate first; a failed gate has no side effects.
            if not self._history_authorized("GET", path):
                return
            if path == "/v1/history/trust":
                # GET /v1/history/trust — the contract-ordered
                # {root, records, head} signer log.
                status, body = service.read_history_trust()
                self._send_json(status, body, sort_keys=False)
            elif path.startswith("/v1/transactions/") and path.endswith(
                "/finalized-receipt"
            ):
                # GET /v1/transactions/{tx_id}/finalized-receipt — an
                # offline-verifiable finalized receipt; a malformed or
                # unknown tx_id returns 404 and an unconfirmed transaction
                # 409. The success document has a contract-fixed key order
                # (receipt, proof, headers, finality), so it is serialized
                # in insertion order rather than alphabetically.
                tx_id = unquote(
                    path[
                        len("/v1/transactions/") : -len("/finalized-receipt")
                    ]
                )
                if not tx_id:
                    self._send_json(404, {"error": "transaction not found"})
                    return
                status, body = service.get_finalized_receipt(tx_id)
                self._send_json(status, body, sort_keys=False)
            elif path.startswith("/v1/transactions/"):
                # GET /v1/transactions/{tx_id} — a transaction receipt; a
                # malformed or unknown tx_id returns 404.
                tx_id = unquote(path[len("/v1/transactions/") :])
                if not tx_id:
                    self._send_json(404, {"error": "transaction not found"})
                    return
                status, body = service.get_transaction(tx_id)
                self._send_json(status, body)
            elif path == "/v1/trust":
                # The trust document has a contract-fixed key order
                # (genesis_hash, sources, allowlist, audit_signers,
                # source_key_history), so it is serialized in insertion order
                # rather than alphabetically.
                status, body = service.get_trust_document()
                self._send_json(status, body, sort_keys=False)
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
            elif path == "/v1/chain/headers":
                # GET /v1/chain/headers?after_height=&after_hash=&limit= —
                # one signed page of block headers strictly after an anchor;
                # the parameter rules are identical to /v1/chain/range.
                # Repeated query parameters are rejected 400 like the other
                # strict endpoints. The success document has a contract-fixed
                # key order (anchor, headers, tip, auth), so it is serialized
                # in insertion order rather than alphabetically.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.get_chain_headers(params)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/chain/finality":
                # GET /v1/chain/finality — the signed finality credential.
                # The endpoint takes no parameters: any query parameter
                # (including a blank one) is rejected 400; a bare trailing
                # "?" carries none and is accepted like the other strict
                # endpoints. The success document has a contract-fixed key
                # order (finalized, tip, auth), so it is serialized in
                # insertion order rather than alphabetically.
                if parse_qs(query, keep_blank_values=True):
                    self._send_json(
                        400, {"error": "finality endpoint takes no parameters"}
                    )
                    return
                status, body = service.get_chain_finality()
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/light-client/sync-state":
                # GET /v1/light-client/sync-state — the read-only synced
                # header/state pair audit, enabled with --sync-state. The
                # endpoint takes no parameters: any query parameter
                # (including a blank one) is rejected 400 with the ordered
                # {"ok", "error"} input body; a bare trailing "?" carries
                # none and is accepted. A node started without --sync-state
                # answers 404 (ordered {"ok", "error"} not_found); the
                # pass-through audit document has a contract-fixed key order
                # (ok, status, header, state, transaction), so it is
                # serialized in insertion order rather than alphabetically.
                if parse_qs(query, keep_blank_values=True):
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                status, body = service.get_light_client_sync_state()
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/chain/finalities":
                # GET /v1/chain/finalities?after_height=&after_hash=&limit= —
                # one signed page of finality credentials strictly after an
                # anchor; the parameter rules are identical to
                # /v1/chain/headers (repeated query parameters are rejected
                # 400 like the other strict endpoints). The success document
                # has a contract-fixed key order (anchor, finalities, next,
                # head), so it is serialized in insertion order rather than
                # alphabetically.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.get_chain_finalities(params)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/chain":
                status, body = service.get_chain()
                self._send_json(status, body)
            elif path.startswith("/v1/state/root/"):
                # GET /v1/state/root/{height} — account-state tree anchored at
                # a historical confirmed block; unknown/non-canonical/pending
                # heights are 404.
                height = unquote(path[len("/v1/state/root/") :])
                if not height:
                    self._send_json(404, {"error": "block not found"})
                    return
                status, body = service.get_state_root(height)
                self._send_json(status, body)
            elif path == "/v1/state/root":
                # GET /v1/state/root — confirmed account-state tree anchor.
                status, body = service.get_state_root()
                self._send_json(status, body)
            elif path == "/v1/forks/sync/export":
                # GET /v1/forks/sync/export?source=&request_id=&mode= —
                # export one received sync candidate. Repeated query
                # parameters are rejected 400 like the other strict
                # endpoints; the success document has a contract-fixed key
                # order, so it is serialized in insertion order.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.export_fork_sync(params)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/forks/sync/range/export":
                # GET /v1/forks/sync/range/export?source=&request_id=&mode= —
                # export one received incremental range delivery. Repeated
                # query parameters are rejected 400 like the other strict
                # endpoints; the success document has a contract-fixed key
                # order, so it is serialized in insertion order. This exact
                # match must precede the generic /v1/forks/{tip}/export
                # branch below.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.export_fork_sync_range(params)
                self._send_json(status, body, sort_keys=False)
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
                # GET /v1/forks/sync?source=&min_height=&max_height=&mode=&
                # limit=&cursor= — repeated query parameters are rejected 400
                # like the other strict endpoints.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(len(values) > 1 for values in parsed.values()):
                    self._send_json(
                        400, {"error": "query parameters must not be repeated"}
                    )
                    return
                params = {key: values[0] for key, values in parsed.items()}
                status, body = service.list_fork_syncs(params)
                self._send_json(status, body)
            elif path == "/v1/index/transactions":
                # GET /v1/index/transactions?tx_id=&account=&height=&
                # min_height=&max_height=&direction=&at_height=&at_hash=&
                # include_summary=&limit=&cursor= — the range/direction
                # parameters, the anchor pair and include_summary reject
                # repeats (even identical values) with the fixed
                # 400 {"error": "input"}; the legacy parameters keep their
                # first-value-wins behaviour.
                parsed = parse_qs(query, keep_blank_values=True)
                if any(
                    len(parsed[name]) > 1
                    for name in (
                        "min_height",
                        "max_height",
                        "direction",
                        "at_height",
                        "at_hash",
                        "include_summary",
                    )
                    if name in parsed
                ):
                    self._send_json(400, {"error": "input"})
                    return
                params = {
                    key: values[0] for key, values in parsed.items()
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
                if not remainder:
                    self._send_json(404, {"error": "account not found"})
                    return
                if remainder.endswith("/sequence"):
                    # GET /v1/accounts/{account}/sequence — next_sequence and
                    # the ascending pending/confirmed {nonce, tx_id} lists. A
                    # stranger account answers 200 with 0 and empty arrays;
                    # the endpoint takes no query parameters.
                    encoded_account = remainder[: -len("/sequence")]
                    account = unquote(encoded_account)
                    if not encoded_account or not account:
                        self._send_json(404, {"error": "account not found"})
                        return
                    if parse_qs(query, keep_blank_values=True):
                        self._send_json(
                            400, {"error": "sequence endpoint takes no parameters"}
                        )
                        return
                    status, body = service.get_account_sequence(account)
                    self._send_json(status, body)
                    return
                if remainder.endswith("/attested-absence-proof"):
                    # GET /v1/accounts/{account}/attested-absence-proof[?height=H]
                    # — a signed non-membership proof in the account-state
                    # tree. The account and query-parameter rules are
                    # identical to /absence-proof (non-empty account;
                    # height is the only optional single strict-decimal
                    # parameter; malformed/repeated/unknown 400; unknown or
                    # pending anchor and pending tip 404; existing target
                    # 409). The success document appends auth to the plain
                    # absence-proof document (account, state, lower, upper,
                    # auth), so it is serialized in insertion order.
                    encoded_account = remainder[: -len("/attested-absence-proof")]
                    account = unquote(encoded_account)
                    if not encoded_account or not account:
                        self._send_json(404, {"error": "account not found"})
                        return
                    parsed = parse_qs(query, keep_blank_values=True)
                    if any(len(values) > 1 for values in parsed.values()):
                        self._send_json(
                            400, {"error": "query parameters must not be repeated"}
                        )
                        return
                    params = {key: values[0] for key, values in parsed.items()}
                    status, body = service.get_attested_account_absence_proof(
                        account, params
                    )
                    self._send_json(status, body, sort_keys=False)
                    return
                if remainder.endswith("/attested-proof"):
                    # GET /v1/accounts/{account}/attested-proof[?height=H] —
                    # a signed account-state inclusion proof. The query
                    # parameter rules are identical to /proof (height is the
                    # only optional single parameter; malformed/unknown 400,
                    # repeated rejected here). The success document has the
                    # contract key order state, proof, auth, so it is
                    # serialized in insertion order rather than
                    # alphabetically.
                    encoded_account = remainder[: -len("/attested-proof")]
                    account = unquote(encoded_account)
                    if not encoded_account or not account:
                        self._send_json(404, {"error": "account not found"})
                        return
                    parsed = parse_qs(query, keep_blank_values=True)
                    if any(len(values) > 1 for values in parsed.values()):
                        self._send_json(
                            400, {"error": "query parameters must not be repeated"}
                        )
                        return
                    params = {key: values[0] for key, values in parsed.items()}
                    status, body = service.get_attested_account_proof(account, params)
                    self._send_json(status, body, sort_keys=False)
                    return
                elif remainder.endswith("/absence-proof"):
                    # GET /v1/accounts/{account}/absence-proof[?height=H] —
                    # a non-membership proof in the account-state tree. The
                    # account uses the same non-empty string semantics as the
                    # single-account proof; height is its only optional,
                    # single strict-decimal query parameter (malformed/
                    # repeated/unknown 400). An unknown/pending anchor or a
                    # pending chain tip is 404, a target already present in
                    # the confirmed tree is 409. The success document keeps
                    # the contract-fixed order account, state, lower, upper,
                    # so it is serialized in insertion order.
                    encoded_account = remainder[: -len("/absence-proof")]
                    account = unquote(encoded_account)
                    if not encoded_account or not account:
                        self._send_json(404, {"error": "account not found"})
                        return
                    parsed = parse_qs(query, keep_blank_values=True)
                    if any(len(values) > 1 for values in parsed.values()):
                        self._send_json(
                            400, {"error": "query parameters must not be repeated"}
                        )
                        return
                    params = {key: values[0] for key, values in parsed.items()}
                    status, body = service.get_account_absence_proof(account, params)
                    self._send_json(status, body, sort_keys=False)
                    return
                elif remainder.endswith("/proof"):
                    # GET /v1/accounts/{account}/proof[?height=H]
                    encoded_account = remainder[: -len("/proof")]
                    account = unquote(encoded_account)
                    if not encoded_account or not account:
                        self._send_json(404, {"error": "account not found"})
                        return
                    # Repeated query parameters are rejected 400 like the other
                    # strict endpoints before the service sees them.
                    parsed = parse_qs(query, keep_blank_values=True)
                    if any(len(values) > 1 for values in parsed.values()):
                        self._send_json(
                            400, {"error": "query parameters must not be repeated"}
                        )
                        return
                    params = {key: values[0] for key, values in parsed.items()}
                    status, body = service.get_account_proof(account, params)
                else:
                    account = unquote(remainder)
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

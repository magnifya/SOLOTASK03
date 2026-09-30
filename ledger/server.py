"""HTTP server exposing the ledger REST API using the Python standard library."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

from .service import LedgerService
from .store import valid_idempotency_key

MAX_BODY_BYTES = 1 << 20  # 1 MiB cap on request bodies

# Optional request header selecting unified idempotency for a state-changing
# POST/DELETE. Its value is 1..128 visible ASCII characters; absent, the
# request behaves exactly as before the feature.
IDEMPOTENCY_HEADER = "Idempotency-Key"
IDEMPOTENCY_REPLAYED_HEADER = "Idempotency-Replayed"

# The 400 body used when an Idempotency-Key itself is malformed. The contract
# pins the conflict body ({"error": "idempotency key conflict"}) but leaves
# other 400s to each route's existing error shape; the token-gated history
# routes use their ordered {"ok", "error"} input document instead.
DEFAULT_IDEMPOTENCY_400 = {"error": "invalid Idempotency-Key"}
HISTORY_IDEMPOTENCY_400 = {"ok": False, "error": "input"}

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
            self,
            status: int,
            body: dict,
            sort_keys: bool = True,
            extra_headers: list[tuple[str, str]] | None = None,
        ) -> None:
            data = json.dumps(
                body, ensure_ascii=False, sort_keys=sort_keys
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            for name, value in extra_headers or ():
                self.send_header(name, value)
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

        def _idempotency_key(self) -> str | None | bool:
            """The request's Idempotency-Key: None (absent), False (invalid)
            or the validated 1..128 visible-ASCII value."""
            raw = self.headers.get(IDEMPOTENCY_HEADER)
            if raw is None:
                return None
            if not valid_idempotency_key(raw):
                return False
            return raw

        def _valid_fingerprint_target(self) -> bool:
            """Whether the full request target can form a stable fingerprint.

            The HTTP origin-form target (path plus any query string) must be
            visible ASCII beginning with ``/``.
            """
            target = self.path
            return (
                isinstance(target, str)
                and bool(target)
                and target.startswith("/")
                and all(0x21 <= ord(char) <= 0x7E for char in target)
            )

        def _drain_optional_body(self) -> tuple[bool, object]:
            """Read an optional JSON body for a normally body-less route.

            Returns the parsed payload (or None when no body is present,
            including an explicit empty ``Content-Length: 0`` — the route
            takes no body and the idempotency fingerprint canonicalizes the
            absent body to JSON null). A present, non-empty body that is not
            valid JSON reports the route-neutral 400 only when an
            Idempotency-Key is in play (the fingerprint could not be formed);
            key-less requests keep the legacy drain-and-ignore behavior.
            """
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                return True, None
            ok, payload = self._read_json()
            if ok:
                return True, payload
            if self._idempotency_key() is None:
                # Preserve the legacy drain-and-ignore behavior exactly.
                return True, None
            return False, payload

        def _run_mutation(
            self,
            invoke,
            payload: object,
            sort_keys: bool = True,
            ordered_error: bool = False,
            prune_syncs: bool = False,
        ) -> None:
            """Dispatch one state-changing POST/DELETE, honoring an optional
            Idempotency-Key.

            Without the header the business method runs and its response is
            sent verbatim (the exact legacy behavior, CLI included). With a
            valid key the request is executed through the service's unified
            idempotency unit: the first success echoes the key with
            ``Idempotency-Replayed: false``, a same-key/same-fingerprint
            retry returns the cached status and JSON with
            ``Idempotency-Replayed: true``, and a same-key/different-fingerprint
            retry is the contract's 409 conflict body. A malformed key (or a
            target that could not fingerprint) answers 400 before the business
            method ever runs, so no state, snapshot or audit entry changes.
            """
            key = self._idempotency_key()
            if key is False or (
                key is not None and not self._valid_fingerprint_target()
            ):
                if ordered_error:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                else:
                    self._send_json(400, DEFAULT_IDEMPOTENCY_400)
                return
            if key is None:
                status, body = invoke()
                self._send_json(status, body, sort_keys=sort_keys)
                return
            status, body, replayed = service.run_idempotent(
                key,
                self.command,
                self.path,
                payload,
                invoke,
                sort_keys=sort_keys,
                prune_syncs=prune_syncs,
            )
            # The Idempotency-Key echo and the replay marker describe a
            # successful first execution or its cached replay only; a 409
            # key-conflict (or any other 4xx/5xx) is an ordinary error and
            # carries neither header.
            extra = (
                [
                    (IDEMPOTENCY_HEADER, key),
                    (IDEMPOTENCY_REPLAYED_HEADER, "true" if replayed else "false"),
                ]
                if 200 <= status < 300
                else None
            )
            self._send_json(status, body, sort_keys=sort_keys, extra_headers=extra)

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
                self._run_mutation(
                    lambda: service.manage_history_credential(payload),
                    payload,
                    sort_keys=False,
                    ordered_error=True,
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
                self._run_mutation(
                    lambda: service.update_history_trust(payload),
                    payload,
                    sort_keys=False,
                    ordered_error=True,
                )
            elif path == "/v1/history/export":
                # POST /v1/history/export — one signed page; the success
                # document has the contract key order
                # base, records, next, head, checkpoint, auth.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                self._run_mutation(
                    lambda: service.export_history_page(payload),
                    payload,
                    sort_keys=False,
                    ordered_error=True,
                )
            elif path == "/v1/chain/headers/locate":
                # READ-ONLY POST: fork location by ordered block locators; no
                # idempotency record is ever created. The success document has
                # the contract key order anchor, headers, tip, auth.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.locate_header_fork(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/chain/finalities/locate":
                # READ-ONLY POST: fork location for the signed finality
                # history; no idempotency record is ever created.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.locate_finality_fork(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/chain/sync-plan":
                # READ-ONLY POST: the sync precheck never touches state and no
                # idempotency record is created.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                status, body = service.build_sync_plan(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/transactions/receipt-proofs/audit":
                # READ-ONLY POST: the offline receipt-proof audit never touches
                # state and no idempotency record is created.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(
                        400, {"ok": False, "error": "input"}, sort_keys=False
                    )
                    return
                status, body = service.audit_receipt_proofs(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/transactions/finalized-receipts":
                # READ-ONLY POST: a batch of finalized receipts; no state
                # change and no idempotency record.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.get_finalized_receipts(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/accounts/attested-proofs":
                # READ-ONLY POST: a batch of signed account-state inclusion
                # proofs; no state change and no idempotency record.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                status, body = service.get_attested_account_proofs(payload)
                self._send_json(status, body, sort_keys=False)
            elif path == "/v1/transactions":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.submit_transaction(payload), payload
                )
            elif path == "/v1/forks/candidates":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.submit_fork_candidate(payload),
                    payload,
                    prune_syncs=True,
                )
            elif path == "/v1/forks/sync/range":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.submit_fork_sync_range(payload),
                    payload,
                    prune_syncs=True,
                )
            elif path == "/v1/forks/sync/range/attested":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.submit_fork_sync_range_attested(payload),
                    payload,
                    prune_syncs=True,
                )
            elif path == "/v1/forks/sync/attested":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.submit_fork_sync_attested(payload),
                    payload,
                    prune_syncs=True,
                )
            elif path == "/v1/forks/sync":
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.submit_fork_sync(payload),
                    payload,
                    prune_syncs=True,
                )
            elif path == "/v1/audit/signer/rotate":
                # POST /v1/audit/signer/rotate — rotate the Ed25519 key that
                # authenticates audit export checkpoints.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.rotate_audit_signer(payload), payload
                )
            elif path == "/v1/trust/sources":
                # POST /v1/trust/sources — register a trusted source.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.register_trust_source(payload), payload
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
                    self._run_mutation(
                        lambda: service.rotate_trust_source(source, payload),
                        payload,
                    )
                else:
                    source = unquote(remainder[: -len("/revoke")])
                    self._run_mutation(
                        lambda: service.revoke_trust_source(source, payload),
                        payload,
                    )
            elif path == "/v1/trust/allowlist":
                # POST /v1/trust/allowlist — add a keyless offline-verify entry.
                ok, payload = self._read_json()
                if not ok:
                    self._send_json(400, payload)  # type: ignore[arg-type]
                    return
                self._run_mutation(
                    lambda: service.add_allowlist_entry(payload), payload
                )
            elif path.startswith("/v1/forks/") and path.endswith("/adopt"):
                # POST /v1/forks/{tip_hash}/adopt — a body is not required.
                ok, extra = self._drain_optional_body()
                if not ok:
                    self._send_json(
                        400, {"error": "request body must be valid JSON"}
                    )
                    return
                tip_hash = unquote(path[len("/v1/forks/") : -len("/adopt")])
                self._run_mutation(
                    lambda: service.adopt_fork(tip_hash),
                    extra,
                    prune_syncs=True,
                )
            elif path == "/v1/blocks":
                # A body is not required; drain one if present.
                ok, extra = self._drain_optional_body()
                if not ok:
                    self._send_json(
                        400, {"error": "request body must be valid JSON"}
                    )
                    return
                self._run_mutation(service.mine_block, extra)
            elif path.startswith("/v1/blocks/"):
                remainder = path[len("/v1/blocks/") :]
                if remainder.endswith("/proofs"):
                    # READ-ONLY POST: batch Merkle proofs; no state change and
                    # no idempotency record.
                    height = unquote(remainder[: -len("/proofs")])
                    ok, payload = self._read_json()
                    if not ok:
                        self._send_json(400, payload)  # type: ignore[arg-type]
                        return
                    status, body = service.get_proofs(height, payload)
                    self._send_json(status, body, sort_keys=False)
                else:
                    # POST /v1/blocks/{height}/confirm | /v1/blocks/{height}/rollback
                    ok, extra = self._drain_optional_body()
                    if not ok:
                        self._send_json(
                            400, {"error": "request body must be valid JSON"}
                        )
                        return
                    if remainder.endswith("/confirm"):
                        height = unquote(remainder[: -len("/confirm")])
                        self._run_mutation(
                            lambda: service.confirm_block(height), extra
                        )
                    elif remainder.endswith("/rollback"):
                        height = unquote(remainder[: -len("/rollback")])
                        self._run_mutation(
                            lambda: service.rollback_block(height), extra
                        )
                    else:
                        self._send_json(404, {"error": "not found"})
            else:
                self._send_json(404, {"error": "not found"})

        def do_DELETE(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path.startswith("/v1/trust/allowlist/"):
                # DELETE /v1/trust/allowlist/{source} — a keyless entry removal.
                source = unquote(path[len("/v1/trust/allowlist/") :])
                self._run_mutation(
                    lambda: service.remove_allowlist_entry(source), None
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
                if not remainder:
                    self._send_json(404, {"error": "account not found"})
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

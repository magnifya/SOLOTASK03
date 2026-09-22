"""Command line interface: send, tx, mine, block, account, proof, state-root,
state-proof, confirm, rollback, status, candidates, chain, adopt, export,
index, sync, sync-range, sync-attested, syncs, sync-history, chain-range,
audit, audit-export, trust
(add/rotate/revoke/export/allowlist-add/allowlist-remove) and offline
verify/audit-verify subcommands.

The CLI talks to a running ledger server over HTTP and prints each response as
a single line of JSON with exactly the same field names as the HTTP API.

Signing a transaction locally is supported through ``send --signing-key``;
the key may be 32 raw hex bytes or ``@/path/to/ed25519-key.pem``. An already
produced signature can be passed instead with ``--from/--signature``. The
``candidates`` subcommand takes the candidate fork's block array (or a
``{"blocks": [...]}`` object) as a single JSON argument.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import crypto

DEFAULT_BASE_URL = os.environ.get("LEDGER_BASE_URL", "http://127.0.0.1:8080")


# -- HTTP helpers ------------------------------------------------------------


def _request(method: str, url: str, payload: dict | None) -> tuple[int, dict]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = {"error": exc.reason}
        return exc.code, body
    except (urllib.error.URLError, OSError) as exc:
        return 0, {"error": f"cannot reach ledger server: {exc}"}


def _emit(status: int, body: dict) -> int:
    print(json.dumps(body, sort_keys=True, ensure_ascii=False))
    # 2xx responses are success; anything else (incl. connection failure) is 1.
    return 0 if 200 <= status < 300 else 1


# -- signing key handling ----------------------------------------------------


def _load_signing_key(spec: str):
    """Load an Ed25519 private key from raw hex or an ``@file`` (hex or PEM)."""
    from cryptography.hazmat.primitives import serialization

    if spec.startswith("@"):
        with open(spec[1:], "rb") as fh:
            material = fh.read()
    else:
        material = spec.encode("ascii")
    stripped = material.strip()
    if stripped.startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(stripped, password=None)
    else:
        raw = bytes.fromhex(stripped.decode("ascii"))
        if len(raw) != 32:
            raise ValueError("signing key must be 32 raw bytes (64 hex chars)")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        key = Ed25519PrivateKey.from_private_bytes(raw)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key is not an Ed25519 private key")
    return key


def _public_key_hex(key) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


# -- subcommands -------------------------------------------------------------


def cmd_send(args: argparse.Namespace) -> int:
    if args.signing_key:
        try:
            key = _load_signing_key(args.signing_key)
        except (ValueError, OSError, TypeError) as exc:
            return _emit(400, {"error": f"invalid signing key: {exc}"})
        sender = _public_key_hex(key)
        message = crypto.canonical_message(sender, args.to, args.amount)
        signature = key.sign(message).hex()
    else:
        if not args.sender or not args.signature:
            return _emit(
                400,
                {"error": "provide either --signing-key or both --from and --signature"},
            )
        sender, signature = args.sender, args.signature

    payload = {
        "from": sender,
        "to": args.to,
        "amount": args.amount,
        "signature": signature,
    }
    status, body = _request("POST", f"{args.base_url}/v1/transactions", payload)
    return _emit(status, body)


def cmd_mine(args: argparse.Namespace) -> int:
    status, body = _request("POST", f"{args.base_url}/v1/blocks", {})
    return _emit(status, body)


def cmd_block(args: argparse.Namespace) -> int:
    status, body = _request(
        "GET", f"{args.base_url}/v1/blocks/{args.height}", None
    )
    return _emit(status, body)


def cmd_tx(args: argparse.Namespace) -> int:
    quoted = urllib.parse.quote(args.tx_id, safe="")
    status, body = _request(
        "GET", f"{args.base_url}/v1/transactions/{quoted}", None
    )
    return _emit(status, body)


def cmd_account(args: argparse.Namespace) -> int:
    quoted = urllib.parse.quote(args.account, safe="")
    status, body = _request(
        "GET", f"{args.base_url}/v1/accounts/{quoted}", None
    )
    return _emit(status, body)


def cmd_state_root(args: argparse.Namespace) -> int:
    if args.height is None:
        url = f"{args.base_url}/v1/state/root"
    else:
        url = f"{args.base_url}/v1/state/root/{urllib.parse.quote(args.height, safe='')}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_state_proof(args: argparse.Namespace) -> int:
    quoted = urllib.parse.quote(args.account, safe="")
    url = f"{args.base_url}/v1/accounts/{quoted}/proof"
    if args.height is not None:
        url = f"{url}?height={urllib.parse.quote(args.height, safe='')}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_proof(args: argparse.Namespace) -> int:
    status, body = _request(
        "GET", f"{args.base_url}/v1/blocks/{args.height}/proof/{args.tx_id}", None
    )
    return _emit(status, body)


def cmd_confirm(args: argparse.Namespace) -> int:
    status, body = _request(
        "POST", f"{args.base_url}/v1/blocks/{args.height}/confirm", {}
    )
    return _emit(status, body)


def cmd_rollback(args: argparse.Namespace) -> int:
    status, body = _request(
        "POST", f"{args.base_url}/v1/blocks/{args.height}/rollback", {}
    )
    return _emit(status, body)


def cmd_status(args: argparse.Namespace) -> int:
    status, body = _request(
        "GET", f"{args.base_url}/v1/blocks/{args.height}/status", None
    )
    return _emit(status, body)


def cmd_candidates(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(args.blocks_json)
    except (ValueError, TypeError) as exc:
        return _emit(400, {"error": f"invalid JSON payload: {exc}"})
    # Accept either the bare blocks array or the full {"blocks": [...]} object.
    body = {"blocks": payload} if isinstance(payload, list) else payload
    status, resp = _request(
        "POST", f"{args.base_url}/v1/forks/candidates", body
    )
    return _emit(status, resp)


def cmd_chain(args: argparse.Namespace) -> int:
    status, body = _request("GET", f"{args.base_url}/v1/chain", None)
    return _emit(status, body)


def cmd_adopt(args: argparse.Namespace) -> int:
    quoted = urllib.parse.quote(args.tip_hash, safe="")
    status, body = _request(
        "POST", f"{args.base_url}/v1/forks/{quoted}/adopt", {}
    )
    return _emit(status, body)


def cmd_export(args: argparse.Namespace) -> int:
    quoted = urllib.parse.quote(args.tip_hash, safe="")
    status, body = _request(
        "GET", f"{args.base_url}/v1/forks/{quoted}/export", None
    )
    return _emit(status, body)


def cmd_sync(args: argparse.Namespace) -> int:
    try:
        candidate = json.loads(args.candidate_json)
    except (ValueError, TypeError) as exc:
        return _emit(400, {"error": f"invalid JSON candidate: {exc}"})
    # Accept the bare blocks array or any export-format object verbatim.
    if isinstance(candidate, list):
        candidate = {"blocks": candidate}
    payload = {
        "source": args.source,
        "request_id": args.request_id,
        "expires_at": args.expires_at,
        "candidate": candidate,
    }
    status, body = _request("POST", f"{args.base_url}/v1/forks/sync", payload)
    return _emit(status, body)


def cmd_syncs(args: argparse.Namespace) -> int:
    filters = {
        "source": args.source,
        "mode": args.mode,
        "min_height": args.min_height,
        "max_height": args.max_height,
        "cursor": args.cursor,
        "limit": args.limit,
    }
    query = urllib.parse.urlencode(
        {key: value for key, value in filters.items() if value is not None}
    )
    url = f"{args.base_url}/v1/forks/sync"
    if query:
        url = f"{url}?{query}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_sync_history(args: argparse.Namespace) -> int:
    filters = {
        "source": args.source,
        "tip_hash": args.tip_hash,
        "kind": args.kind,
        "mode": args.mode,
        "min_height": args.min_height,
        "max_height": args.max_height,
        "cursor": args.cursor,
        "limit": args.limit,
    }
    query = urllib.parse.urlencode(
        {key: value for key, value in filters.items() if value is not None}
    )
    url = f"{args.base_url}/v1/forks/sync/history"
    if query:
        url = f"{url}?{query}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_chain_range(args: argparse.Namespace) -> int:
    filters = {
        "after_height": args.after_height,
        "after_hash": args.after_hash,
        "limit": args.limit,
    }
    query = urllib.parse.urlencode(
        {key: value for key, value in filters.items() if value is not None}
    )
    url = f"{args.base_url}/v1/chain/range"
    if query:
        url = f"{url}?{query}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_sync_range(args: argparse.Namespace) -> int:
    try:
        if args.range_json == "-":
            document = json.loads(sys.stdin.read())
        else:
            document = json.loads(args.range_json)
    except (ValueError, TypeError) as exc:
        return _emit(400, {"error": f"invalid JSON range document: {exc}"})
    # The range document is {"anchor", "blocks"[, "tip"]}; a GET
    # /v1/chain/range page may be piped verbatim (its extra canonical/
    # next_height fields are ignored).
    if not isinstance(document, dict):
        return _emit(400, {"error": "range document must be a JSON object"})
    anchor = document.get("anchor")
    blocks = document.get("blocks")
    if not isinstance(anchor, dict) or not isinstance(blocks, list):
        return _emit(
            400, {"error": "range document must contain an anchor object and a blocks list"}
        )
    payload = {
        "source": args.source,
        "request_id": args.request_id,
        "expires_at": args.expires_at,
        "anchor": anchor,
        "blocks": blocks,
    }
    tip = document.get("tip")
    if tip is None and blocks:
        # Derive the tip summary from the final delivered block so a plain
        # range page (which carries no tip) can be pushed verbatim.
        last = blocks[-1]
        if isinstance(last, dict):
            anchor_height = anchor.get("height")
            length = (
                anchor_height + 1 + len(blocks)
                if isinstance(anchor_height, int) and not isinstance(anchor_height, bool)
                else None
            )
            tip = {
                "tip_hash": last.get("block_hash"),
                "height": last.get("height"),
                "length": length,
                "status": last.get("status"),
            }
    if tip is not None:
        payload["tip"] = tip
    status, body = _request("POST", f"{args.base_url}/v1/forks/sync/range", payload)
    return _emit(status, body)


def cmd_sync_attested(args: argparse.Namespace) -> int:
    try:
        if args.candidate_json == "-":
            candidate = json.loads(sys.stdin.read())
        else:
            candidate = json.loads(args.candidate_json)
    except (ValueError, TypeError) as exc:
        return _emit(400, {"error": f"invalid JSON candidate: {exc}"})
    # Preserve the candidate's original form (export object, {"blocks": [...]}
    # wrapper or a bare block array): the signature is over the canonical
    # message embedding exactly that parsed value.
    if not isinstance(candidate, (dict, list)):
        return _emit(400, {"error": "candidate must be a JSON object or array"})
    document = {
        "domain": "ledger-sync-v1",
        "source": args.source,
        "request_id": args.request_id,
        "expires_at": args.expires_at,
        "candidate": candidate,
    }
    message = json.dumps(
        document, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    # Sign the raw 32-byte SHA-256 digest with the 64-lowercase-hex Ed25519
    # seed; the result is a 128-lowercase-hex signature.
    signature = crypto.sign_message(
        args.signing_key, hashlib.sha256(message).digest()
    )
    if signature is None:
        return _emit(400, {"error": "signing key must be 64 lowercase hex characters"})
    payload = {
        "source": args.source,
        "request_id": args.request_id,
        "expires_at": args.expires_at,
        "candidate": candidate,
        "signature": signature,
    }
    status, body = _request(
        "POST", f"{args.base_url}/v1/forks/sync/attested", payload
    )
    return _emit(status, body)


def cmd_index(args: argparse.Namespace) -> int:
    filters = {
        "tx_id": args.tx_id,
        "account": args.account,
        "height": args.height,
        "cursor": args.cursor,
        "limit": args.limit,
    }
    query = urllib.parse.urlencode(
        {key: value for key, value in filters.items() if value is not None}
    )
    url = f"{args.base_url}/v1/index/transactions"
    if query:
        url = f"{url}?{query}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_trust_add(args: argparse.Namespace) -> int:
    payload = {
        "source": args.source,
        "public_key": args.public_key,
        "expires_at": args.expires_at,
    }
    status, body = _request("POST", f"{args.base_url}/v1/trust/sources", payload)
    return _emit(status, body)


def cmd_trust_rotate(args: argparse.Namespace) -> int:
    source = urllib.parse.quote(args.source, safe="")
    payload = {
        "public_key": args.public_key,
        "expires_at": args.expires_at,
        "expected_version": args.expected_version,
    }
    status, body = _request(
        "POST", f"{args.base_url}/v1/trust/sources/{source}/rotate", payload
    )
    return _emit(status, body)


def cmd_trust_revoke(args: argparse.Namespace) -> int:
    source = urllib.parse.quote(args.source, safe="")
    payload = {"expected_version": args.expected_version}
    status, body = _request(
        "POST", f"{args.base_url}/v1/trust/sources/{source}/revoke", payload
    )
    return _emit(status, body)


def cmd_trust_export(args: argparse.Namespace) -> int:
    status, body = _request("GET", f"{args.base_url}/v1/trust", None)
    return _emit(status, body)


def cmd_trust_allowlist_add(args: argparse.Namespace) -> int:
    payload = {"source": args.source, "expires_at": args.expires_at}
    status, body = _request("POST", f"{args.base_url}/v1/trust/allowlist", payload)
    return _emit(status, body)


def cmd_trust_allowlist_remove(args: argparse.Namespace) -> int:
    source = urllib.parse.quote(args.source, safe="")
    status, body = _request(
        "DELETE", f"{args.base_url}/v1/trust/allowlist/{source}", None
    )
    return _emit(status, body)


def cmd_audit(args: argparse.Namespace) -> int:
    filters = {
        "source": args.source,
        "kind": args.kind,
        "cursor": args.cursor,
        "limit": args.limit,
    }
    query = urllib.parse.urlencode(
        {key: value for key, value in filters.items() if value is not None}
    )
    url = f"{args.base_url}/v1/audit/events"
    if query:
        url = f"{url}?{query}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_audit_export(args: argparse.Namespace) -> int:
    filters = {
        "cursor": args.cursor,
        "limit": args.limit,
    }
    query = urllib.parse.urlencode(
        {key: value for key, value in filters.items() if value is not None}
    )
    url = f"{args.base_url}/v1/audit/export"
    if query:
        url = f"{url}?{query}"
    status, body = _request("GET", url, None)
    return _emit(status, body)


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Offline audit export verification; no server contact is made.

    The input is one export page or a JSON array of pages (the pages of a
    full export, in order), read from ``FILE`` or standard input when the
    argument is ``-``. Prints a single JSON line:
    ``{"ok": true, "checkpoint": {...}}`` on success or
    ``{"ok": false, "error": "input"|"integrity"|"auth"}`` on failure, and
    exits 0/1 respectively.

    Without ``--trust`` only the hash chain is checked. With a trust document
    its genesis anchor and ``audit_signers`` additionally authenticate every
    page's ``checkpoint_auth`` signature and bind the pages to one another.
    """
    from .audit import verify_export

    try:
        if args.export_file == "-":
            document = json.loads(sys.stdin.read())
        else:
            with open(args.export_file, "r", encoding="utf-8") as fh:
                document = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        # Unreadable or non-JSON input is an input error.
        body = {"ok": False, "error": "input"}
    else:
        trust = None
        if args.trust is not None:
            try:
                with open(args.trust, "r", encoding="utf-8") as fh:
                    trust = json.load(fh)
            except (OSError, ValueError, UnicodeDecodeError):
                body = {"ok": False, "error": "input"}
                print(json.dumps(body, sort_keys=True, ensure_ascii=False))
                return 1
        body = verify_export(document, trust)
    print(json.dumps(body, sort_keys=True, ensure_ascii=False))
    return 0 if body.get("ok") is True else 1


def cmd_audit_signer_rotate(args: argparse.Namespace) -> int:
    status, body = _request(
        "POST",
        f"{args.base_url}/v1/audit/signer/rotate",
        {"private_key": args.private_key, "expected_version": args.expected_version},
    )
    return _emit(status, body)


def cmd_verify(args: argparse.Namespace) -> int:
    """Offline light-client verification; no server contact is made."""
    from .light_client import verify_bundle

    try:
        if args.bundle == "-":
            bundle = json.loads(sys.stdin.read())
        else:
            with open(args.bundle, "r", encoding="utf-8") as fh:
                bundle = json.load(fh)
        with open(args.trust, "r", encoding="utf-8") as fh:
            trust = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        # Unreadable or non-JSON inputs are reported in the same envelope as
        # every other verification failure.
        body = {"ok": False, "error": "input"}
    else:
        body = verify_bundle(bundle, trust)
    print(json.dumps(body, sort_keys=True, ensure_ascii=False))
    return 0 if body.get("ok") is True else 1


# -- argparse wiring ---------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ledger", description="Verifiable ledger CLI")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="ledger server URL (default: LEDGER_BASE_URL or %(default)s)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_send = sub.add_parser("send", help="submit a transaction")
    p_send.add_argument("--to", required=True, help="recipient account id")
    p_send.add_argument("--amount", required=True, type=int, help="integer amount")
    p_send.add_argument("--signing-key", help="sender Ed25519 private key: hex or @file (PEM/hex)")
    p_send.add_argument("--from", dest="sender", help="sender public key hex (with --signature)")
    p_send.add_argument("--signature", help="raw Ed25519 signature hex")
    p_send.set_defaults(func=cmd_send)

    p_mine = sub.add_parser("mine", help="pack pending transactions into a block")
    p_mine.set_defaults(func=cmd_mine)

    p_block = sub.add_parser("block", help="fetch a block by height")
    p_block.add_argument("height", help="block height (0 = genesis)")
    p_block.set_defaults(func=cmd_block)

    p_tx = sub.add_parser("tx", help="fetch a transaction receipt by tx_id")
    p_tx.add_argument("tx_id", help="transaction id (64 lowercase hex characters)")
    p_tx.set_defaults(func=cmd_tx)

    p_account = sub.add_parser("account", help="fetch an account")
    p_account.add_argument("account", help="account id (public key hex)")
    p_account.set_defaults(func=cmd_account)

    p_state_root = sub.add_parser(
        "state-root", help="fetch the confirmed account-state Merkle root"
    )
    p_state_root.add_argument(
        "--height",
        help="anchor at a historical confirmed block height (unsigned decimal, "
        "no leading zeros; omitted anchors the highest confirmed block)",
    )
    p_state_root.set_defaults(func=cmd_state_root)

    p_state_proof = sub.add_parser(
        "state-proof", help="fetch an account-state Merkle inclusion proof"
    )
    p_state_proof.add_argument("account", help="account id (public key hex)")
    p_state_proof.add_argument(
        "--height",
        help="anchor at a historical confirmed block height (unsigned decimal, "
        "no leading zeros; omitted anchors the highest confirmed block)",
    )
    p_state_proof.set_defaults(func=cmd_state_proof)

    p_proof = sub.add_parser("proof", help="fetch a Merkle inclusion proof")
    p_proof.add_argument("height", help="block height containing the transaction")
    p_proof.add_argument("tx_id", help="transaction id (64-char hex)")
    p_proof.set_defaults(func=cmd_proof)

    p_confirm = sub.add_parser("confirm", help="confirm a pending tip block")
    p_confirm.add_argument("height", help="block height to confirm")
    p_confirm.set_defaults(func=cmd_confirm)

    p_rollback = sub.add_parser("rollback", help="roll back a pending tip block")
    p_rollback.add_argument("height", help="block height to roll back")
    p_rollback.set_defaults(func=cmd_rollback)

    p_status = sub.add_parser("status", help="fetch a block's confirm status")
    p_status.add_argument("height", help="block height")
    p_status.set_defaults(func=cmd_status)

    p_candidates = sub.add_parser(
        "candidates", help="submit a candidate fork from a blocks JSON array"
    )
    p_candidates.add_argument(
        "blocks_json",
        help='fork blocks as a JSON array (or a {"blocks": [...]} object)',
    )
    p_candidates.set_defaults(func=cmd_candidates)

    p_chain = sub.add_parser("chain", help="fetch the canonical chain and candidate forks")
    p_chain.set_defaults(func=cmd_chain)

    p_adopt = sub.add_parser("adopt", help="adopt a candidate fork by tip hash")
    p_adopt.add_argument("tip_hash", help="candidate fork tip block hash")
    p_adopt.set_defaults(func=cmd_adopt)

    p_export = sub.add_parser("export", help="export a candidate fork by tip hash")
    p_export.add_argument("tip_hash", help="candidate fork tip block hash")
    p_export.set_defaults(func=cmd_export)

    p_sync = sub.add_parser(
        "sync", help="push a candidate fork received from another node"
    )
    p_sync.add_argument("--source", required=True, help="originating node identifier")
    p_sync.add_argument(
        "--request-id", required=True, help="idempotency key scoped to the source"
    )
    p_sync.add_argument(
        "--expires-at",
        required=True,
        type=int,
        help="expiry as Unix seconds; an expired delivery is rejected 410",
    )
    p_sync.add_argument(
        "candidate_json",
        help="candidate fork: an export-format object or a blocks JSON array",
    )
    p_sync.set_defaults(func=cmd_sync)

    p_syncs = sub.add_parser("syncs", help="audit-list received synced candidates")
    p_syncs.add_argument("--source", help="filter by originating node identifier")
    p_syncs.add_argument(
        "--mode",
        help="transport mode filter: plain (default when omitted), attested "
        "or all; other values are rejected by the server with 400",
    )
    p_syncs.add_argument("--min-height", help="minimum tip height (decimal)")
    p_syncs.add_argument("--max-height", help="maximum tip height (decimal)")
    p_syncs.add_argument("--cursor", help="pagination offset (decimal, default 0)")
    p_syncs.add_argument("--limit", help="page size (decimal, 1-200, default 50)")
    p_syncs.set_defaults(func=cmd_syncs)

    p_sync_history = sub.add_parser(
        "sync-history", help="audit-list the full sync lifecycle event history"
    )
    p_sync_history.add_argument("--source", help="filter by originating node identifier")
    p_sync_history.add_argument(
        "--tip-hash", help="filter by synced candidate tip hash (64 hex chars)"
    )
    p_sync_history.add_argument(
        "--kind",
        help="filter by lifecycle kind: sync_received, sync_adopted or "
        "sync_expired (invalid values are rejected by the server with 400)",
    )
    p_sync_history.add_argument(
        "--mode",
        help="transport mode filter: all (default when omitted), plain or "
        "attested; other values are rejected by the server with 400",
    )
    p_sync_history.add_argument("--min-height", help="minimum frozen tip height (decimal)")
    p_sync_history.add_argument("--max-height", help="maximum frozen tip height (decimal)")
    p_sync_history.add_argument("--cursor", help="pagination offset (decimal, default 0)")
    p_sync_history.add_argument("--limit", help="page size (decimal, 1-200, default 50)")
    p_sync_history.set_defaults(func=cmd_sync_history)

    p_chain_range = sub.add_parser(
        "chain-range",
        help="fetch the canonical blocks after an anchor (incremental range)",
    )
    p_chain_range.add_argument(
        "--after-height", required=True, help="anchor block height (decimal)"
    )
    p_chain_range.add_argument(
        "--after-hash",
        required=True,
        help="anchor block hash (64 lowercase hex characters)",
    )
    p_chain_range.add_argument(
        "--limit", help="page size (decimal, 1-500, default 100)"
    )
    p_chain_range.set_defaults(func=cmd_chain_range)

    p_sync_range = sub.add_parser(
        "sync-range",
        help="push an incremental chain range received from another node",
    )
    p_sync_range.add_argument("--source", required=True, help="originating node identifier")
    p_sync_range.add_argument(
        "--request-id", required=True, help="idempotency key scoped to the source"
    )
    p_sync_range.add_argument(
        "--expires-at",
        required=True,
        type=int,
        help="expiry as Unix seconds; an expired delivery is rejected 410",
    )
    p_sync_range.add_argument(
        "range_json",
        help='range document {"anchor","blocks"[,"tip"]}, a chain-range page, '
        "or - to read JSON from standard input",
    )
    p_sync_range.set_defaults(func=cmd_sync_range)

    p_sync_attested = sub.add_parser(
        "sync-attested",
        help="push a signature-attested candidate chain from another node",
    )
    p_sync_attested.add_argument(
        "--source", required=True, help="originating node identifier"
    )
    p_sync_attested.add_argument(
        "--request-id", required=True, help="idempotency key scoped to the source"
    )
    p_sync_attested.add_argument(
        "--expires-at",
        required=True,
        type=int,
        help="expiry as Unix seconds; an expired delivery is rejected 410",
    )
    p_sync_attested.add_argument(
        "--signing-key",
        required=True,
        help="64 lowercase hex Ed25519 seed matching the source's registered key",
    )
    p_sync_attested.add_argument(
        "candidate_json",
        help="export document, {\"blocks\":[...]} object, a bare block array, "
        "or - to read JSON from standard input",
    )
    p_sync_attested.set_defaults(func=cmd_sync_attested)

    p_index = sub.add_parser(
        "index", help="query the confirmed-chain transaction index"
    )
    p_index.add_argument("--tx-id", help="filter by transaction id (64-char hex)")
    p_index.add_argument("--account", help="filter by sender or recipient account")
    p_index.add_argument("--height", help="filter by block height (decimal)")
    p_index.add_argument("--cursor", help="pagination offset (decimal, default 0)")
    p_index.add_argument("--limit", help="page size (decimal, 1-200, default 50)")
    p_index.set_defaults(func=cmd_index)

    p_verify = sub.add_parser(
        "verify",
        help="offline-verify a proof bundle against a local trust document",
    )
    p_verify.add_argument(
        "--bundle",
        required=True,
        help="bundle JSON file path, or - to read it from standard input",
    )
    p_verify.add_argument(
        "--trust",
        required=True,
        help="local trust JSON file (genesis_hash, sources, allowlist)",
    )
    p_verify.set_defaults(func=cmd_verify)

    # Source-trust management: `trust <action> ...`.
    p_trust = sub.add_parser("trust", help="manage trusted sources and export the trust document")
    trust_sub = p_trust.add_subparsers(dest="trust_action", required=True)

    p_trust_add = trust_sub.add_parser("add", help="register a trusted source")
    p_trust_add.add_argument("--source", required=True, help="source node identifier")
    p_trust_add.add_argument("--public-key", required=True, help="Ed25519 public key (64 hex chars)")
    p_trust_add.add_argument("--expires-at", required=True, type=int, help="expiry as Unix seconds")
    p_trust_add.set_defaults(func=cmd_trust_add)

    p_trust_rotate = trust_sub.add_parser("rotate", help="rotate a trusted source's public key")
    p_trust_rotate.add_argument("--source", required=True, help="source node identifier")
    p_trust_rotate.add_argument("--public-key", required=True, help="new Ed25519 public key (64 hex chars)")
    p_trust_rotate.add_argument("--expires-at", required=True, type=int, help="new expiry as Unix seconds")
    p_trust_rotate.add_argument("--expected-version", required=True, type=int, help="current source version")
    p_trust_rotate.set_defaults(func=cmd_trust_rotate)

    p_trust_revoke = trust_sub.add_parser("revoke", help="revoke a trusted source")
    p_trust_revoke.add_argument("--source", required=True, help="source node identifier")
    p_trust_revoke.add_argument("--expected-version", required=True, type=int, help="current source version")
    p_trust_revoke.set_defaults(func=cmd_trust_revoke)

    p_trust_export = trust_sub.add_parser("export", help="export the offline verify trust document")
    p_trust_export.set_defaults(func=cmd_trust_export)

    p_trust_allowlist_add = trust_sub.add_parser(
        "allowlist-add", help="add a keyless allowlist entry for offline verify"
    )
    p_trust_allowlist_add.add_argument("--source", required=True, help="source node identifier")
    p_trust_allowlist_add.add_argument(
        "--expires-at", required=True, type=int, help="expiry as Unix seconds"
    )
    p_trust_allowlist_add.set_defaults(func=cmd_trust_allowlist_add)

    p_trust_allowlist_remove = trust_sub.add_parser(
        "allowlist-remove", help="remove a keyless allowlist entry"
    )
    p_trust_allowlist_remove.add_argument("--source", required=True, help="source node identifier")
    p_trust_allowlist_remove.set_defaults(func=cmd_trust_allowlist_remove)

    p_audit = sub.add_parser("audit", help="query the append-only audit event log")
    p_audit.add_argument("--source", help="filter by source identifier")
    p_audit.add_argument("--kind", help="filter by event kind")
    p_audit.add_argument("--cursor", help="pagination offset (decimal, default 0)")
    p_audit.add_argument("--limit", help="page size (decimal, 1-200, default 50)")
    p_audit.set_defaults(func=cmd_audit)

    p_audit_export = sub.add_parser(
        "audit-export",
        help="export a hash-anchored audit page for offline verification",
    )
    p_audit_export.add_argument(
        "--cursor", help="pagination offset (decimal, default 0)"
    )
    p_audit_export.add_argument(
        "--limit", help="page size (decimal, 1-200, default 50)"
    )
    p_audit_export.set_defaults(func=cmd_audit_export)

    p_audit_verify = sub.add_parser(
        "audit-verify",
        help="offline-verify an audit export file (a page or an ordered "
        "list of pages); - reads standard input",
    )
    p_audit_verify.add_argument(
        "export_file",
        metavar="FILE|-",
        help="audit export JSON file, or - to read the document from stdin",
    )
    p_audit_verify.add_argument(
        "--trust",
        help="optional local trust JSON file (genesis_hash + audit_signers); "
        "when given, checkpoint_auth signatures are additionally verified",
    )
    p_audit_verify.set_defaults(func=cmd_audit_verify)

    p_audit_signer = sub.add_parser(
        "audit-signer-rotate",
        help="rotate the Ed25519 key authenticating audit export checkpoints",
    )
    p_audit_signer.add_argument(
        "--private-key",
        required=True,
        help="new Ed25519 private seed (64 lowercase hex characters)",
    )
    p_audit_signer.add_argument(
        "--expected-version",
        required=True,
        type=int,
        help="current signer version (conflict 409 if stale)",
    )
    p_audit_signer.set_defaults(func=cmd_audit_signer_rotate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

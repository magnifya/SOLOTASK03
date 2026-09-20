"""Command line interface: send, mine, block, account, proof, confirm,
rollback, status, candidates, chain, adopt, export, index, sync, syncs and
verify subcommands.

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


def cmd_account(args: argparse.Namespace) -> int:
    quoted = urllib.parse.quote(args.account, safe="")
    status, body = _request(
        "GET", f"{args.base_url}/v1/accounts/{quoted}", None
    )
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


def cmd_verify(args: argparse.Namespace) -> int:
    """Offline-verify a light-client bundle; no server is contacted.

    The bundle is read from ``--bundle PATH`` (``-`` reads standard input) and
    the trust document from ``--trust PATH``. The result is one line of JSON:
    ``{"ok": true, ...}`` exits 0, every failure
    (``{"ok": false, "error": ...}``) exits 1. Unreadable or non-JSON inputs
    are reported as the ``input`` error category.
    """
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
        result = {"ok": False, "error": "input"}
    else:
        result = verify_bundle(bundle, trust)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0 if result.get("ok") else 1


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

    p_account = sub.add_parser("account", help="fetch an account")
    p_account.add_argument("account", help="account id (public key hex)")
    p_account.set_defaults(func=cmd_account)

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
    p_syncs.add_argument("--min-height", help="minimum tip height (decimal)")
    p_syncs.add_argument("--max-height", help="maximum tip height (decimal)")
    p_syncs.add_argument("--cursor", help="pagination offset (decimal, default 0)")
    p_syncs.add_argument("--limit", help="page size (decimal, 1-200, default 50)")
    p_syncs.set_defaults(func=cmd_syncs)

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
        "verify", help="offline-verify a light-client bundle (no server needed)"
    )
    p_verify.add_argument(
        "--bundle", required=True, help="bundle JSON file, or '-' to read stdin"
    )
    p_verify.add_argument("--trust", required=True, help="trust-document JSON file")
    p_verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

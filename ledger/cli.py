"""Command line interface: send, mine, block, account, proof, confirm,
rollback and status subcommands.

The CLI talks to a running ledger server over HTTP and prints each response as
a single line of JSON with exactly the same field names as the HTTP API.

Signing a transaction locally is supported through ``send --signing-key``;
the key may be 32 raw hex bytes or ``@/path/to/ed25519-key.pem``. An already
produced signature can be passed instead with ``--from/--signature``.
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

    p_confirm = sub.add_parser("confirm", help="confirm the pending chain-tip block")
    p_confirm.add_argument("height", help="block height to confirm")
    p_confirm.set_defaults(func=cmd_confirm)

    p_rollback = sub.add_parser("rollback", help="roll back the pending chain-tip block")
    p_rollback.add_argument("height", help="block height to roll back")
    p_rollback.set_defaults(func=cmd_rollback)

    p_status = sub.add_parser("status", help="fetch a block's confirmation status")
    p_status.add_argument("height", help="block height (0 = genesis)")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

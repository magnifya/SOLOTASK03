"""Entry point: ``python -m ledger`` runs the HTTP server."""
from __future__ import annotations

import argparse
import os
import sys

from .server import serve
from .service import DEFAULT_INITIAL_BALANCE, LedgerService
from .store import LedgerStore, StateRecoveryError

DEFAULT_STATE_PATH = os.environ.get("LEDGER_STATE", "ledger_state.json")
DEFAULT_HOST = os.environ.get("LEDGER_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("LEDGER_PORT", "8080"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ledger", description="Verifiable ledger server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind host (default: %(default)s)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port (default: %(default)s)")
    parser.add_argument("--state", default=DEFAULT_STATE_PATH, help="state JSON file (default: %(default)s)")
    parser.add_argument(
        "--initial-balance",
        type=int,
        default=int(os.environ.get("LEDGER_INITIAL_BALANCE", str(DEFAULT_INITIAL_BALANCE))),
        help="endowment per identity (default: %(default)s)",
    )
    parser.add_argument(
        "--history",
        default=None,
        help="advance checkpoint path whose history the /v1/history routes "
        "expose; requires --history-trust and --history-token",
    )
    parser.add_argument(
        "--history-trust",
        default=None,
        dest="history_trust",
        help="durable checkpoint-history signer log path; requires --history "
        "and --history-token",
    )
    parser.add_argument(
        "--history-token",
        default=None,
        dest="history_token",
        help="bearer token guarding /v1/history; requires --history and "
        "--history-trust (must be non-empty)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # The three history options are all-or-nothing: a partial set never names
    # a usable configuration, so the process exits 2 before opening any file.
    history_options = (args.history, args.history_trust, args.history_token)
    given = [value is not None for value in history_options]
    if any(given):
        # A partial set never names a usable configuration, and an explicit
        # empty value is as good as missing; the process exits 2 before any
        # file is opened.
        if not all(given) or not all(history_options):
            print(
                "ledger: --history, --history-trust and --history-token must "
                "all be given together with non-empty values",
                file=sys.stderr,
            )
            return 2
    history_path, history_trust_path, history_token = history_options
    try:
        store = LedgerStore(
            args.state,
            history_path=history_path,
            history_trust_path=history_trust_path,
        )
    except StateRecoveryError as exc:
        # Never silently start a fresh chain on corrupt/unrecoverable state:
        # report the failing location and reason, then exit non-zero.
        print(f"ledger state recovery failed: {exc}", file=sys.stderr)
        return 2
    service = LedgerService(
        store,
        initial_balance=args.initial_balance,
        history_token=history_token,
    )
    print(f"ledger listening on http://{args.host}:{args.port} (state: {args.state})")
    try:
        serve(service, args.host, args.port)
    except KeyboardInterrupt:
        print("ledger shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

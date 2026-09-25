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
        help="checkpoint-history file exposed at /v1/history/* (requires "
        "--history-trust and --history-token)",
    )
    parser.add_argument(
        "--history-trust",
        default=None,
        help="durable signer log file for /v1/history/trust (requires "
        "--history and --history-token)",
    )
    parser.add_argument(
        "--history-token",
        default=None,
        help="bearer token required by /v1/history/* (requires --history "
        "and --history-trust)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # The managed checkpoint-history endpoints are either fully configured
    # (all three options present and non-empty) or absent; a partial set is a
    # configuration error reported with exit code 2 before any state loads.
    history_options = (args.history, args.history_trust, args.history_token)
    given = [value is not None for value in history_options]
    if any(given):
        if not all(given) or not all(value for value in history_options):
            print(
                "ledger: --history, --history-trust and --history-token must "
                "all be given together with non-empty values (or all omitted)",
                file=sys.stderr,
            )
            return 2
        history_config = (args.history, args.history_trust, args.history_token)
    else:
        history_config = None
    try:
        store = LedgerStore(
            args.state,
            history_path=history_config[0] if history_config else None,
            history_trust_path=history_config[1] if history_config else None,
        )
    except StateRecoveryError as exc:
        # Never silently start a fresh chain on corrupt/unrecoverable state:
        # report the failing location and reason, then exit non-zero.
        print(f"ledger state recovery failed: {exc}", file=sys.stderr)
        return 2
    service = LedgerService(
        store,
        initial_balance=args.initial_balance,
        history_config=history_config,
    )
    print(f"ledger listening on http://{args.host}:{args.port} (state: {args.state})")
    try:
        serve(service, args.host, args.port)
    except KeyboardInterrupt:
        print("ledger shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Entry point: ``python -m ledger`` runs the HTTP server."""
from __future__ import annotations

import argparse
import os

from .server import serve
from .service import DEFAULT_INITIAL_BALANCE, LedgerService
from .store import LedgerStore

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
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    store = LedgerStore(args.state)
    service = LedgerService(store, initial_balance=args.initial_balance)
    print(f"ledger listening on http://{args.host}:{args.port} (state: {args.state})")
    try:
        serve(service, args.host, args.port)
    except KeyboardInterrupt:
        print("ledger shutting down")


if __name__ == "__main__":
    main()

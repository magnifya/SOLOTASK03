"""End-to-end test for the Merkle proof endpoint and CLI proof subcommand.

Spins up the real HTTP server on an ephemeral port and drives it through the
CLI exactly as a user would. Run: python3 tests/proof_test.py
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http.server import ThreadingHTTPServer

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def keypair():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def run_cli(*argv: str) -> tuple[int, dict]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_main(list(argv))
    line = buf.getvalue().strip()
    assert "\n" not in line, "CLI must print exactly one line"
    return code, json.loads(line)


def main() -> None:
    tmp = tempfile.mkdtemp()
    svc = LedgerService(LedgerStore(os.path.join(tmp, "state.json")), initial_balance=1000)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(svc))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    ka, A = keypair()
    kb, B = keypair()
    kc, C = keypair()

    def send(key, sender, to, amount):
        code, body = run_cli(
            "--base-url", base, "send", "--to", to, "--amount", str(amount),
            "--signing-key", key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ).hex(),
        )
        assert code == 0, body
        return body["tx_id"]

    # -- zero transactions: genesis block has no txs -------------------------
    code, body = run_cli("--base-url", base, "proof", "0", "a" * 64)
    assert code == 1 and "error" in body, body

    # -- single transaction block --------------------------------------------
    t1 = send(ka, A, B, 100)
    code, blk = run_cli("--base-url", base, "mine")
    assert code == 0 and blk["height"] == 1, blk

    code, proof = run_cli("--base-url", base, "proof", "1", t1)
    assert code == 0, proof
    assert proof["height"] == 1 and proof["tx_id"] == t1 and proof["index"] == 0
    assert proof["siblings"] == []
    assert proof["merkle_root"] == blk["merkle_root"]
    assert proof["block_hash"] == blk["block_hash"]
    assert crypto.verify_merkle_proof(
        proof["tx_id"], proof["siblings"], proof["merkle_root"],
        proof["block_hash"], proof["block_hash"],
    )
    # wrong expected block hash -> False
    assert not crypto.verify_merkle_proof(
        proof["tx_id"], proof["siblings"], proof["merkle_root"],
        proof["block_hash"], "0" * 64,
    )

    # -- multi transaction block (odd count exercises self-pairing) ----------
    t2 = send(kb, B, C, 50)
    t3 = send(kc, C, A, 25)
    t4 = send(ka, A, C, 10)
    code, blk2 = run_cli("--base-url", base, "mine")
    assert code == 0 and blk2["height"] == 2, blk2
    ordered = sorted([t2, t3, t4])

    for i, tx_id in enumerate(ordered):
        code, proof = run_cli("--base-url", base, "proof", "2", tx_id)
        assert code == 0, proof
        assert proof["index"] == i and proof["tx_id"] == tx_id
        assert len(proof["siblings"]) == 2, proof  # 3 leaves -> 2 levels
        for sib in proof["siblings"]:
            assert sib["direction"] in ("left", "right")
            assert len(sib["hash"]) == 64
            assert sib["hash"] == sib["hash"].lower()
        assert crypto.verify_merkle_proof(
            tx_id, proof["siblings"], blk2["merkle_root"],
            blk2["block_hash"], blk2["block_hash"],
        )
        # tampered sibling hash breaks verification
        bad = [dict(s) for s in proof["siblings"]]
        bad[0]["hash"] = ("0" if bad[0]["hash"][0] != "0" else "1") + bad[0]["hash"][1:]
        assert not crypto.verify_merkle_proof(
            tx_id, bad, blk2["merkle_root"], blk2["block_hash"], blk2["block_hash"]
        )

    # -- errors: unknown tx, wrong height, bad tx_id, bad height -------------
    assert run_cli("--base-url", base, "proof", "2", t1)[0] == 1  # t1 is in block 1
    assert run_cli("--base-url", base, "proof", "99", t1)[0] == 1
    assert run_cli("--base-url", base, "proof", "1", "not-a-tx-id")[0] == 1
    assert run_cli("--base-url", base, "proof", "abc", t1)[0] == 1
    assert run_cli("--base-url", base, "proof", "1", "z" * 64)[0] == 1

    # -- regression: block and account endpoints unchanged -------------------
    code, b1 = run_cli("--base-url", base, "block", "1")
    assert code == 0 and b1["transaction_ids"] == [t1], b1
    code, b2 = run_cli("--base-url", base, "block", "2")
    assert code == 0 and b2["transaction_ids"] == ordered, b2
    assert b2["prev_hash"] == b1["block_hash"]

    code, acc = run_cli("--base-url", base, "account", A)
    assert code == 0 and acc["balance"] == 1000 - 100 - 10 + 25, acc
    code, acc = run_cli("--base-url", base, "account", C)
    assert code == 0 and acc["balance"] == 1000 + 50 - 25 + 10, acc
    assert run_cli("--base-url", base, "account", "nobody")[0] == 1

    httpd.shutdown()
    print("proof test OK")


if __name__ == "__main__":
    main()

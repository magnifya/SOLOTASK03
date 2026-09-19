"""Smoke test exercising the ledger service in-process (no network needed).

Run: python3 tests/smoke_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.service import LedgerService
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def main() -> None:
    tmp = tempfile.mkdtemp()
    state_a = os.path.join(tmp, "a.json")
    state_b = os.path.join(tmp, "b.json")

    ka, A = keypair()
    kb, B = keypair()

    svc = LedgerService(LedgerStore(state_a), initial_balance=1000)

    # genesis
    status, genesis = svc.get_block(0)
    assert status == 200 and genesis["height"] == 0
    assert genesis["prev_hash"] == "0" * 64 and genesis["transaction_ids"] == []
    assert genesis["status"] == "confirmed"

    # invalid: missing field, non-positive amount, wrong signer
    assert svc.submit_transaction({"from": A})[0] == 400
    assert svc.submit_transaction(make_tx(ka, A, B, 0))[0] == 400
    assert svc.submit_transaction(make_tx(kb, A, B, 10))[0] == 400

    # two valid txs, pending overspend is rejected
    _, t1 = svc.submit_transaction(make_tx(ka, A, B, 100))
    _, t2 = svc.submit_transaction(make_tx(ka, A, B, 900))
    assert svc.submit_transaction(make_tx(ka, A, B, 1))[0] == 400

    # mining packs in ascending tx_id order; the new block is pending
    status, block = svc.mine_block()
    assert status == 201 and block["height"] == 1 and block["status"] == "pending"
    assert svc.mine_block()[0] == 409  # tip is pending
    _, stored = svc.get_block(1)
    assert stored["transaction_ids"] == sorted([t1["tx_id"], t2["tx_id"]])
    assert stored["prev_hash"] == genesis["block_hash"]
    assert stored["status"] == "pending"

    # confirm the tip, then mining with an empty mempool is a 409
    status, confirmed = svc.confirm_block(1)
    assert status == 200 and confirmed["status"] == "confirmed"
    assert svc.mine_block()[0] == 409

    # balances
    _, acc_a = svc.get_account(A)
    _, acc_b = svc.get_account(B)
    assert acc_a["balance"] == 0 and acc_b["balance"] == 2000
    assert svc.get_account("nobody")[0] == 404

    # determinism: same transactions submitted in reverse order on a fresh
    # store must produce the identical merkle root and block hash
    svc2 = LedgerService(LedgerStore(state_b), initial_balance=1000)
    svc2.submit_transaction(make_tx(ka, A, B, 900))
    svc2.submit_transaction(make_tx(ka, A, B, 100))
    _, block2 = svc2.mine_block()
    assert block2["merkle_root"] == block["merkle_root"]
    assert block2["block_hash"] == block["block_hash"]

    # persistence survives reopening
    svc3 = LedgerService(LedgerStore(state_a), initial_balance=1000)
    _, reopened = svc3.get_block(1)
    assert reopened["block_hash"] == block["block_hash"]
    assert reopened["status"] == "confirmed"

    print("smoke test OK")


if __name__ == "__main__":
    main()

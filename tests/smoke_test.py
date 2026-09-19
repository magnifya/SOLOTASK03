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

    # genesis: always confirmed
    status, genesis = svc.get_block(0)
    assert status == 200 and genesis["height"] == 0
    assert genesis["prev_hash"] == "0" * 64 and genesis["transaction_ids"] == []
    assert genesis["status"] == "confirmed"
    assert svc.get_block_status(0) == (200, {"height": 0, "status": "confirmed"})

    # invalid: missing field, non-positive amount, wrong signer
    assert svc.submit_transaction({"from": A})[0] == 400
    assert svc.submit_transaction(make_tx(ka, A, B, 0))[0] == 400
    assert svc.submit_transaction(make_tx(kb, A, B, 10))[0] == 400

    # two valid txs, pending overspend is rejected
    _, t1 = svc.submit_transaction(make_tx(ka, A, B, 100))
    _, t2 = svc.submit_transaction(make_tx(ka, A, B, 900))
    assert svc.submit_transaction(make_tx(ka, A, B, 1))[0] == 400

    # mining packs in ascending tx_id order and yields a *pending* block
    status, block = svc.mine_block()
    assert status == 201 and block["height"] == 1 and block["status"] == "pending"
    # cannot mine again while the tip is pending (even with an empty mempool)
    assert svc.mine_block()[0] == 409
    _, stored = svc.get_block(1)
    assert stored["status"] == "pending"
    assert stored["transaction_ids"] == sorted([t1["tx_id"], t2["tx_id"]])
    assert stored["prev_hash"] == genesis["block_hash"]

    # pending block exposes no Merkle proof; accounts ignore it entirely
    assert svc.get_proof(1, t1["tx_id"])[0] == 409
    assert svc.get_block_status(1) == (200, {"height": 1, "status": "pending"})
    assert svc.get_account(A)[0] == 404
    assert svc.get_account(B)[0] == 404

    # only the pending tip with a confirmed predecessor can be confirmed
    assert svc.confirm_block(99)[0] == 409
    status, confirmed = svc.confirm_block(1)
    assert status == 200 and confirmed == {"height": 1, "status": "confirmed"}
    # repeated confirmation is idempotent
    assert svc.confirm_block(1) == (200, {"height": 1, "status": "confirmed"})

    # balances after confirmation
    _, acc_a = svc.get_account(A)
    _, acc_b = svc.get_account(B)
    assert acc_a["balance"] == 0 and acc_b["balance"] == 2000
    assert svc.get_account("nobody")[0] == 404
    # proof now available
    assert svc.get_proof(1, t1["tx_id"])[0] == 200

    # pending debits reduce the reported balance, pending credits do not
    t3 = make_tx(kb, B, A, 50)
    _, t3_body = svc.submit_transaction(t3)
    _, pending2 = svc.mine_block()
    assert pending2["height"] == 2 and pending2["status"] == "pending"
    _, acc_b = svc.get_account(B)
    _, acc_a = svc.get_account(A)
    assert acc_b["balance"] == 1950  # 2000 confirmed - 50 pending outgoing
    assert acc_a["balance"] == 0     # pending incoming is not counted
    # a duplicate submission while packed is rejected, and proof stays 409
    assert svc.submit_transaction(t3)[0] == 409
    assert svc.get_proof(2, t3_body["tx_id"])[0] == 409

    # roll back the pending tip: block disappears and txs return to pending
    status, rolled = svc.rollback_block(2)
    assert status == 200 and rolled == {"height": 2, "status": "rolled_back"}
    assert svc.get_block(2)[0] == 404
    assert svc.get_block_status(2)[0] == 404
    # unknown / repeated rollback -> 404; confirmed / non-tip -> 409
    assert svc.rollback_block(2)[0] == 404
    assert svc.rollback_block(99)[0] == 404
    assert svc.rollback_block(1)[0] == 409
    # restored transaction is pending again and cannot be resubmitted
    assert svc.submit_transaction(t3)[0] == 409

    # re-mining the restored set reproduces the identical hashes
    _, remined = svc.mine_block()
    assert remined["height"] == 2
    assert remined["block_hash"] == pending2["block_hash"]
    assert remined["merkle_root"] == pending2["merkle_root"]
    assert svc.confirm_block(2) == (200, {"height": 2, "status": "confirmed"})
    _, proof3 = svc.get_proof(2, t3_body["tx_id"])
    assert proof3["block_hash"] == pending2["block_hash"]
    _, acc_b = svc.get_account(B)
    _, acc_a = svc.get_account(A)
    assert acc_b["balance"] == 1950 and acc_a["balance"] == 50

    # determinism: same transactions submitted in reverse order on a fresh
    # store must produce the identical merkle root and block hash
    svc2 = LedgerService(LedgerStore(state_b), initial_balance=1000)
    svc2.submit_transaction(make_tx(ka, A, B, 900))
    svc2.submit_transaction(make_tx(ka, A, B, 100))
    _, block2 = svc2.mine_block()
    assert block2["status"] == "pending"
    assert block2["merkle_root"] == block["merkle_root"]
    assert block2["block_hash"] == block["block_hash"]
    assert svc2.confirm_block(1)[0] == 200

    # persistence survives reopening; statuses are restored with the chain
    svc3 = LedgerService(LedgerStore(state_a), initial_balance=1000)
    _, reopened = svc3.get_block(1)
    assert reopened["block_hash"] == block["block_hash"]
    assert reopened["status"] == "confirmed"
    assert svc3.get_block_status(2) == (200, {"height": 2, "status": "confirmed"})
    # rebuilt index: a confirmed tx resubmitted after restart is still rejected
    assert svc3.submit_transaction(make_tx(ka, A, B, 100))[0] == 409

    print("smoke test OK")


if __name__ == "__main__":
    main()

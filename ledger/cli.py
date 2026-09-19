"""命令行入口：send / mine / block / account，与 HTTP 接口一一对应。

输出始终是单行 JSON，字段与 HTTP 响应一致。
另提供 keygen 辅助子命令生成 Ed25519 密钥（非接口要求，仅为方便签名）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import List, Optional

from .crypto import generate_keypair, sign
from .models import canonical_message

DEFAULT_SERVER = "http://127.0.0.1:8000"


def _server_url(args: argparse.Namespace) -> str:
    return (args.server or os.environ.get("LEDGER_SERVER") or DEFAULT_SERVER).rstrip("/")


def _request(method: str, url: str, payload: Optional[dict] = None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read().decode("utf-8"))
        except ValueError:
            return error.code, {"error": "请求失败"}
    except urllib.error.URLError as error:
        return None, {"error": f"无法连接服务: {error.reason}"}


def _emit(status, body) -> int:
    print(json.dumps(body, ensure_ascii=False, sort_keys=True))
    return 0 if status is not None and 200 <= status < 300 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ledger-cli", description="可验证账本命令行")
    parser.add_argument("--server", help="服务地址，默认环境变量 LEDGER_SERVER 或 " + DEFAULT_SERVER)
    sub = parser.add_subparsers(dest="command", required=True)

    p_send = sub.add_parser("send", help="提交交易（对应 POST /v1/transactions）")
    p_send.add_argument("--from", dest="sender", required=True)
    p_send.add_argument("--to", dest="recipient", required=True)
    p_send.add_argument("--amount", type=int, required=True)
    sig = p_send.add_mutually_exclusive_group(required=True)
    sig.add_argument("--signature", help="十六进制签名")
    sig.add_argument("--private-key", help="十六进制 Ed25519 私钥，提供后自动签名")

    sub.add_parser("mine", help="打包区块（对应 POST /v1/blocks）")

    p_block = sub.add_parser("block", help="查询区块（对应 GET /v1/blocks/{height}）")
    p_block.add_argument("height", type=int)

    p_account = sub.add_parser("account", help="查询账户（对应 GET /v1/accounts/{account}）")
    p_account.add_argument("account")

    sub.add_parser("keygen", help="生成 Ed25519 密钥对（辅助工具）")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    base = _server_url(args)

    if args.command == "keygen":
        priv, pub = generate_keypair()
        print(json.dumps({"private_key": priv, "public_key": pub}, sort_keys=True))
        return 0

    if args.command == "send":
        if args.private_key:
            message = canonical_message(args.sender, args.recipient, args.amount)
            signature = sign(args.private_key, message)
        else:
            signature = args.signature
        payload = {
            "from": args.sender,
            "to": args.recipient,
            "amount": args.amount,
            "signature": signature,
        }
        return _emit(*_request("POST", f"{base}/v1/transactions", payload))

    if args.command == "mine":
        return _emit(*_request("POST", f"{base}/v1/blocks"))

    if args.command == "block":
        return _emit(*_request("GET", f"{base}/v1/blocks/{args.height}"))

    if args.command == "account":
        return _emit(*_request("GET", f"{base}/v1/accounts/{args.account}"))

    return 1


if __name__ == "__main__":
    sys.exit(main())

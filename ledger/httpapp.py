"""HTTP 服务：标准库 http.server 暴露账本接口。

路由：
- POST /v1/transactions
- POST /v1/blocks
- GET  /v1/blocks/{height}
- GET  /v1/accounts/{account}
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import unquote

from .service import LedgerService
from .store import Store


def create_handler(service: LedgerService):
    class LedgerHandler(BaseHTTPRequestHandler):
        server_version = "VerifiableLedger/1.0"

        def _send_json(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json_body(self) -> Optional[dict]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                return json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return None

        def do_POST(self) -> None:
            if self.path == "/v1/transactions":
                payload = self._read_json_body()
                if payload is None:
                    self._send_json(400, {"error": "请求体不是合法 JSON"})
                    return
                status, body = service.submit_transaction(payload)
                self._send_json(status, body)
            elif self.path == "/v1/blocks":
                status, body = service.mine_block()
                self._send_json(status, body)
            else:
                self._send_json(404, {"error": "未知路径"})

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path.startswith("/v1/blocks/"):
                token = unquote(path[len("/v1/blocks/"):])
                if not token.isdigit():
                    self._send_json(404, {"error": "区块不存在"})
                    return
                status, body = service.get_block(int(token))
                self._send_json(status, body)
            elif path.startswith("/v1/accounts/"):
                account = unquote(path[len("/v1/accounts/"):])
                if not account:
                    self._send_json(404, {"error": "账户不存在"})
                    return
                status, body = service.get_account(account)
                self._send_json(status, body)
            else:
                self._send_json(404, {"error": "未知路径"})

        def log_message(self, fmt, *args) -> None:
            pass

    return LedgerHandler


def serve(service: LedgerService, host: str = "127.0.0.1", port: int = 8000) -> None:
    handler = create_handler(service)
    httpd = ThreadingHTTPServer((host, port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ledger-server", description="可验证账本 HTTP 服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data-dir", default="./ledger_data", help="持久化目录")
    parser.add_argument(
        "--genesis",
        help="创世余额 JSON 文件，内容为 {账户公钥十六进制: 余额}；仅首次初始化生效",
    )
    args = parser.parse_args(argv)

    genesis = None
    if args.genesis:
        with open(args.genesis, "r", encoding="utf-8") as fh:
            genesis = json.load(fh)

    store = Store(args.data_dir, genesis)
    serve(LedgerService(store), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

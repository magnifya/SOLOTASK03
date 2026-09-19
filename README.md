# SOLOTASK03 可验证账本后端

要实现一个可验证账本后端，用 Python 标准库加 hashlib 与 cryptography，同时提供 HTTP 服务和命令行入口。交易提交走 POST /v1/transactions，请求体是 JSON，含 from、to、amount 与 signature，amount 是整数；签名与余额校验通过才进入待打包集合，返回 202 与 tx_id，签名不合法或余额不足返回 400 并说明原因。打包走 POST /v1/blocks，把待打包交易按 tx_id 升序封成区块，算出前块哈希、Merkle 根与区块哈希后持久化，返回 201 与 height、block_hash、merkle_root，没有待打包交易返回 409。查询走 GET /v1/blocks/{height} 与 GET /v1/accounts/{account}，分别返回 block_hash、prev_hash、merkle_root、transaction_ids 与 balance、confirmed_transactions，查不到都返回 404。命令行提供 send、mine、block、account 四个子命令，与接口一一对应，打印单行 JSON。创世区块高度为零，逐块加一。同一批交易按相同顺序打包必须得到相同的 merkle_root 与 block_hash。

## 实现说明

代码全部在 `ledger/` 包中：

| 文件 | 职责 |
| --- | --- |
| `ledger/crypto.py` | Ed25519 验签、规范化交易消息、SHA-256 tx_id、Merkle 根 |
| `ledger/models.py` | Transaction / Block 模型与确定性区块哈希 |
| `ledger/store.py` | 链与待打包集合的 JSON 原子持久化、创世区块 |
| `ledger/service.py` | 提交校验（签名、金额、余额）、打包、查询 |
| `ledger/server.py` | 标准库 `http.server` 实现的 REST 接口 |
| `ledger/cli.py` | `send` / `mine` / `block` / `account` 四个子命令 |

约定：

- 账户标识即 Ed25519 公钥的十六进制（64 个字符）；`signature` 是对规范化
  消息 `{"amount":N,"from":"...","to":"..."}`（key 升序、无空白的 UTF-8 JSON）
  的 Ed25519 签名十六进制。
- `tx_id = sha256(规范化消息)`；同一笔交易重复提交（待打包或已确认）返回 409。
- Merkle 树每层做 `sha256(left_hex + right_hex)`，奇数节点与自身配对；
  空列表根为 `sha256(b"")`。
- 区块哈希为 `sha256(规范化 {"height","prev_hash","merkle_root"})`，不含时间戳，
  因此同一父块与同一批有序交易必然产生相同 `merkle_root` 与 `block_hash`。
- 任务未定义铸币接口，故每个身份拥有固定初始余额（默认 1,000,000，可用
  `--initial-balance` 或 `LEDGER_INITIAL_BALANCE` 调整）。余额 = 初始余额
  + 已确认收入 − 已确认支出；提交时还会扣除自己已在待打包集合中的支出，防止
  重复花用同一笔钱。身份首次出现在已确认区块后，账户才可查询（此前返回 404）。
- 创世区块高度为 0，`prev_hash` 为 64 个 `0`，不含交易；服务首次启动时自动创建。

## 安装依赖

需要 Python 3.10+ 与 cryptography（系统已装可跳过安装）：

```bash
pip install -r requirements.txt
```

## 启动服务

```bash
python -m ledger --host 0.0.0.0 --port 8080 --state ledger_state.json
```

环境变量 `LEDGER_HOST` / `LEDGER_PORT` / `LEDGER_STATE` / `LEDGER_INITIAL_BALANCE`
可提供同样的默认值。

## HTTP 接口

```bash
# 提交交易（signature 用 from 对应私钥对规范化消息签名）
curl -s -X POST localhost:8080/v1/transactions \
  -H 'Content-Type: application/json' \
  -d '{"from":"<pubkey-hex>","to":"<pubkey-hex>","amount":100,"signature":"<sig-hex>"}'
# -> 202 {"tx_id": "..."}；签名错误/余额不足 -> 400 {"error": "..."}

# 打包
curl -s -X POST localhost:8080/v1/blocks
# -> 201 {"height":1,"block_hash":"...","merkle_root":"..."}；无待打包交易 -> 409

# 查询
curl -s localhost:8080/v1/blocks/0
curl -s localhost:8080/v1/accounts/<pubkey-hex>
```

## 命令行

CLI 通过 HTTP 访问服务（默认 `http://127.0.0.1:8080`，可用 `--base-url` 或
`LEDGER_BASE_URL` 覆盖），输出与 HTTP 响应字段完全一致的单行 JSON：

```bash
# 本地用 Ed25519 私钥（PEM 文件或 64 位十六进制）签名后提交
python -m ledger.cli send --signing-key @alice.pem --to <recipient-pubkey-hex> --amount 100
python -m ledger.cli mine
python -m ledger.cli block 1
python -m ledger.cli account <pubkey-hex>
# 也可以传已有的签名：send --from <pubkey-hex> --signature <sig-hex> --to ... --amount ...
```

非 2xx 响应同样打印单行 JSON 并以退出码 1 结束。

## 基础测试

```bash
python -m compileall -q ledger   # 编译检查
python tests/smoke_test.py       # 不依赖网络的全流程冒烟测试
```

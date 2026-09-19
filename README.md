# SOLOTASK03 可验证账本后端

要实现一个可验证账本后端，用 Python 标准库加 hashlib 与 cryptography，同时提供 HTTP 服务和命令行入口。交易提交走 POST /v1/transactions，请求体是 JSON，含 from、to、amount 与 signature，amount 是整数；签名与余额校验通过才进入待打包集合，返回 202 与 tx_id，签名不合法或余额不足返回 400 并说明原因。打包走 POST /v1/blocks，**仅当链尾已确认且存在待打包交易时**，把待打包交易按 tx_id 升序封成**待定（pending）区块**，算出前块哈希、Merkle 根与区块哈希后持久化，返回 201 与 height、block_hash、merkle_root、`status=pending`，否则 409。区块查询 GET /v1/blocks/{height} 在原有字段外增加 `status`（`confirmed`/`pending`），查不到返回 404。已确认交易可通过 GET /v1/blocks/{height}/proof/{tx_id} 获取 Merkle 包含证明，返回 height、tx_id、index、merkle_root、block_hash 与 siblings；siblings 自叶向根排列，每项含 direction（sibling 位于当前节点的 left/right）与 64 位小写十六进制 hash，**待定区块的 proof 返回 409**，区块不存在、交易不在该高度或 tx_id 格式不符均返回 404。新增 GET /v1/blocks/{height}/status，仅返回 height、status，未知高度 404。新增 POST /v1/blocks/{height}/confirm：仅待定链尾且其前块已确认时可确认，200 返回 `status=confirmed`；对已确认区块重复调用幂等（仍 200），其他情况 409。新增 POST /v1/blocks/{height}/rollback：仅待定链尾可回滚，删除该区块并把其中交易去重后恢复到待打包集合，200 返回 `status=rolled_back`；未知高度（含已回滚的重复调用）404，已确认区块或非链尾 409；同一批交易重新打包得到相同 block_hash。创世区块高度为零且始终已确认，逐块加一。账户接口只统计已确认区块：余额 = 初始余额 + 已确认收入 − 已确认支出，再扣除所有待定支出（待打包集合与待定区块内），不计待定收入。同一批交易按相同顺序打包必须得到相同的 merkle_root 与 block_hash。

## 实现说明

代码全部在 `ledger/` 包中：

| 文件 | 职责 |
| --- | --- |
| `ledger/crypto.py` | Ed25519 验签、规范化交易消息、SHA-256 tx_id、Merkle 根与包含证明 |
| `ledger/models.py` | Transaction / Block 模型与确定性区块哈希 |
| `ledger/store.py` | 链与待打包集合的 JSON 原子持久化、创世区块、重启重建已确认交易索引 |
| `ledger/service.py` | 提交校验（签名、金额、余额）、打包、确认/回滚状态机、查询 |
| `ledger/server.py` | 标准库 `http.server` 实现的 REST 接口 |
| `ledger/cli.py` | `send` / `mine` / `block` / `account` / `proof` / `confirm` / `rollback` / `status` 子命令 |

约定：

- 账户标识即 Ed25519 公钥的十六进制（64 个字符）；`signature` 是对规范化
  消息 `{"amount":N,"from":"...","to":"..."}`（key 升序、无空白的 UTF-8 JSON）
  的 Ed25519 签名十六进制。
- `tx_id = sha256(规范化消息)`；同一笔交易重复提交（待打包或已确认）返回 409。
- Merkle 树每层做 `sha256(left_hex + right_hex)`，奇数节点与自身配对；
  空列表根为 `sha256(b"")`。包含证明 `merkle_proof(tx_ids, index)` 返回自叶向根
  的兄弟节点列表，每项 `{"direction": "left"|"right", "hash": ...}`，direction 表示
  兄弟节点位于路径节点的左/右侧；`verify_merkle_proof(tx_id, siblings, merkle_root,
  block_hash, expected_block_hash)` 重算根并比对区块哈希，任何畸形输入（非 64 位
  小写十六进制、非法 direction、层级过深等）均返回 `False`。
- 区块哈希为 `sha256(规范化 {"height","prev_hash","merkle_root"})`，不含时间戳，
  因此同一父块与同一批有序交易必然产生相同 `merkle_root` 与 `block_hash`。
- 任务未定义铸币接口，故每个身份拥有固定初始余额（默认 1,000,000，可用
  `--initial-balance` 或 `LEDGER_INITIAL_BALANCE` 调整）。账户只统计已确认区块，
  账户余额 = 初始余额 + 已确认收入 − 已确认支出，再扣除所有待定支出（待打包集合
  与待定区块内自己的支出），不计待定收入；提交与查询均使用该口径。身份首次出现
  在已确认区块后，账户才可查询（此前返回 404）。
- 区块有 `confirmed` / `pending` 两种状态：挖出的区块先为 pending，且最多只有
  链尾一块待定；`confirm` 后变为 confirmed，`rollback` 删除待定链尾并把交易去重
  恢复到待打包集合。链、待打包集合与已确认交易索引在一次原子写盘（临时文件 +
  `os.replace` + fsync）中共同落盘，落盘后才响应；重启时只按已确认区块重建索引，
  待定区块与孤儿交易不进索引。
- 创世区块高度为 0，`prev_hash` 为 64 个 `0`，不含交易，始终为 confirmed；服务首次启动时自动创建。

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

# 打包（仅链尾已确认且有待打包交易；新块为 pending）
curl -s -X POST localhost:8080/v1/blocks
# -> 201 {"height":1,"block_hash":"...","merkle_root":"...","status":"pending"}；否则 409

# 查询（区块摘要含 status）
curl -s localhost:8080/v1/blocks/0
curl -s localhost:8080/v1/blocks/1/status
# -> {"height":1,"status":"pending"|"confirmed"}；未知高度 404
curl -s localhost:8080/v1/accounts/<pubkey-hex>

# 确认待定链尾（已确认重复调用幂等；其他情况 409）
curl -s -X POST localhost:8080/v1/blocks/1/confirm
# -> 200 {"height":1,"status":"confirmed"}

# 回滚待定链尾：删除区块并去重恢复交易（未知/重复 404，已确认/非链尾 409）
curl -s -X POST localhost:8080/v1/blocks/1/rollback
# -> 200 {"height":1,"status":"rolled_back"}

# 已确认交易的 Merkle 包含证明（待定区块 409；区块不存在/交易不在该高度/tx_id 非法 -> 404）
curl -s localhost:8080/v1/blocks/1/proof/<tx-id-hex>
```

## 命令行

CLI 通过 HTTP 访问服务（默认 `http://127.0.0.1:8080`，可用 `--base-url` 或
`LEDGER_BASE_URL` 覆盖），输出与 HTTP 响应字段完全一致的单行 JSON：

```bash
# 本地用 Ed25519 私钥（PEM 文件或 64 位十六进制）签名后提交
python -m ledger.cli send --signing-key @alice.pem --to <recipient-pubkey-hex> --amount 100
python -m ledger.cli mine
python -m ledger.cli block 1
python -m ledger.cli status 1
python -m ledger.cli confirm 1
python -m ledger.cli rollback 1
python -m ledger.cli account <pubkey-hex>
python -m ledger.cli proof 1 <tx-id-hex>
# 也可以传已有的签名：send --from <pubkey-hex> --signature <sig-hex> --to ... --amount ...
```

非 2xx 响应同样打印单行 JSON 并以退出码 1 结束。

## 基础测试

```bash
python -m compileall -q ledger   # 编译检查
python tests/smoke_test.py       # 不依赖网络的全流程冒烟测试
python tests/merkle_proof_test.py  # Merkle 证明（crypto/service/HTTP/CLI）与接口回归
```

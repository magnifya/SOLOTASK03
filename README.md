# SOLOTASK03 可验证账本后端

要实现一个可验证账本后端，用 Python 标准库加 hashlib 与 cryptography，同时提供 HTTP 服务和命令行入口。交易提交走 POST /v1/transactions，请求体是 JSON，含 from、to、amount 与 signature，amount 是整数；签名与余额校验通过才进入待打包集合，返回 202 与 tx_id，签名不合法或余额不足返回 400 并说明原因。打包走 POST /v1/blocks，仅当链尾已确认且有待打包交易时，把待打包交易按 tx_id 升序封成待定区块，算出前块哈希、Merkle 根与区块哈希后持久化，返回 201 与 height、block_hash、merkle_root、status=pending，链尾待定或没有待打包交易都返回 409。查询走 GET /v1/blocks/{height} 与 GET /v1/accounts/{account}，分别返回 block_hash、prev_hash、merkle_root、status、transaction_ids 与 balance、confirmed_transactions，查不到都返回 404。已确认交易还可通过 GET /v1/blocks/{height}/proof/{tx_id} 获取 Merkle 包含证明，返回 height、tx_id、index、merkle_root、block_hash 与 siblings；siblings 自叶向根排列，每项含 direction（sibling 位于当前节点的 left/right）与 64 位小写十六进制 hash，区块不存在、交易不在该高度或 tx_id 格式不符均返回 404，区块仍为待定时返回 409。命令行提供 send、mine、block、account、proof、confirm、rollback、status 八个子命令，与接口一一对应，打印单行 JSON。创世区块高度为零，逐块加一。同一批交易按相同顺序打包必须得到相同的 merkle_root 与 block_hash。

## 确认 / 回滚状态机

每个区块带有 `status`（`pending` 或 `confirmed`）。创世区块直接为已确认；POST /v1/blocks 仅在链尾已确认且有待打包交易时打包，产出**待定块**并返回 201 与 status=pending，链尾待定或 mempool 为空都返回 409。待定块不计入账户与 Merkle 证明，只能位于链尾，之后有两种归宿：

- **确认**：POST /v1/blocks/{height}/confirm。仅待定链尾且前块已确认时可确认，返回 200 与 status=confirmed；对已确认区块重复确认是幂等的（仍返回 200），其余情况（未知高度、非链尾等）返回 409。
- **回滚**：POST /v1/blocks/{height}/rollback。仅待定链尾可回滚：删除该区块并把其中交易**去重**放回待打包集合，返回 200 与 status=rolled_back；未知高度或重复回滚返回 404，已确认或非链尾区块返回 409。回滚后重新打包同一批交易得到相同的 merkle_root 与 block_hash。

GET /v1/blocks/{height}/status 返回 height 与 status，未知高度返回 404。账户只统计已确认区块：balance 额外扣除待定块中自己的支出，但不计入待定收入；只出现在待定块中的账户查询返回 404。链、状态、待打包集合、交易索引与账户视图在一次原子写入中落盘，落盘后才响应；重启时从链重建索引（排除待定块）并校验 prev_hash 链接，杜绝孤儿块。

## 多区块一致性与崩溃恢复

每次成功的原子写入都把单调递增的 `generation` 写入快照。写入流程是：在主文件同目录创建唯一名 `.ledger-*` 临时快照 → 写入并 `fsync` 文件 → `os.replace` 原子提升为主文件 → `fsync` 目录。因此断电只会留下「旧主文件」或「已落盘但未改名的完整快照」，绝不会留下写了一半的主文件。`generation` 只在提升成功后才在内存推进，失败的写入不消耗 generation。

启动时扫描主文件及同目录所有 `.ledger-*` 候选：

- **一个文件都不存在**：按既有约定创建唯一创世块（仅此一种情况会新建链）。
- **只要存在文件**：逐一严格校验 JSON、`generation`、连续高度、`prev_hash`、重算 `block_hash` 与 Merkle 根、每笔交易的 `tx_id` 与 Ed25519 签名，以及「pending 只能位于链尾」「pending 与链上交易不得重复（块内/内存池内部也不得重复）」。
- 选择**有效快照中 generation 最大**者；若它仍是临时快照，则原子提升为主文件，并清理所有已判定的旧候选与残留临时文件。
- 同代快照内容冲突，或目录里没有任何有效候选时，抛出公开可捕获的 `ledger.store.StateRecoveryError`（`ValueError` 子类），携带 `path`（候选文件或所在目录）与 `reason`，**绝不静默新建链**。`python -m ledger` 遇到该错误会向 stderr 打印路径与原因并以退出码 2 结束。

并发的提交、打包、确认、回滚与启动恢复彼此串行化；写入在落盘前失败时，对应的内存改动会回滚，因此不会超支、重复入池、丢交易或返回未落盘的结果。重启、写入中断、主文件损坏、残留临时文件、哈希/签名错误、重复 pending 之后，next height、账户余额、`confirmed_transactions`、`tx_index`、Merkle proof 与多区块查询保持一致。


## 实现说明

代码全部在 `ledger/` 包中：

| 文件 | 职责 |
| --- | --- |
| `ledger/crypto.py` | Ed25519 验签、规范化交易消息、SHA-256 tx_id、Merkle 根与包含证明 |
| `ledger/models.py` | Transaction / Block 模型（含 pending/confirmed 状态）与确定性区块哈希 |
| `ledger/store.py` | 链、状态、待打包集合、索引与账户的 JSON 原子持久化（fsync 快照 + 原子改名）、generation、创世区块、启动快照扫描与崩溃恢复 |
| `ledger/service.py` | 提交校验（签名、金额、余额）、打包、确认/回滚状态机、查询 |
| `ledger/server.py` | 标准库 `http.server` 实现的 REST 接口 |
| `ledger/cli.py` | `send` / `mine` / `block` / `account` / `proof` / `confirm` / `rollback` / `status` 八个子命令 |

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
# 已确认交易的 Merkle 包含证明（区块不存在/交易不在该高度/tx_id 非法 -> 404；区块待定 -> 409）
curl -s localhost:8080/v1/blocks/1/proof/<tx-id-hex>

# 状态机
curl -s localhost:8080/v1/blocks/1/status          # -> {"height":1,"status":"pending"}
curl -s -X POST localhost:8080/v1/blocks/1/confirm  # -> 200 {"height":1,"status":"confirmed"}
curl -s -X POST localhost:8080/v1/blocks/1/rollback # 仅待定链尾可用
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
python -m ledger.cli proof 1 <tx-id-hex>
python -m ledger.cli status 1
python -m ledger.cli confirm 1
python -m ledger.cli rollback 1
# 也可以传已有的签名：send --from <pubkey-hex> --signature <sig-hex> --to ... --amount ...
```

非 2xx 响应同样打印单行 JSON 并以退出码 1 结束。

## 基础测试

```bash
python -m compileall -q ledger   # 编译检查
python tests/smoke_test.py       # 不依赖网络的全流程冒烟测试
python tests/merkle_proof_test.py  # Merkle 证明（crypto/service/HTTP/CLI）与接口回归
python tests/confirm_rollback_test.py  # 确认/回滚状态机（service/HTTP/CLI/重启重建）
python tests/recovery_test.py         # generation、多区块一致性、快照恢复、损坏拒绝、并发串行化
```

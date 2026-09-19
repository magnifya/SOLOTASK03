# SOLOTASK03 可验证账本后端

要实现一个可验证账本后端，用 Python 标准库加 hashlib 与 cryptography，同时提供 HTTP 服务和命令行入口。交易提交走 POST /v1/transactions，请求体是 JSON，含 from、to、amount 与 signature，amount 是整数；签名与余额校验通过才进入待打包集合，返回 202 与 tx_id，签名不合法或余额不足返回 400 并说明原因。打包走 POST /v1/blocks，把待打包交易按 tx_id 升序封成区块，算出前块哈希、Merkle 根与区块哈希后持久化，返回 201 与 height、block_hash、merkle_root，没有待打包交易返回 409。查询走 GET /v1/blocks/{height} 与 GET /v1/accounts/{account}，分别返回 block_hash、prev_hash、merkle_root、transaction_ids 与 balance、confirmed_transactions，查不到都返回 404。命令行提供 send、mine、block、account 四个子命令，与接口一一对应，打印单行 JSON。创世区块高度为零，逐块加一。同一批交易按相同顺序打包必须得到相同的 merkle_root 与 block_hash。

## 当前状态

接口已实现，代码位于 `ledger/`：

- `models.py` — 交易/区块模型、待签名报文、Merkle 根与区块哈希（确定性 JSON）
- `crypto.py` — 基于 cryptography 的 Ed25519 签名/验签
- `store.py` — 区块与内存池的 JSON 持久化、创世区块、余额重放
- `service.py` — 提交/打包/查询业务逻辑与状态码
- `httpapp.py` — 标准库 `http.server` 实现的 HTTP 服务
- `cli.py` — `send` / `mine` / `block` / `account` 命令行，输出单行 JSON

### 关键约定

- 待签名报文：`"<from>|<to>|<amount>"`（`from` 为付款方 Ed25519 公钥的十六进制）
- `tx_id = sha256(报文 + 十六进制签名)`
- Merkle 树奇数节点复制最后一个；空树的根为空串（创世区块）
- 区块哈希 = `sha256(确定性排序 JSON 的区块头)`，含 height/prev_hash/merkle_root/transaction_ids
- 创世区块高度为 0，`prev_hash` 为 64 个 0；此后高度逐块加一
- 同一批交易无论提交顺序如何，都按 `tx_id` 升序打包，故 merkle_root 与 block_hash 相同
- 余额校验会扣除内存池中已挂起的支出，防止同额双花

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动服务

```bash
# genesis.json 内容形如 {"<账户公钥十六进制>": 初始余额}
python3 -m ledger.httpapp --host 127.0.0.1 --port 8000 \
    --data-dir ./ledger_data --genesis genesis.json
```

### 命令行用法

服务地址可用 `--server` 或环境变量 `LEDGER_SERVER` 指定，默认 `http://127.0.0.1:8000`。

```bash
# 生成密钥（辅助工具，非四个业务接口之一）
python3 -m ledger.cli keygen

# send：可用私钥自动签名，或用 --signature 直传十六进制签名
python3 -m ledger.cli send --from <付款方公钥hex> --to <收款方> --amount 30 \
    --private-key <私钥hex>
python3 -m ledger.cli mine
python3 -m ledger.cli block 1
python3 -m ledger.cli account <账户公钥hex>
```

### HTTP 接口与状态码

- `POST /v1/transactions`：成功 `202 {tx_id}`；签名不合法或余额不足 `400`（含原因）
- `POST /v1/blocks`：成功 `201 {height, block_hash, merkle_root}`；内存池为空 `409`
- `GET /v1/blocks/{height}`：`200 {block_hash, prev_hash, merkle_root, transaction_ids}`；不存在 `404`
- `GET /v1/accounts/{account}`：`200 {balance, confirmed_transactions}`；不存在 `404`

### 基础测试

```bash
python3 -m compileall -q ledger          # 语法/构建检查
python3 -c "import ledger, ledger.httpapp, ledger.cli"  # 导入检查
```

端到端：启动服务后用 CLI 依次 `keygen → send → mine → block → account`，
错误签名/超额转账应得到 `400`，空池 `mine` 得 `409`，查询越界高度或未知账户得 `404`。


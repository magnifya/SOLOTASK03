# SOLOTASK03 可验证账本后端

要实现一个可验证账本后端，用 Python 标准库加 hashlib 与 cryptography，同时提供 HTTP 服务和命令行入口。交易提交走 POST /v1/transactions，请求体是 JSON，含 from、to、amount 与 signature，amount 是整数；签名与余额校验通过才进入待打包集合，返回 202 与 tx_id，签名不合法或余额不足返回 400 并说明原因。打包走 POST /v1/blocks，把待打包交易按 tx_id 升序封成区块，算出前块哈希、Merkle 根与区块哈希后持久化，返回 201 与 height、block_hash、merkle_root，没有待打包交易返回 409。查询走 GET /v1/blocks/{height} 与 GET /v1/accounts/{account}，分别返回 block_hash、prev_hash、merkle_root、transaction_ids 与 balance、confirmed_transactions，查不到都返回 404。命令行提供 send、mine、block、account 四个子命令，与接口一一对应，打印单行 JSON。创世区块高度为零，逐块加一。同一批交易按相同顺序打包必须得到相同的 merkle_root 与 block_hash。

## 当前状态

上述接口尚未实现。实现完成后，请在此补充安装依赖、启动方式与基础测试命令。

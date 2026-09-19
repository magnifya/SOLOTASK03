# SOLOTASK03

可验证账本后端。Python 标准库加 hashlib 与 cryptography，对外提供 HTTP 服务与命令行入口，两者能力一致。

## 运行

    python -m app --port <port>      # 启动 HTTP 服务
    python -m app <subcommand>       # 命令行入口，输出单行 JSON

## 公开接口

POST /v1/transactions
  请求：from、to、amount、signature
  成功：202 -> tx_id
  签名不合法或余额不足：400

POST /v1/blocks
  作用：把当前待打包交易封成区块，计算前块哈希、交易 Merkle 根与区块哈希并持久化
  成功：201 -> height、block_hash、merkle_root
  无待打包交易：409

GET /v1/blocks/{height}
  成功：200 -> block_hash、prev_hash、merkle_root、transaction_ids
  不存在：404

GET /v1/accounts/{account}
  成功：200 -> balance、confirmed_transactions
  不存在：404

## 约定

- 同一批交易按相同顺序打包，Merkle 根与区块哈希必须完全一致
- 进程重启后已确认的区块仍可读取
- 区块高度从零开始连续递增

## 当前状态

接口尚未实现；实现完成后需在此补充安装依赖、启动方式与基础测试命令。

# SOLOTASK03 可验证账本后端

要实现一个可验证账本后端，用 Python 标准库加 hashlib 与 cryptography，同时提供 HTTP 服务和命令行入口。交易提交走 POST /v1/transactions，请求体是 JSON，含 from、to、amount 与 signature，amount 是整数；签名与余额校验通过才进入待打包集合，返回 202 与 tx_id，签名不合法或余额不足返回 400 并说明原因。打包走 POST /v1/blocks，仅当链尾已确认且有待打包交易时，把待打包交易按 tx_id 升序封成待定区块，算出前块哈希、Merkle 根与区块哈希后持久化，返回 201 与 height、block_hash、merkle_root、status=pending，链尾待定或没有待打包交易都返回 409。查询走 GET /v1/blocks/{height} 与 GET /v1/accounts/{account}，分别返回 block_hash、prev_hash、merkle_root、status、transaction_ids 与 balance、confirmed_transactions，查不到都返回 404。已确认交易还可通过 GET /v1/blocks/{height}/proof/{tx_id} 获取 Merkle 包含证明，返回 height、tx_id、index、merkle_root、block_hash 与 siblings；siblings 自叶向根排列，每项含 direction（sibling 位于当前节点的 left/right）与 64 位小写十六进制 hash，区块不存在、交易不在该高度或 tx_id 格式不符均返回 404，区块仍为待定时返回 409。批量接口 POST /v1/blocks/{height}/proofs 请求体为 {"tx_ids":[...]}，须为非空、元素互异且各为 64 位小写十六进制的数组；解析失败、键缺失/额外、类型错误、空数组/重复/格式错均 400 且不改状态，未知高度或缺交易 404，待定块 409。成功返回顶层键序固定为 height,block_hash,merkle_root,transaction_ids,proofs：transaction_ids 为该块全部叶子（按 tx_id 升序），proofs 按 tx_id 字典序排列，每项键序 tx_id,index,siblings。离线可用 ledger.crypto.verify_merkle_proof_bundle(bundle, expected_block_hash, expected_merkle_root) -> bool 严格校验键序、类型、唯一 tx_id、index 映射、自叶到根路径、重算根与区块哈希，任何畸形或篡改均返回 False 而不抛异常。命令行提供 send、mine、block、account、proof、proofs、confirm、rollback、status 等子命令，与接口一一对应，打印单行 JSON；proofs HEIGHT TX_ID... 在非 2xx 时退出码为 1。创世区块高度为零，逐块加一。同一批交易按相同顺序打包必须得到相同的 merkle_root 与 block_hash。

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


## 候选分叉与采用

除逐笔打包外，还可以整链提交**候选分叉**，由节点校验后按最长链规则选用。

- **提交候选**：`POST /v1/forks/candidates`，请求体 `{"blocks":[...]}`，每个块含
  `height`、`prev_hash`、`merkle_root`、`block_hash`、`status`、`transactions`，
  每笔交易含 `from`、`to`、`amount`、`signature`、`tx_id`。候选必须**接 canonical
  创世块**（第 0 块与 canonical 创世块逐字节一致：高度 0、空交易、已确认），随后
  逐块高度连续、`prev_hash` 相连。节点逐块重算 `block_hash` 与 Merkle 根、逐笔校验
  `tx_id` 与 Ed25519 签名，要求块内及全链 `tx_id` 唯一且按 `tx_id` 升序，并按初始
  余额重放整链确保任何账户都不超支；`status` 只能全部 `confirmed` 或仅末块
  `pending`。合法返回 `201` 与分叉描述
  `S = {"tip_hash","height","length","status"}`，其中 `length` **含创世块**；非法
  候选 `400`，与 canonical 或已存在候选重复（tip_hash 相同）返回 `409`。
- **查询链视图**：`GET /v1/chain` 返回
  `{"canonical": S, "candidates": [S,...], "adoptable": [S]}`。候选按
  `tip_hash` 升序排列；`canonical` 是当前链。`adoptable` 至多一个元素：当某个**非
  canonical** 候选在比较中胜出时放入它，否则为空。
- **比较与采用**：链之间「最长优先」，长度相同取 `tip_hash` 最小者。
  `POST /v1/forks/{tip_hash}/adopt` 采用胜出候选：未知 tip（含非 64 位十六进制）
  返回 `404`，候选不是当前胜者返回 `409`，成功 `200` 返回新链的 S。采用在**一次
  原子写入**中替换 canonical 链、单调递增 `generation` 并重建全部索引：旧链独有的
  **已确认**交易去重后回到待打包集合，旧链 pending 末块与新链已含的交易都不入池；
  新链若带 pending 末块，该末块同样不进入内存池。
- **快照与恢复**：候选与 `generation` 一起写入快照；重启时丢弃任何不再合法的候选
  （不会因此报错），而 canonical 链无效或同代快照内容冲突仍抛
  `ledger.store.StateRecoveryError`，绝不静默新建链。
- **导出候选**：`GET /v1/forks/{tip_hash}/export` 导出已存候选分叉，返回五字段
  `{tip_hash, height, length, status, blocks}`：前四个摘要字段均描述末块（tip），
  `blocks` 含创世块、每笔交易的签名与可选的 pending 末块。canonical tip、未知 tip
  与非法 tip（非 64 位小写十六进制）都返回 `404`。导出的文档可原样提交给
  `POST /v1/forks/candidates`（即除 `{"blocks":[...]}` 外也接受该五字段格式），
  节点会按块重算并核对摘要字段，重验失败 `400`，重复 `409`。

## 节点间候选链同步与审计查询

除本地提交候选外，节点还能接收其他节点推来的候选链并提供审计查询。

- **接收同步**：`POST /v1/forks/sync`，请求 JSON 含
  `{"source","request_id","expires_at","candidate"}`：`source` 是来源节点标识，
  `request_id` 是该来源作用域内的幂等键，`expires_at` 是 Unix 秒过期时刻，
  `candidate` 按现有导出格式（五字段文档，也接受 `{"blocks":[...]}` 或裸块数组）。
  **新请求先过来源授权闸门**：`source` 必须在持久化信任注册表中存在、`status`
  仍为 `active` 且其注册 `expires_at` 晚于当前时刻；未知、已撤销或注册已过期的
  来源一律返回 `403`，此时不检查候选、不落任何状态。仅在授权通过后，节点才对
  候选按既有规则**全量重验**：canonical 创世块逐字节一致、高度连续、
  `prev_hash` 相连、重算 `block_hash` 与 Merkle 根、逐笔校验 `tx_id` 与 Ed25519
  签名、`tx_id` 全链唯一且块内升序、按初始余额重放不超支、仅允许末块 `pending`，
  导出文档自带的摘要字段也会逐一核对。成功 `201` 返回
  `{tip_hash, height, length, status, expires_at}`。状态码优先级：字段格式错误
  `400` → 来源未授权 `403` → 字段合法但请求 `expires_at` 不晚于当前时刻 `410`
  → 候选整链/摘要校验失败 `400` → tip 与 canonical 或已存候选重复 `409`。
- **幂等与冲突**：同一 `source` + `request_id` 且记录未过期的重试**豁免授权
  检查**：即使该来源此后已轮换、撤销或注册过期，候选内容相同仍返回 `200` 与
  **首次的原结果**（含原 `expires_at`）；内容不同返回 `409`；篡改摘要字段仍按
  新请求重算并返回 `400`；候选 `tip_hash` 与 canonical 或任一已存候选重复也
  返回 `409`。
- **过期处理**：同步带来的候选只在记录未过期期间存活；一旦过期，记录与其候选
  分叉一并移除（已采用上链的 tip 只留审计记录、不影响 canonical 链）。元数据与
  候选在**同一次原子写入**中落盘；重启时重验全部候选并丢弃过期或失效记录，
  **并按当前信任注册表重新校验每条记录的来源授权**——来源未知、已撤销或注册已
  过期的记录连同其候选一并丢弃（已采用 tip 仅移除元数据，canonical 链不动）。
  **停机期间到期或授权失效的每条记录，恢复时在持久化审计历史之后补写恰好一条
  `sync_expired`**（`event_id` 紧随其后连续编号、保留
  source/request_id/tip_hash/expires_at 字段，并按 `(source, request_id)`
  排序）；已持久化过 `sync_expired` 的记录不再补写（崩溃重试不重复），补写结果
  随调和后的记录/分叉在**同一次原子写入**落盘。指纹不符或 tip 无处解析等其他
  失效仍静默丢弃、不产生事件。历史 `sync_received`/`sync_adopted`/`sync_expired`
  事件逐字保留、`event_id` 从 1 起不间断。
- **审计查询**：`GET /v1/forks/sync` 支持 `source`、`min_height`、`max_height`、
  `mode`、`limit`（默认 50，范围 1–200）、`cursor`（默认 0）。`mode` 为可选
  传输模式过滤：缺省或 `plain` 只列普通同步（整链与增量区间）记录，`attested`
  只列签名同步记录，`all` 合并两类；仅允许 `plain`、`attested`、`all`，非法值
  或重复参数一律 `400`。数值参数必须是首位非 0 的
  十进制（`0` 合法），非法值 `400`，`min_height > max_height` 也是 `400`。合并
  结果按 `(height, tip_hash, source, mode, request_id)` 升序稳定分页，返回
  `{items, total, next_cursor}`；
  `cursor == total` 返回空页，`cursor > total` 返回 `400`，没有更多结果时
  `next_cursor` 为 `null`。每个 item 保留原七字段
  `{source, request_id, tip_hash, height, length, status, expires_at}`，不含
  `mode`。
- **生命周期历史查询**：`GET /v1/forks/sync/history` 以只增审计历史为数据源，
  每个同步生命周期的每个阶段一行。支持 `source`、`tip_hash`、`kind`、`mode`、
  `min_height`、`max_height`、`limit`（默认 50，范围 1–200）、`cursor`（默认
  0）。`tip_hash` 必须是 64 位小写十六进制：格式错误 `400`，未知值只返回空页；
  `kind` 只允许 `sync_received`、`sync_adopted`、`sync_expired`，未知值 `400`。
  `mode` 缺省或 `all` 返回全量事件；`plain` 匹配普通事件（含没有 `mode` 字段
  的旧事件——旧事件仍按既有字段输出、不新增字段）；`attested` 仅匹配
  `mode="attested"` 的事件；非法或重复 `mode` 返回 `400`。
  数值参数必须是非负十进制字符串——除 `0` 外禁止前导零，符号、小数、空白及重复
  参数一律 `400`；`min_height > max_height` 或 `cursor > total` 也是 `400`，
  `cursor == total` 返回空页。结果按
  `(height, tip_hash, source, request_id, event_id)` 升序，返回
  `{items, total, next_cursor}`，没有更多结果时 `next_cursor` 为 `null`。每个
  item 为
  `{event_id, kind, at, source, request_id, tip_hash, height, length, status,
  expires_at}`。接收时冻结候选摘要，之后采用或过期均不改写已落盘行；每个来源
  采用时追加恰好一条 `sync_adopted`，每个生命周期过期追加恰好一条
  `sync_expired`；已采用 tip 过期只留审计记录、不动 canonical 链。重启时校验
  历史元数据、来源授权与排序；相关操作共锁并在一次原子写入中落盘，失败回滚
  候选、记录、generation 与审计事件，重试不产生重复事件；缺少冻结摘要的旧快照
  仍可加载（查询时回退实时解析）。
- **同步记录导出**：`GET /v1/forks/sync/export?source=S&request_id=R&mode=M`
  按幂等键导出一条已接收的同步候选。三个参数全部必填且只能出现一次，
  `mode` 仅允许 `plain`/`attested`（普通与签名记录是分立的幂等命名空间），
  `source`/`request_id` 必须非空；缺失、重复、未知参数或非法取值一律
  `400`。命中返回 `200`，顶层键序固定为
  `source, request_id, mode, expires_at, tip_hash, height, length, status,
  candidate, attestation`：`expires_at`/`height`/`length` 为非布尔整数，
  `tip_hash` 为 64 位小写十六进制，`status` 为 `pending|confirmed`。
  `plain` 记录的 `candidate` 是五字段导出文档
  `{tip_hash, height, length, status, blocks}`（可原样再提交），
  `attestation` 为 `null`；`attested` 记录的 `candidate` 逐字保留被签名的
  原始候选，`attestation` 为冻结的 `{public_key, version, signature}`，
  导出前按 domain、冻结公钥与指纹重新验签。候选在同一把锁内从存储的
  fork 或（已采用时）canonical 前缀重建，不新增权威副本；增量区间
  （range）记录命中返回 `409`；未知、已过期或已清理的键返回 `404`。
  导出时若签名/摘要重验失配，按既有规则静默丢弃该缓存记录（审计历史
  保留、不产生事件）并返回 `404`；清理落盘失败会恢复记录与候选并抛出
  `OSError`。重启后导出结果一致。
- **串行化与采用**：同步接收、审计查询与候选采用共用同一把锁串行化。采用规则
  不变（最长链优先、同长取最小 `tip_hash`），在一次原子写入中换链、递增
  `generation` 并重建索引：旧链独有的已确认交易去重回池，旧链 pending 末块与
  新链已含交易都不入池；已采用 tip 的同步记录继续可查询直到过期。

## 整链同步的增量区间协议

整链同步之外，节点还可以只拉取/推送锚点之后的**增量区间**；既有接口全部保持
兼容，增量候选在服务端拼接 canonical 前缀后走的仍是现有整链重验与最长链规则。

- **拉取区间**：`GET /v1/chain/range`，必填 `after_height`、`after_hash`，可选
  `limit`（默认 100，范围 1–500）。参数重复出现、数值不是首位非 0 的严格十进制、
  `after_hash` 不是 64 位小写十六进制，或 `limit` 越界，一律 `400`；锚点高度不
  存在返回 `404`；`after_hash` 与该高度的区块不匹配返回 `409`。在同一把锁内
  返回 `{"anchor","blocks","canonical","next_height"}`：`anchor` 是
  `{height,block_hash}`，`blocks` 是锚点**之后**的完整区块文档（含全部交易，
  pending 尾块同样可导出），至多 `limit` 个；`canonical` 是当前链描述符 S；
  `next_height` 是本页之后的下一高度，已到链尾时为 `null`。
- **推送区间**：`POST /v1/forks/sync/range`，请求体
  `{"source","request_id","expires_at","anchor","blocks","tip"}`。`anchor` 为
  `{height,block_hash}`；`blocks` 非空，自锚点下一高度起连续；`tip` 是拼接后
  整链的链尾摘要 `{tip_hash,height,length,status}`（`length` 含 canonical 前缀
  与创世块）。**新请求**严格按既有顺序处理：字段格式错误 `400` → 来源未授权
  `403` → 请求 `expires_at` 已到 `410` → 锚点高度/哈希与当前 canonical 不匹配
  `409` → 拼接 canonical 前缀执行**现有整链重验**（创世一致、连续高度与
  prev_hash、重算 block_hash/Merkle 根、tx_id 与 Ed25519、全链唯一且块内升序、
  初始余额重放不超支、仅末块可 pending）并逐一核对 `tip` 字段，失败 `400` →
  tip 与 canonical 或已存候选重复 `409`。成功 `201` 返回与整链同步相同的五字段
  `{tip_hash,height,length,status,expires_at}`。
- **幂等与原子持久化**：同一 `source`+`request_id` 的存活记录重试时**豁免授权
  与过期检查**，且不重新拼接、不依赖当前 canonical——只对请求自带的锚点与尾部
  区块做独立重验（篡改 `tip`/区块仍返回 `400`，不回放缓存）：内容相同返回 `200`
  与首次原结果（含原 `expires_at`），即使此后来源被轮换/撤销、canonical 已推进；
  内容不同返回 `409`。首次成功时在**同一次原子写入**里保存**拼接后的完整候选**
  （按 tip_hash 存入既有候选表）、同步记录、仅覆盖锚点+尾部的内容**指纹**与
  `sync_received` 事件；写盘失败完整回滚候选、同步记录、审计事件与
  `generation`。此后采用（最长链/最小 tip_hash）、旧链已确认交易去重回池、
  pending 末块不入池、过期清理与重启调和全部直接作用于该完整候选，规则与整链
  同步完全一致；重启按当前信任注册表重新授权，并用持久化的 range 载荷独立重算
  指纹、核对存储候选恰为 canonical 前缀加该尾部，失配记录静默丢弃。
- **区间记录导出**：`GET /v1/forks/sync/range/export?source=S&request_id=R&mode=M`
  按幂等键导出一条已接收的增量区间记录（整链记录仍走
  `GET /v1/forks/sync/export`，遇 range 记录依旧 `409`）。三个参数全部必填、
  单值，`mode` 仅允许 `plain`/`attested`（两个幂等命名空间）；缺失、重复、
  未知参数或非法取值一律 `400`，未知、已过期或已清理的键 `404`，命中整链
  （非 range）记录 `409`。命中返回 `200`，顶层键序固定为
  `source, request_id, mode, expires_at, anchor, blocks, tip, attestation`：
  `expires_at` 为非布尔整数；`anchor` 键序 `height, block_hash`（非负整数、
  64 位小写十六进制）；`blocks` 为交付的非空尾部区块文档（README 键序）；
  `tip` 键序 `tip_hash, height, length, status`，由 anchor+blocks 重算。
  `plain` 记录的 `attestation` 为 `null`；`attested` 记录携带冻结的
  `{public_key, version, signature}`（公钥 64 位小写十六进制、`version`
  正整数、`signature` 128 位小写十六进制）。导出前按既有规则重验：尾部独立
  重验（高度连续、prev_hash 相连、重算 block_hash 与 Merkle 根、tx_id 与
  Ed25519、唯一且块内升序、仅末块可 pending）、拼接链整链重验并核对恰为
  canonical 锚点前缀加该尾部、重算 range 指纹；attested 记录另按
  `ledger-sync-range-v1` domain、冻结公钥重新验签并核对冻结 tip 重算一致。
  任一失配按既有缓存规则静默丢弃该记录（审计历史保留、不产生事件）并返回
  `404`；清理落盘失败恢复记录与候选并抛出 `OSError`。导出在同一把锁内从
  存储的 fork 或（已采用时）canonical 前缀重建，不新增权威副本；重启后
  导出结果一致。命令行为
  `python -m ledger.cli sync-range-export --source S --request-id R --mode
  plain|attested`，打印单行 JSON，非 2xx 退出码 1。

## 签名区块头分页

`GET /v1/chain/headers` 在既有入口全部不变的前提下，提供只含**区块头**的
签名分页，供离线节点只同步头、随后按需校验。

- **参数**：`after_height`、`after_hash` 必填，`limit` 可选（默认 100，
  范围 1–500），规则与 `GET /v1/chain/range` 完全相同：参数重复、严格
  十进制/64 位小写十六进制格式不符、`limit` 越界一律 `400`；锚点高度未知
  `404`；`after_hash` 与该高度区块不符 `409`。
- **200 文档键序固定为 `anchor, headers, tip, auth`**：
  - `anchor` 键序 `height, block_hash`，即本页起始锚点（页面内容在其
    **之后**）；
  - `headers` 为锚点之后的区块头**升序**数组（不含交易），至多 `limit`
    个；每项键序恰为
    `height, prev_hash, merkle_root, block_hash, status`（非负非布尔整数、
    64 位小写 hex、`status` 仅取 `confirmed`/`pending`），pending 区块只
    能出现在链尾；
  - `tip` 沿用链描述符 S（`tip_hash, height, length, status`）；
  - `auth` 键序 `key_version, signature`：由节点当前审计签名者
    （`GET /v1/trust` 的 `audit_signers` 中当前版本）对
    **SHA-256 摘要**做出的 Ed25519 签名，签名消息为
    `UTF8("ledger-headers-v1") ‖ canonical_json(去掉 auth 的文档)`，其中
    `canonical_json` 即 `json.dumps(..., sort_keys=True,
    separators=(",",":"), ensure_ascii=False)` 的 UTF-8 字节，签名为 128
    位小写十六进制。
- 当锚点就是当前链尾时，`headers` 为空数组，文档仍照常签名；客户端可据此
  轮询链是否推进。
- **离线校验**：`ledger.light_client.verify_header_page(document, anchor,
  tip_hash, trust) -> dict`。`anchor` 为调用方钉住的
  `{height, block_hash}`，`tip_hash` 为钉住的链尾哈希，`trust` 取
  `GET /v1/trust` 文档（按 `audit_signers` 中 `key_version` 对应的
  `public_key` 取公钥）。校验顺序：顶层与嵌套**键序/类型**严格一致
  （畸形为 `input`）；按 `key_version` 取审计公钥并按上述
  `ledger-headers-v1` 摘要验 Ed25519 签名（版本未知或签名验不过为
  `auth`）；`document.anchor` 必须与钉住锚点严格相等；逐项**重算头哈希**
  （`block_hash = SHA256(canonical_json({height, prev_hash, merkle_root}))`，
  键按 `height, merkle_root, prev_hash` 排序的紧凑 JSON）并核对
  `prev_hash` 链接与连续高度（首页首项接锚点哈希，其后接前一项哈希），
  pending 只允许在链尾；`tip` 必须命名钉住的 `tip_hash`、`length` 等于
  `height + 1`，且页面末项（或空页时的锚点）与 S 自洽——任一不符为
  `integrity`。函数**不抛异常**，失败返回 `{"ok": false, "error"}`，
  `error` 仅取 `input`/`auth`/`integrity`；成功键序固定为
  `ok, anchor, tip, verified_block_hashes`，`verified_block_hashes` 为本页
  按升序验证通过的头哈希（锚点即链尾时为空数组）。签名者轮换后，旧页面仍
  可用其 `key_version` 对应的历史公钥继续验证。
- **多页连续校验**：`ledger.light_client.verify_header_pages(documents,
  anchor, tip_hash, trust) -> dict`。`documents` 为**非空有序数组**，每页
  沿用 `verify_header_page` 的键序、类型、签名者历史、域签名与头哈希契约
  逐页复验；各页 `tip` 必须逐字段相同且 `tip_hash` 等于入参。首页
  `anchor` 必须等于钉住锚点，后页 `anchor` 必须等于前页末头的
  `{height, block_hash}`，高度与 `prev_hash` 跨页连续——缺页、重页、乱序
  均断链；非末页 `headers` 不得为空，pending 只许为全批末头（pending 之后
  不允许再有后续页），末页必须到达钉住的 tip，空页仅当其锚点即 tip 时合
  法。函数**不抛异常**：数组/参数形状、键序、类型错误为 `input`，未知签
  名版本或验签失败为 `auth`，锚点、tip、哈希、链接、分页或 pending 位置
  错误为 `integrity`。成功键序固定为
  `ok, anchor, tip, pages, verified_block_hashes`，`pages` 为页数，哈希
  按链序且不含锚点；失败仅返回 `{"ok": false, "error"}`。
- **分叉定位**：`POST /v1/chain/headers/locate`。请求体为 JSON 对象，**仅
  含顺序键 `locators` 与可选 `limit`**（顺序不符、多/缺键均 `400`）：
  `locators` 为 **1–64 项**数组，每项键序恰为 `height, block_hash`，
  `height` 为非布尔非负整数、在数组中**严格降序且不重复**，`block_hash`
  为 64 位小写 hex；`limit` 省略时默认 100，否则为非布尔整数 1–500。
  JSON 解析失败或任何键/值非法一律 `400` 且**无副作用**。节点按数组顺序
  取**首个**与主链同高度且同哈希的项作为命中锚点；全部不匹配为 `409`。
  `200` 沿用签名头页契约，键序固定 `anchor, headers, tip, auth`：`anchor`
  为命中项，`headers` 自其后升序、至多 `limit` 项，空页、头项、`tip` 与
  签名规则均与 `GET /v1/chain/headers` 完全相同；主链与签名者在**同一把
  锁**下取快照，分页与签名不会混用并发状态（并发只许整体采用或整体轮换，
  不混合）。
- **定位页离线校验**：`ledger.light_client.verify_header_locator_page(
  document, locators, tip_hash, trust) -> dict`。`document` 为定位接口返回
  的签名头页，`locators` 为客户端原始请求列表（形状/键序/类型规则同上），
  `tip_hash`、`trust` 沿用 `verify_header_page`。先严格校验列表与参数
  （`input`），再按 `ledger-headers-v1` 域签名取 `audit_signers` 验签
  （未知版本或验签失败为 `auth`）；页面自身 `anchor` 必须是 `locators`
  中之一，其下标（**从 0 起**）作为 `matched_index` 返回，且头哈希、
  `prev_hash` 链接、连续高度、pending 位置与 `tip` 全部按
  `verify_header_page` 复验——`anchor` 不在列表、头链断裂或 `tip` 不符为
  `integrity`。函数**不抛异常**；成功键序固定为
  `ok, anchor, tip, matched_index, verified_block_hashes`，失败仅
  `{"ok": false, "error"}`，`error` 仅取 `input`/`auth`/`integrity`。
- **持久化头检查点**：`ledger.light_client.advance_headers(path,
  documents, anchor, tip_hash, trust) -> dict` 把每批**已核验**的签名头页
  落盘为可继续的头检查点（纯库 API，其余入口不变）。首次使用 `path` 时
  `anchor` 必须是键序 `height, block_hash` 的合法锚点；续写传 `None`
  （从已存 tip 继续）或已存 tip 的 `{height, block_hash}`。`documents`
  按 `verify_header_pages` 原样多页校验；新 tip **不得降高**，同高度仅允
  许同一 `block_hash` 从 `pending` 变 `confirmed`，其余为 `integrity`；
  与已存**末批**完全相同（`tip_hash`、`trust`、`documents` 逐字相同）的
  提交幂等，不增代、文件字节不动。文件为单个紧凑 UTF-8 JSON 文档（非
  ASCII 不转义、末尾恰好一个换行），顶层键序固定为
  `v, generation, anchor, tip, finalized, steps, hash`：`v = 3`
  （v1/v2 文件仍可读取——其 `anchor` 即隐式 finalized 边界——下次成功
  写入时迁移为 v3），`generation` 为非布尔正整数、每次成功推进、重组或
  最终化 +1，`anchor` 为首次钉住的锚点，`tip` 沿用链描述符 S，
  `finalized` 为不可逆最终化边界 `{height, block_hash}`（键序
  `height, block_hash`；新检查点等于 `anchor`，由
  `finalize_headers` 推进），`steps`
  为非空数组且每项键序恰为
  `kind, tip_hash, trust, documents, locators`（`kind` 为
  `linear`/`locator`；`linear` 步 `locators` 为 `null`，`locator` 步
  携带其请求定位列表；嵌套键序沿用既有契约），`hash` 为去掉
  `hash` 自身的 canonical_json（`sort_keys`、紧凑分隔符、
  `ensure_ascii=False`）字节的 SHA-256（64 位小写 hex），v3 在 v2
  基础上仅新增 `finalized` 一个字段、序列化与摘要规则不变。加载时
  逐批重放、重验 finalized 归属（必须为重放所得当前分支的 anchor 或
  confirmed 头）并核对最终 tip；同一 `path` 共用一把锁串行、临时文件
  fsync 后 `os.replace` 原子换入，任何失败原字节不变且不增代。成功按
  键序 `ok, generation, tip` 返回；失败仅返回 `{"ok": false,
  "error"}` 且**不抛异常**，`error` 仅取 `input`（参数、首锚或
  `tip_hash` 非法）、`auth`（验签）、`integrity`（批次或 tip 冲突）、
  `state`（已存文件的解析、键序、类型、摘要、归属或重放失配，文件不
  被截断或重建）、`io`（读写失败）。
- **检查点重组**：`ledger.light_client.reorg_headers(path, documents,
  locators, tip_hash, trust) -> dict` 把一批**已核验**的定位签名头页
  （分叉重组）落盘到同一检查点文件（纯库 API，HTTP/CLI 不变）。批次按
  `verify_header_locator_pages` 原样多页校验；`path` 处检查点必须已存在
  （缺失为 `io`，无首次使用）。**边界**为 anchor 匹配的**最后**一个已存
  step 的 tip；无 step 匹配时才取初始 anchor（anchor 落在别处为
  `integrity`）。该边界还必须是 finalized 边界本身或其后的当前分支点：
  最终化历史不可逆，anchor 早于 finalized（更低高度，或同高异 hash）的
  批次为 `integrity`，文件字节与 generation 均不变。边界之后的步骤后缀
  被删除、追加一条 `locator` 步，`replaced` 为删除的步数，finalized
  边界保持不变。新 tip 高度**不得低于**已存 tip；同高度异 hash（即重组
  本身）`pending`/`confirmed` 均可，同 hash 仅允许
  `pending -> confirmed`，其余同高冲突为 `integrity`。与已存**末
  locator 步**完全相同（`tip_hash`、`trust`、`documents`、`locators`
  逐字相同）的提交幂等：`replaced = 0`、不写盘、不增代；其余成功
  `generation + 1` 并原子换入 v3 文件。成功按键序
  `ok, generation, tip, replaced` 返回；失败仅返回
  `{"ok": false, "error"}` 且**不抛异常**，`error` 仅取 `input`
  （参数或定位/批次结构）、`auth`（签名者版本或验签）、`integrity`
  （最终化、边界、链、高度或同高冲突）、`state`（已存文件键序、类型、
  摘要、归属或重放校验失败）、`io`（文件缺失或读写失败）。
- **不可逆最终化边界**：`ledger.light_client.finalize_headers(path,
  height, block_hash) -> dict`（纯库 API，参数无默认值）。`path` 为非空
  串、`height` 为非布尔非负整数、`block_hash` 为 64 位小写 hex，参数非法
  为 `input`。检查点在同一把 per-path 锁下被严格加载与完整重放（缺失为
  `io`；解析、键序、类型、摘要、归属或重放失配为 `state`）。目标必须
  是重放所得当前分支的 **anchor 或 confirmed 头**：未知高度（含高于
  tip）、pending 头、低于当前 finalized 高度、同高异 hash 均为
  `integrity`，不增代、文件字节不动。提高边界时 `generation + 1` 并以
  v3 原子换入（anchor/tip/steps 不变，仅 `finalized` 推进）；同一目标
  幂等，返回当前 generation 且字节不变。成功键序固定为
  `ok, generation, finalized`，`finalized` 键序 `height, block_hash`；
  失败仅返回 `{"ok": false, "error"}` 且**不抛异常**。v1/v2 文件读取时
  以其 `anchor` 为 finalized，本函数成功写入即完成 v3 迁移；v3 文件恢复
  时须重验 finalized 的分支归属（落在已丢弃分叉或 pending 头为
  `state`）。

- **签名最终化凭证**：`GET /v1/chain/finality`（**无参数**，携带任何查询
  参数——含空值或重复参数——一律 `400`；裸 `?` 无参数照常接受）。主链与
  审计签名者在**同一把锁**内取快照，`200` 文档键序固定为
  `finalized, tip, auth`：
  - `finalized` 键序 `height, block_hash`，取当前主链**最后一个 confirmed
    块**（genesis 出生即 confirmed；pending 链尾不计入）；
  - `tip` 沿用链描述符 S（与 `GET /v1/chain/headers` 的 `tip` 完全相同，
    故链尾 pending 时 `tip` 为 pending 而 `finalized` 仍指上一 confirmed
    块）；
  - `auth` 键序 `key_version, signature`：由节点当前审计签名者按
    **SHA-256 摘要**做出的 Ed25519 签名，签名消息为
    `UTF8("ledger-finality-v1") ‖ canonical_json(去掉 auth 的文档)`
    （`canonical_json` 规则与头页一致；签名 128 位小写 hex），版本取
    `GET /v1/trust` 的 `audit_signers`，轮换后旧凭证仍可按其
    `key_version` 的历史公钥验证。
- **应用签名最终化凭证**：`ledger.light_client.apply_finality(path,
  document, trust) -> dict`（纯库 API，参数无默认值）。`path` 为非空串，
  `document` 为上述凭证（顶层键序恰为 `finalized, tip, auth`：非布尔整数、
  64 位小写 hex 哈希、128 位小写 hex 签名），`trust` 须携带
  `audit_signers`。结构或类型错误为 `input`。随后检查点在同一把
  per-path 锁下被严格加载与完整重放（文件缺失为 `io`，已存文件解析、
  键序、摘要或重放失配为 `state`，先于凭证判定）；再验凭证：
  `key_version` 未知或按 `ledger-finality-v1` 域验签失败为 `auth`。
  凭证 `tip` 必须与本地重放 tip **逐字段相同**，`finalized` 必须命名
  重放分支的 anchor 或某一 **confirmed** 头，且不得使边界倒退（更低
  高度）或横移（同高异 hash）——tip 不符、未知/pending/已丢弃分叉目标
  或边界倒退均为 `integrity`。凭证边界与已存边界完全
  相同则**幂等**：返回当前 generation 且文件字节不动；提高边界时
  `generation + 1` 并沿用 v3 格式（与 `finalize_headers` 相同的序列化与
  哈希规则）原子换入。成功键序固定为 `ok, generation, finalized`，
  `finalized` 键序 `height, block_hash`；失败仅返回
  `{"ok": false, "error"}`、**不抛异常**且**不改变文件字节**。

- **可分页最终化历史**：`GET
  /v1/chain/finalities?after_height=&after_hash=&limit=`。参数规则与
  `GET /v1/chain/headers` 完全相同（`after_height`、`after_hash` 必填且
  单值，`limit` 可选、默认 100、范围 1–500；未知、重复或格式错误参数
  `400`，未知高度 `404`，哈希不符或锚点为 pending `409`，均无副作用）。
  `200` 文档顶层键序固定为 `anchor, finalities, next, head`：`anchor`
  键序 `height, block_hash` 且等于请求锚点；`finalities` 含锚点后至多
  `limit` 个**连续 confirmed 块**的凭证（按高度升序），每项沿用
  `GET /v1/chain/finality` 的键序 `finalized, tip, auth` 与
  `ledger-finality-v1` 签名，其中 `finalized` 指该块、`tip` 为该块的链
  描述符 S，可直接整批传给 `ledger.light_client.apply_finalities`；
  `head` 为**同一把锁**内快照生成的当前最终化凭证。若尚未到 head，
  `next` 为末项 `finalized`（可直接作为下一页的锚点），否则为 `null`；
  锚点已是 head 时 `finalities` 为空且 `next` 为 `null`。链、当前签名者
  与整个响应在同一把锁内取快照，签名或构造失败不会返回部分页面。
- **原子消费可分页最终化历史**：`ledger.light_client.apply_finality_pages(path,
  pages, trust) -> dict`（纯库 API，参数无默认值）。`pages` 为非空数组，
  元素严格遵守 `GET /v1/chain/finalities` 的键序、类型与
  `ledger-finality-v1` 签名契约（顶层键序 `anchor, finalities, next,
  head`）；`trust` 须携带 `audit_signers`。结构、键序或类型错误为
  `input`；随后检查点在同一把 per-path 锁下严格加载并完整重放（缺文件
  `io`，存量解析/键序/摘要/重放失配 `state`）；再逐页验每个凭证（含各页
  `head`）的签名，未知版本或坏签名为 `auth`。完整性规则：各页 `head`
  逐字段相同且 `head.tip` 等于本地重放 tip；首页 `anchor` 等于已存
  finalized，后页 `anchor` 等于前页 `next`；非末页 `finalities` 非空且
  `next` 等于末项 `finalized`；末页 `next` 为 `null` 并到达
  `head.finalized`（仅单页可在 anchor 已是 head 时为空）；凭证依次命名
  本地 confirmed 分支的下一个连续头，`tip` 为对应块的描述符 S——分页、
  分支、tip 或边界错均为 `integrity`。全批通过才按 v3 格式原子推进至
  `head.finalized`，`generation` 只加 1；空的 anchor-已是-head 单页幂等
  且字节不变。成功键序固定为 `ok, generation, finalized, pages,
  applied`（后二者为页数、凭证数）；失败仅返回
  `{"ok": false, "error"}`、**不抛异常**且**不改变文件字节**。

## 签名认证的增量区间协议

增量区间还可以带来源签名推送：`POST /v1/forks/sync/range/attested`。请求体为
`{"source","request_id","expires_at","anchor","blocks","tip","signature"}`：
`anchor`/`blocks`/`tip` 的结构与类型约束与普通区间完全一致（`tip` 仍为恰好四字段
的封闭摘要，逐字段严格类型），`signature` 必须是 **128 位小写十六进制**。签名覆盖
文档
`{"domain":"ledger-sync-range-v1","source","request_id","expires_at","anchor","blocks","tip"}`
（与整链签名不同的独立 domain，防止两种消息互验）：按 key 排序、
`ensure_ascii=false`、紧凑分隔符 `(",",":")` 序列化为 UTF-8 字节，取其
**SHA-256 32 字节摘要**，再用来源**当前 active 且未过期**的注册公钥做 Ed25519
验签。

- **状态码优先级（新 key）**：信封结构/类型/封闭 tip/签名格式错误 `400` →
  来源未授权（未知、已撤销或注册已过期）`403` → 请求 `expires_at` 已到 `410` →
  签名用当前公钥验不过 `403` → 锚点与当前 canonical 不匹配 `409` → 拼接 canonical
  前缀执行整链重验并核对 `tip`，失败 `400` → tip 与 canonical 或已存候选重复
  `409`。成功 `201` 返回 S（`tip_hash,height,length,status`）加 `expires_at`。
- **冻结与幂等**：成功时在**同一次原子写入**里保存拼接后的完整候选、attested
  同步记录（独立于普通区间端点的幂等命名空间）、冻结的**公钥/注册版本/签名/
  已签名 range 载荷与指纹**，以及一条 `mode="attested"` 的 `sync_received` 事件。
  同一 `source`+`request_id` 的存活记录重试**豁免授权与过期检查**，并用**冻结
  公钥**重新验签：签名错 `403`；签名通过但锚点/尾部/tip 独立重验失败（不再重新
  拼接、不依赖当前 canonical）`400`；签名有效但指纹不同 `409`；内容完全相同返回
  `200` 与首次原结果（含原 `expires_at`），即使此后来源被轮换/撤销或 canonical
  已推进——用轮换后的新公钥重签同一内容仍因冻结公钥验签失败而 `403`。
- **生命周期与重启**：采用（最长链/最小 tip_hash）、旧链已确认交易去重回池、
  pending 末块不入池、过期清理、重启调和全部沿用既有 attested 规则；未采用的
  候选随记录过期删除，并补恰好一条 `mode="attested"` 的 `sync_expired`。重启时
  用冻结公钥重验签名、重算指纹、独立重验尾部并核对存储候选恰为 canonical 前缀加
  该尾部；签名/指纹不符或已签名 tip 解析失效一律**静默丢弃**该记录（链不动、
  不产生事件），停机期间到期/失权则按既有去重规则补写 `sync_expired`。
- **查询**：该记录自然纳入 `GET /v1/forks/sync` 的 `attested`/`all` 选择与
  `(height, tip_hash, source, mode, request_id)` 排序，以及
  `GET /v1/forks/sync/history` 中 `mode="attested"` 的生命周期事件，item 形状不变。
- **命令行**：`python -m ledger.cli sync-range-attested --source ... --request-id
  ... --expires-at ... --signing-key <64 位小写十六进制私钥种子> <区间 JSON|->`；
  参数与 `sync-range` 相同（区间文档缺 `tip` 时按末块自动派生，`-` 从标准输入
  读 JSON），客户端按上述 canonical 方式本地签名；非 2xx 响应打印单行 JSON 并以
  退出码 1 结束。

## 持久化来源信任与审计

轻客户端所需的信任文档不再靠手工维护：节点持久化保存**来源信任注册表**、
**allowlist**、**来源公钥历史（source_key_history）** 与一条**只增审计事件流**，
与链、状态、候选分叉和同步记录在同一份原子快照中落盘；任何一次信任变更都与其
审计事件和公钥历史一起提交，写盘失败一并回滚。

- **注册来源**：`POST /v1/trust/sources`，请求体
  `{"source","public_key","expires_at"}`：`source` 必须是非空字符串，
  `public_key` 必须是 64 位小写十六进制（Ed25519 公钥），`expires_at` 必须是
  整数（拒绝布尔）。合法新建返回 `201` 与 `{source, public_key, expires_at,
  version, status}`，其中 `version=1`、`status=active`，并在
  `source_key_history` 中以 `source_registered` 事件号写入版本 1 公钥；同一
  来源以**完全相同**的 `(public_key, expires_at)` 重试是幂等的，返回 `200`
  与既有记录（不产生新版本或新事件，也不追加历史）；内容不同返回 `409`；
  字段非法返回 `400`。
- **轮换公钥**：`POST /v1/trust/sources/{source}/rotate`，请求体
  `{"public_key","expires_at","expected_version"}`。未知来源或已撤销来源
  返回 `404`；`expected_version` 与当前版本不符返回 `409`；成功则安装新公钥、
  保持 `active`、`version` 递增，在同一原子写入中追加 `source_rotated`
  事件并把 `{version: 新版本, public_key: 新公钥, activated_event_id: 该事件号}`
  追加到该来源公钥历史（旧公钥永久保留），返回 `200`。
- **撤销来源**：`POST /v1/trust/sources/{source}/revoke`，请求体
  `{"expected_version"}`。未知来源 `404`；版本不符 `409`；成功置
  `status=revoked` 并返回 `200`，对已撤销来源以记录版本重复撤销是幂等的
  （仍 `200`，不产生第二条事件）。已撤销来源不能再轮换，**其公钥历史原样
  保留**，以便旧 attestation 仍可离线核验。
- **allowlist 新增**：`POST /v1/trust/allowlist`，请求体
  `{"source","expires_at"}`：`source` 必须是非空字符串，`expires_at` 必须是
  非布尔整数（过去时刻合法，表示一条已过期条目）。合法新建在同一原子写入中
  追加 `allowlist_added` 事件（携带 `source`、`expires_at`）并返回 `201` 与
  `{source, expires_at}`；以完全相同内容重试是幂等的，返回 `200` 且**不追加
  事件、不产生写入**；同 source 不同 `expires_at` 返回 `409`；字段非法
  `400`。
- **allowlist 删除**：`DELETE /v1/trust/allowlist/{source}`。未知条目 `404`；
  成功在同一原子写入中删除条目并追加 `allowlist_removed` 事件（携带
  `source` 与被删条目的 `expires_at`），返回 `200` 与
  `{source, removed: true}`。删除 allowlist 条目不触及同名 trust source；
  allowlist 仅供**离线 verify**，绝不改变 `POST /v1/forks/sync` 的授权。
  过期条目**不自动删除**，verify 按既有规则返回 `expired`。
- **信任文档**：`GET /v1/trust` 返回离线验证所需的
  `{"genesis_hash","sources","allowlist","audit_signers","source_key_history"}`
  （顶层即此固定键序）：`genesis_hash` 固定
  锚定 canonical 创世块；`sources[source] = {public_key, expires_at}` 只包含
  **未过期且未撤销**的来源（`expires_at <= now` 即剔除）；持久化的
  `allowlist[source] = expires_at` 原样保留；`audit_signers` 按 `version`
  升序列出节点曾经持有的**全部**审计检查点签名公钥，每项
  `{version, public_key, activated_event_id}`，首版 `activated_event_id` 为
  `0`；`source_key_history` 是 source 到其**历史公钥**数组（数组按 `version`
  升序）的映射，每项恰为 `{version, public_key, activated_event_id}`，其中
  `version` 与 `activated_event_id` 均为非布尔正整数、`public_key` 为 64 位
  小写十六进制。注册写入版本 1（`activated_event_id` 即
  `source_registered` 事件号），轮换递增版本并以 `source_rotated` 事件号
  激活新公钥，撤销**保留全部历史**。该文档可直接作为 `ledger verify
  --trust` 的输入，其 `genesis_hash` 与 `audit_signers` 也供 `ledger
  audit-verify --trust` 使用，`source_key_history` 供离线区间导出的 attested
  核验按版本选取历史公钥。
- **审计查询**：`GET /v1/audit/events` 支持 `source`、`kind`、`cursor`、
  `limit`（默认 50，范围 1–200）过滤；数值参数必须是首位非 0 的十进制
  （`0` 合法），非法值 `400`。事件按 `event_id` 升序分页，返回
  `{items,total,next_cursor}`；`cursor == total` 返回空页，`cursor > total`
  返回 `400`，没有更多结果时 `next_cursor` 为 `null`。
- **哈希链与检查点**：每个事件额外携带两个链接字段 `prev_hash` 与
  `event_hash`。首条事件的 `prev_hash` 是 64 个 ASCII `0`，之后每条取前一条的
  `event_hash`；`event_hash = sha256(prev_hash 的 ASCII 字节 || 事件去掉
  prev_hash/event_hash 两字段后、key 排序的紧凑 UTF-8 JSON)`（`sort_keys`、
  `separators=(",",":")`、`ensure_ascii=False`）。快照另存顶层
  `audit_checkpoint = {event_id, event_hash}` 钉住日志链头，空流为
  `{0, "0"*64}`；检查点同样参与同代快照冲突比较。事件追加与哈希链接、检查点
  在同一把锁内一次原子落盘，写盘失败连同事件一起回滚，重试不重不漏。
- **审计导出**：`GET /v1/audit/export` 的 `cursor`/`limit` 分页语义与
  `/v1/audit/events` 完全一致（但面向整条日志、不接受 source/kind 过滤）；
  任何查询参数重复出现返回 `400`。返回
  `{items,total,next_cursor,anchor_hash,checkpoint,checkpoint_auth}`：`items`
  按 `event_id` 升序且每个事件含 `prev_hash`/`event_hash`；`anchor_hash` 是
  本页首条事件的前一哈希（`cursor=0` 为 64 个 0；`cursor=total` 的空末页为
  当前链头），`checkpoint` 是导出时刻的日志检查点，每页都带；
  `checkpoint_auth = {key_version, signature}`：把
  `{genesis_hash, checkpoint, key_version}` 序列化为 key 排序、紧凑分隔符的
  UTF-8 JSON，取其 SHA-256 32 字节摘要，再用**当前审计签名私钥**做 Ed25519
  签名。同一份导出的各页钉住同一检查点、携带同一 `checkpoint_auth`。
- **检查点签名密钥轮换**：节点首次创建时生成版本 1 的 Ed25519 审计检查点
  密钥（首版在事件 `0` 激活）。`POST /v1/audit/signer/rotate` 请求体
  `{"private_key", "expected_version"}`，其中 `private_key` 为 64 位小写
  十六进制私钥种子（公钥由其推导）；私钥非法/字段缺失 `400`，
  `expected_version` 与当前版本不符 `409`；成功 `200` 返回
  `{"version","public_key"}`，在同一原子落盘内追加一条
  `audit_signer_rotated` 事件（携带新版本号与新公钥）、切到新密钥，并永久
  保留历史公钥。此后每次审计变化都以当前私钥签名当前检查点。
- **事件覆盖**：信任变更记录 `source_registered` / `source_rotated` /
  `source_revoked`；节点间同步记录 `sync_received`（接收）、
  `sync_adopted`（候选被采用，按来源同步记录逐条登记）与 `sync_expired`
  （过期清理，包含已采用上链的 tip——只留审计记录、canonical 链不动）；
  审计检查点密钥轮换记录 `audit_signer_rotated`（携带新版本号与新公钥，
  其事件 id 即新密钥的 `activated_event_id`）；keyless allowlist 的新增与
  删除记录 `allowlist_added` / `allowlist_removed`（均携带 `source` 与
  `expires_at`）；节点托管检查点历史接口的访问记录 `history_access`
  （载荷键序 `action,trust_head,history_head`，`action` 为
  read/update/export，无头时为 `null`）；持久分权历史凭据的轮换/撤销记录
  `history_credential_changed`（载荷为 `action` 后接凭据响应四字段
  `version,token_hash,permissions,status`，`action` 为 rotate/revoke，
  首版版本为 0）。事件一旦写入永不删除：候选
  **采用或过期之后仍可按 source/kind 分页查询**。
- **恢复语义**：信任注册表、allowlist、来源公钥历史与审计流是权威配置而非
  可丢弃缓存，快照恢复时逐项严格校验（公钥格式、整数、正版本号、合法状态；
  allowlist 条目键唯一且 `expires_at` 为非布尔整数；`event_id`
  必须从 1 起连续无重复；每条 `prev_hash`/`event_hash` 必须重算一致，
  `audit_checkpoint` 必须钉住真实链头，`allowlist_added`/`allowlist_removed`
  事件也必须携带非空 `source` 与整数 `expires_at`）。任一项损坏，或同代
  快照内容冲突，都抛 `StateRecoveryError`，绝不静默新建。来源公钥历史同样
  严格校验：持久化的 `source_key_history` 每项必须结构合法（版本自 1 起
  稠密、`activated_event_id` 升序、公钥为 64 位小写 hex），并与注册表记录
  及审计事件完全一致——版本 1 必须由该来源的 `source_registered` 事件
  （public_key/version 相符）激活，之后每个版本由 id/version/public_key
  完全对应的 `source_rotated` 事件激活，撤销后不得再轮换，注册表当前
  version/public_key 必须等于历史最新条目；历史结构错误、版本不稠密、激活
  事件号或公钥对不上，都抛 `ledger.store.StateRecoveryError(path, reason)`。
  持久分权历史凭据同样严格校验：顶层 `history_credential` 区段（存在时）
  必须恰为 `{version,token_hash,permissions,status}`（版本为非布尔非负整数、
  `token_hash` 为 64 位小写 hex、权限为 read/update/export 的非空无重子集且
  按该顺序、status 为 active/revoked），且必须与重放全部
  `history_credential_changed` 事件得到的凭据**逐字一致**——首次 rotate
  创建版本 0，之后每次 rotate 版本恰 +1，revoke 保留版本/哈希/权限仅置
  revoked，动作或载荷非法、版本不连续、撤销后再撤销、区段与事件不符都抛
  `StateRecoveryError(path, reason)`；该区段也参与同代快照冲突比较。
  写于该特性之前、没有 `source_key_history` 区段的旧快照不强制迁移写盘：
  恢复时在内存中由注册表与审计事件重建（同代冲突判定、generation 均不受
  影响），下一次普通写盘自然持久化。审计检查点签名者同样严格校验：
  存储的私钥必须能推导出对应公钥，签名者历史版本必须自 1 起连续、首版在
  事件 0 激活、激活事件 id 升序，当前签名者必须等于最新历史条目，版本 1
  之后的每个版本都必须由一条 id/version/public_key 完全对应的
  `audit_signer_rotated` 事件激活（不得有孤立事件），并用存储私钥对恢复出
  的检查点重新签名验证。任一错配，或同代快照在这些区段（含检查点与签名者
  历史）上内容冲突，都抛出 `ledger.store.StateRecoveryError`，绝不静默新建
  链。写于哈希链/检查点认证特性之前的**无签名旧快照**（无签名者区段）只在
  唯一胜者选定后一次性生成版本 1 密钥、补齐整链与检查点并原子保存，再次
  重启不再改写；停机期间到期/授权失效记录补写的 `sync_expired` 也在同一
  修复中完成链接。补写只在同代冲突判定之后对唯一胜出快照执行，因此冲突
  比较始终基于持久化内容，重放恢复也不会改变判定。

## 账户状态 Merkle 证明

每个**已确认**账户在状态树中按 `account` 升序占一个叶子，叶子与树根定义为：

```
leaf = sha256(utf8(canonical_json({"account": a, "balance": b, "confirmed_transactions": T})))
```

其中 `canonical_json` 用 `json.dumps(..., sort_keys=True, ensure_ascii=False,
separators=(",", ":"))` 序列化（三个键固定按字母序、紧凑分隔、非 ASCII 原样
输出），`T` 是该账户已确认交易 id 的**链上原序列表**（块内按 tx_id 升序），
`b` 是已确认余额。树根沿用交易 Merkle 的配对规则：每层
`sha256(left_hex + right_hex)`，奇数节点与自身配对，空账户集根为
`sha256(b"")`。叶子顺序只由 `account` 升序决定。

- **状态根**：`GET /v1/state/root` 返回
  `{state_root, height, block_hash, account_count}`，锚定**最高块**。当最高块
  为 pending 时（状态尚未最终化）返回 `404`；此时已确认账户集本身不变，但
  不对外发布锚点。
- **历史高度状态根**：`GET /v1/state/root/{height}` 返回与无 height 接口
  **完全相同**的四个字段，但状态只从创世重放到该已确认块（canonical 已确认
  前缀）。`height` 必须是无符号十进制且无前导零（`0` 本身合法）；未知高度、
  非 canonical 高度或该块为 pending 时返回 `404`。历史视图是只读重放：不计入
  pending 收入，也不改变当前索引、余额与快照。
- **账户证明**：`GET /v1/accounts/{account}/proof` 返回账户三元组
  `{account, balance, confirmed_transactions}` 加上
  `{index, state_root, height, block_hash, siblings}`：`index` 是账户在
  account 升序中的 0-based 位置；`siblings` 自叶向根排列，每项
  `{direction: left|right, hash}`（64 位小写十六进制，direction 表示兄弟节点
  相对路径节点的方位）。最高块 pending 或账户不在已确认账户集时返回 `404`。
  可选查询参数 `?height=H` 按同样严格格式把 proof 锚定到历史已确认块：缺省
  仍锚定最高已确认块；`height` 是唯一允许的查询参数，非法、重复或未知参数
  返回 `400`，锚点未知/非 canonical/pending
  返回 `404`，账户在该历史状态不存在也是 `404`。成功 proof 的
  `height/block_hash/state_root/index/siblings` 全部对应 H，
  `confirmed_transactions` 保持链上原序。
- **离线验证**：`ledger.crypto.verify_account_proof(proof, expected_root,
  expected_height, expected_hash) -> bool` 从 proof 的账户三元组**重算
  leaf**，沿 siblings 重算到根，并核对：重算根同时等于 proof 的
  `state_root` 与 `expected_root`，`height == expected_height`，
  `block_hash == expected_hash`。任何非法 hash、非法 direction、非法/越界
  index、被篡改的 leaf（balance/account/T 任一不符）或锚点不符都返回
  `False` 而不抛异常；奇数层自我配对的幻像槽位（左兄弟等于当前节点）也判为
  非法。签名无需改变即可验证历史 proof——传入该高度的 root/height/block_hash
  即可。
- **快照与恢复**：每次原子快照在 `state.state_root` 记录已确认账户树根（与
  链、generation 同一文档）。恢复时只对**唯一胜出快照**在同代冲突判定之后
  按该快照记录的初始余额重算状态根；重算值与记录不符即抛
  `ledger.store.StateRecoveryError(path, reason)`，绝不静默改写或新建链。
  同代孪生快照若 `state_root` 不同也属于冲突。该特性之前的旧快照（无
  state_root 字段）仍可加载。
- **CLI**：`state-root [--height H]` 与 `state-proof <account> [--height H]`
  两个子命令，`--height` 缺省时行为与输出完全不变；提供时逐字转发对应历史
  高度接口的单行 JSON 响应（含非 2xx 错误体）。

## 交易索引

`GET /v1/index/transactions` 在**已确认链**上提供交易索引（不含 pending 末块）。
查询参数 AND 组合：`tx_id`（64 位小写十六进制）、`account`（匹配 from 或 to）、
`height`、`limit`、`cursor`；数值参数必须是首位非 0 的十进制（`0` 本身合法），
`limit` 默认 50、范围 1–200，`cursor` 默认 0，任何非法值返回 `400`。结果按
`(height, index, tx_id)` 升序，`index` 是交易在块内从 0 起的位置，与 Merkle
proof 的 index 一致。返回 `{items, total, next_cursor}`：`total` 是过滤后的总数，
`cursor` 等于总数时返回空页、大于总数返回 `400`；`next_cursor` 是下一页偏移整数，
没有更多结果时为 `null`。每个 item 含
`{tx_id, height, block_hash, index, from, to, amount}`。

## 交易回执

`GET /v1/transactions/{tx_id}` 返回单笔交易的回执。`tx_id` 必须恰好是 64 位
**小写**十六进制（大写、长度不符或含其他字符均按非法处理）；非法 id 或交易
不存在都返回 `404`。查询只面向 canonical 链与待处理集合，**不暴露候选分叉中的
交易**。成功返回 `200` 与固定九字段（字段集与顺序固定）：

```
{tx_id, from, to, amount, signature, status, height, block_hash, index}
```

- `status` 只能是 `pending` 或 `confirmed`。
- **内存池中的交易**：`pending`，且 `height`、`block_hash`、`index` 均为
  `null`。
- **已打包但未确认（pending 末块）的交易**：`pending`，返回该待定块的
  `height`、`block_hash` 与块内从 0 起的 `index`（与块内按 tx_id 升序的顺序、
  Merkle proof 的 index 一致）。
- **已确认交易**：`confirmed`，字段锚定 canonical 上的已确认块。

回滚后交易恢复内存池形态（`height`/`block_hash`/`index` 回到 `null`）；分叉
采用使交易进入 canonical 时，旧链独有交易回池、被新链包含的交易锚定到新块，
回执始终反映**最终**状态而不读取旧链缓存。回执一律由存储的签名交易重算
`tx_id` 并严格复核类型：`from`/`to`/`signature` 为非空字符串、`amount` 为正
整数（拒绝布尔等非整数）。回执不新增任何权威副本：重启时从 canonical 链、
pending 集合与待定尾块重建，快照损坏或冲突仍按既有规则抛
`StateRecoveryError`。查询与提交、打包、确认、回滚、采用、清理共用同一把锁，
只反映已持久化的状态。

## 批量 Merkle 证明

在单笔 `GET /v1/blocks/{height}/proof/{tx_id}` 之外，提供一次取多笔的批量接口：

- **请求**：`POST /v1/blocks/{height}/proofs`，请求体必须是 JSON 对象且**只含**
  `tx_ids` 一个键：非空数组，元素两两互异，每个元素都是恰好 64 位**小写**
  十六进制字符串。JSON 解析失败、不是对象、键缺失或有额外键、`tx_ids`
  类型错误、空数组、元素重复或格式不符（含大写、长度错、非字符串）一律
  `400`，且不改变任何状态（不落盘、不推进 generation）。
- **状态码**：`height` 必须是无前导零的非负十进制（`0` 合法）；高度未知或
  任一请求交易不在该块返回 `404`；区块仍为 pending 返回 `409`（与单笔
  proof 相同）。成功返回 `200`。
- **响应**：顶层键序固定为
  `{height, block_hash, merkle_root, transaction_ids, proofs}`。
  `transaction_ids` 是该块**全部**交易叶子，按 tx_id 升序；`proofs` 只覆盖
  请求的交易子集，按 tx_id 字典序（升序）排列，与请求中的顺序无关。每项
  键序为 `{tx_id, index, siblings}`：`index` 是该 tx_id 在
  `transaction_ids` 中的 0-based 位置；`siblings` 自叶向根排列，每项键序
  `{direction, hash}`，`direction` 仅 `left`/`right`（表示兄弟节点相对路径
  节点的方位），`hash` 为 64 位小写十六进制。配对规则沿用
  `sha256(left_hex + right_hex)` 与奇数节点自配。
- **离线校验**：`ledger.crypto.verify_merkle_proof_bundle(bundle,
  expected_block_hash, expected_merkle_root) -> bool`。严格检查顶层/各项的
  **键序与键集**（缺失或额外键、键序错误即 False）、原始类型（height 为
  非布尔非负整数，hash 为 64 位小写 hex，index 为非布尔整数等）、
  `transaction_ids` 非空/唯一/升序并据此**直接重算 Merkle 根**、proofs
  非空且 tx_id 唯一升序、每个 `index` 恰好等于该 tx_id 在
  `transaction_ids` 中的位置且不越界、路径深度与 index 相容、逐跳方向与
  index 一致（偶数位必为左孩子、奇数位必为右孩子，左兄弟等于当前节点的
  幻像自配槽位判非法），最终重算根同时等于束内 `merkle_root` 与
  `expected_merkle_root`，`block_hash == expected_block_hash`。任何缺失/
  额外键、非法方向或哈希、越界 index、叶子/路径/根/区块哈希被篡改都返回
  `False`，全程不抛异常。
- **CLI**：`proofs HEIGHT TX_ID...`（一个或多个 tx_id）向该接口 POST
  `{"tx_ids":[...]}`，输出与接口字段、键序一致的单行 JSON；任何非 2xx
  响应（含连接失败）退出码为 1。

## 离线轻客户端验证

不持有链状态、也不连接服务端的客户端，可以凭一份**证明束**（bundle）与本地
**信任文档**（trust）离线核对响应：

- **bundle**：`{source, expires_at, response, candidate, proofs[, signature]}`。
  `expires_at` 是 Unix 秒；`candidate` 是自创世块起的完整块数组（也接受现有
  导出五字段文档）；`proofs` 为 `{height, proof}` 列表，`proof` 即
  `/proof/` 接口返回的 `{height, tx_id, index, merkle_root, block_hash,
  siblings}` 文档；`signature` 可选，为 Ed25519 签名的十六进制。
  可选的**账户状态扩展**再带四个字段——`state_root`、`state_height`、
  `state_block_hash`、`state_proofs`——要么全部省略（历史格式），要么全部
  提供；`state_proofs` 为非空列表，每项仅含 `{height, proof}`，`proof` 即
  `/v1/accounts/{account}/proof` 返回的 `{account, balance,
  confirmed_transactions, index, state_root, height, block_hash, siblings}`
  八字段文档（缺失、额外或类型错误都判 `input`）。
- **trust**：`{genesis_hash, sources, allowlist}`（`GET /v1/trust` 还会带
  `audit_signers` 与 `source_key_history`，轻客户端束验证忽略这两个额外
  字段）。`genesis_hash` 锚定创世块；
  `sources[source] = {public_key, expires_at}`；
  `allowlist[source] = expires_at`。
- **来源与签名**：`source` 必须受信（在 `sources` 或 `allowlist` 中）且未过期
  （束、来源、allowlist 三处的 `expires_at` 逐一检查，`<= now` 即过期）。
  受信且有公钥的来源**必须**验签：签名覆盖
  `SHA256(bundle 去掉 signature 后排序紧凑 UTF-8 JSON)`，再做 Ed25519 验签；
  无公钥来源只有在 `allowlist` 中且束**不带签名**时才可接受。
- **重算链**：从 `genesis_hash` 锚定的创世块起，逐块核对连续高度与 `prev_hash`、
  重算每笔交易的 `tx_id` 并验证其 Ed25519 签名、`tx_id` 全链唯一且块内升序、
  重算 Merkle 根与 `block_hash`，且 pending 块只能位于链尾。
- **核对 response 与 proofs**：`response` 中出现的 `tip_hash/height/length/
  status` 必须与重算链的链尾描述符 `S` 完全一致（一个都不出现则无法绑定，拒绝）。
  每个 proof 必须唯一（同 `height`+`tx_id` 不得重复），其 `tx_id`、`height`、
  `index` 与区块字段（`block_hash`、`merkle_root`）必须与候选链中的块一致，
  Merkle 路径按现有 `verify_merkle_proof` 规则验证；**pending 链尾禁止出 proof**。
- **核对状态扩展**（存在时）：`state_height` 必须对应候选链中的**已确认**块
  且 `state_block_hash` 相同（未知高度、pending 或哈希不符判 `integrity`）；
  每项的 `height`、每个 proof 文档的 `height/state_root/block_hash` 都必须与
  锚点一致。随后按该高度 confirmed 交易的账户**升序集合**核对每个 proof 的
  `account` 与 `index`（不在集合或位置不符判 `proof`），`height`+`account`
  不得重复，最后逐条交给 `crypto.verify_account_proof` 以束上的
  `state_root/state_height/state_block_hash` 为锚验证（非法方向/哈希、伪造
  leaf、非法自配对、siblings 畸形均判 `proof`）。

成功返回 `{ok: true, source, S, verified_tx_ids}`（`verified_tx_ids` 为按
tx_id 升序的已验证交易列表）；带状态扩展的束成功时另含按 account 升序的
`verified_accounts`，不带扩展的束返回形状与历史完全一致。失败返回
`{ok: false, error}`，`error` 仅取
`input` / `auth` / `expired` / `integrity` / `proof` 五类：

| error | 含义 |
| --- | --- |
| `input` | bundle/trust 结构或字段类型不合法（含非 64 位十六进制公钥、布尔数值） |
| `auth` | 来源不受信、受信来源缺签名，或 allowlist 来源带了无法核对的签名 |
| `expired` | 束或信任条目已过期 |
| `integrity` | 签名错误、链重算不一致（创世块/prev_hash/tx_id/签名/Merkle/block_hash）、response 与链尾不符，或状态锚点未知/pending/哈希不符 |
| `proof` | proof 重复、字段与区块不一致、Merkle 路径无效或指向 pending 链尾；状态 proof 的账户不在锚点集合、index 不符、`height`+`account` 重复或 `verify_account_proof` 失败 |

## 区间导出的离线校验

不连接服务端也能核验一份已接收增量区间的导出文档：
`ledger.light_client.verify_range_export(document, expected_anchor, trust,
now=None) -> dict` 直接接收已解码的
`GET /v1/forks/sync/range/export` 响应、调用方钉住的
`expected_anchor = {height, block_hash}` 与本地信任文档。CLI 入口为
`python -m ledger.cli verify-range --export FILE|- --trust TRUST
--anchor-height H --anchor-hash HASH`（`-` 从标准输入读），不发起任何网络
请求。

- **结构（input）**：document 顶层键序必须恰为 `source, request_id, mode,
  expires_at, anchor, blocks, tip, attestation`；`mode` 仅取
  `plain`/`attested`；`anchor`/`expected_anchor` 为 `{height,
  block_hash}`（非布尔非负整数、64 位小写十六进制）；`tip` 恰为
  `{tip_hash, height, length, status}`；attested 的 `attestation` 恰为
  `{public_key, version, signature}`（64 位十六进制公钥、正整数版本、
  128 位十六进制签名）；trust 的 `sources`/`allowlist` 形状同离线
  verify，可选的 `source_key_history` 为 source 到非空升序数组的映射，
  每项恰为 `{version, public_key, activated_event_id}`（版本自 1 起稠密、
  `version`/`activated_event_id` 为非布尔正整数、公钥 64 位小写 hex、
  激活事件号严格升序），任何形状/类型不符都返回 `input`。文件不可读、
  JSON 解析失败或锚点参数非法同样返回 `input`。
- **授权（auth）**：`plain` 要求来源在 `allowlist` 中且
  `attestation` 为 `null`。`attested` 分两种情形：信任文档**携带**
  `source_key_history` 时，按 attestation 的 `version` 从该来源的历史
  公钥数组中选取公钥——来源不在映射中、版本号不是其稠密版本之一、或
  attestation 的 `public_key` 与该历史公钥不一致，都返回 `auth`（来源
  是否已轮换/撤销、是否仍在 `sources` 中均不影响，旧公钥签的旧导出仍可
  核验）；信任文档**不带** `source_key_history` 时沿用旧规：来源必须在
  `trust.sources` 中且 attestation 的 `public_key` 与钉住公钥一致。
- **期限（expired）**：文档的 `expires_at` 必须晚于 `now`；`plain`
  另查对应 allowlist 条目的期限，旧规（无历史映射）下 `attested` 另查
  `sources` 条目的期限；携带历史映射时只查文档自身的 `expires_at`
  （历史来源没有当前期限），`<= now` 即过期。
- **完整性（integrity）**：`expected_anchor` 必须严格等于文档的
  `anchor`；随后从该锚点独立重验交付尾部（高度自 `anchor.height + 1`
  连续、`prev_hash` 链接、逐笔 tx_id 与 Ed25519 签名、tx_id 全尾唯一且
  块内升序、Merkle 根与区块哈希重算、pending 只能在末块；原始值类型
  缺陷仍归 `input`），闭合 `tip` 摘要必须等于重算结果；attested 再用
  选中的公钥（历史公钥或旧规钉住公钥）验证 `ledger-sync-range-v1`
  canonical JSON 摘要的 Ed25519 签名，签名验不过为 `integrity`。

成功返回固定键序 `{ok, source, request_id, mode, anchor, tip,
verified_tx_ids}`（`verified_tx_ids` 为尾部全部交易按 tx_id 升序），
失败返回 `{ok: false, error}` 且 `error` 仅取
`input`/`auth`/`expired`/`integrity`；任何畸形输入都不抛异常。CLI
成功退出 0、失败退出 1。

## 多页增量区间的离线连续校验

一份较大的增量可能由多页导出文档按顺序组成。
`ledger.light_client.verify_range_exports(documents, expected_anchor, trust,
now=None) -> dict` 接收一个**非空数组**，每个元素都是一份八键顺序固定
（`source, request_id, mode, expires_at, anchor, blocks, tip,
attestation`）的区间导出文档，并把它们当作一条连续链逐页复验。

- **逐页复验**：每一页都独立套用单页 `verify_range_export` 的全部
  input/auth/expired/integrity 规则（结构、授权、期限、尾部重算、tip 摘要、
  attested 签名）。
- **锚点链接**：首页的 `anchor` 必须严格等于调用方钉住的
  `expected_anchor = {height, block_hash}`；此后每页的 `anchor` 必须严格
  等于**前一页闭合 tip** 的 `{height, block_hash}`。断锚、高度跳高或分叉
  都归 `integrity`。
- **跨页交易唯一**：tx_id 在整批范围内唯一（不仅是页内/块内），跨页重复
  归 `integrity`。
- **pending 只许末页**：任何一页（无论是否最后一页）的非末块为 pending 仍是
  该页的 `integrity`；此外若某页以 pending 收尾而其后还有页面，则整批归
  `integrity`——pending 之后不得再交付区块。

成功返回固定键序 `{ok, anchor, tip, pages, verified_tx_ids}`：`anchor` 为
首页钉住的锚点，`tip` 为**末页**的闭合 tip，`pages` 为页数（N），
`verified_tx_ids` 为全部页面交易按 tx_id 升序。失败返回
`{ok: false, error}`，`error` 仅取 `input`/`auth`/`expired`/`integrity`；
数组为空、元素不是对象、锚点/trust 形状非法等均为 `input`，任何畸形输入都
不抛异常。

CLI 入口为 `python -m ledger.cli verify-range-batch --exports FILE|-
--trust TRUST --anchor-height H --anchor-hash HASH`：`FILE` 读取导出文档的
JSON 数组，`-` 从标准输入读取；锚点参数钉住首页。成功打印单行
`{"ok":true,"anchor":{...},"tip":{...},"pages":N,"verified_tx_ids":[...]}`
退出 0；任何核验失败、文件不可读、JSON 解析失败或锚点参数非法均打印
`{"ok":false,"error":"..."}` 退出 1。

### 持久化区间检查点 `advance`

`ledger.light_client.advance(path, docs, trust, anchor, now) -> dict` 在
`verify_range_exports` 之上把每批**已核验**的增量落盘为一个可继续的检查点
文件（纯库 API，verify-range 系列 CLI 不变）：

- `now` 必须是**非布尔、非负整数**；`anchor` 首次使用 `path` 时必须给合法的
  `{height, block_hash}`，之后可传 `None`（从已存 tip 继续）或已存 tip 的
  `{height, block_hash}`。核验逻辑与 `verify_range_exports` 完全一致。
- 文件为单个紧凑 UTF-8 JSON 文档（非 ASCII 不转义），顶层键序固定为
  `generation, anchor, tip, context, state_hash`，末尾恰好一个换行；
  `generation` 从 **1** 起每次成功 +1，`context` 键序固定为
  `verified_at, trust, documents, verified_tx_ids`，`state_hash =
  SHA256(其余字段 canonical_json 字节)`（`sort_keys`、紧凑分隔符、
  `ensure_ascii=False`）。
- 同一 `path` 共用一把锁，临时文件 fsync 后 `os.replace` 原子换入；**核验
  失败不增代、不改动文件**。成功在 `verify_range_exports` 结果末尾追加
  `generation`。
- 每次推进先严格加载既有检查点：校验顶层/context 键序、字段类型、重算
  `state_hash`，并按 context 的 `verified_at` 用其保存的 `trust` 与
  `documents` 重放（必须复现 anchor/tip/verified_tx_ids）。任何失配归
  `state`，且**禁止截断或重建**该文件。
- 失败只返回 `{ok:false,error}`，`error` 仅取
  `input`/`auth`/`expired`/`integrity`/`state`/`io`：参数畸形为 `input`，
  批次核验沿用四类，已存检查点失配为 `state`（JSON 解析失败也是 `state`），
  文件无法读/写/原子替换为 `io`。

### 检查点代际历史 `path + ".history"` 与 `history`

每次成功的 `advance` 还会在同一事务里维护 `path + ".history"` 侧车文件
（纯库 API，其余入口不变），序列化规则与检查点完全相同（紧凑 UTF-8、
非 ASCII 不转义、末尾恰好一个换行、临时文件 fsync 后 `os.replace`）：

- 顶层键序固定为 `v, base, records, head`，`v = 1`；`base` 键序
  `generation, hash`，命名第一条留存记录**之前**的代；每条记录键序
  `checkpoint, prev, hash`，其中 `checkpoint` 即落盘的原五键检查点文档。
- 记录代号从 `base.generation + 1` 起连续；首条 `prev = base.hash`，之后
  取前一条的 `hash`；`hash = SHA256(ASCII(prev) ‖ canonical_json(checkpoint))`，
  `head` 为末条记录的 `hash`，均为 64 位小写 hex。
- 全新路径从 `base = {0, Z}`（Z = 64 个 0）开始；已存在的 g 代检查点
  若没有侧车，视为 `base = {g-1, Z}` 且该检查点即首条记录，之后推进时
  追加。侧车末条记录必须复现当前检查点，否则为 `state`。
- 两个文件共用同一把按路径锁作为一个事务写入；任一写失败归 `io` 并
  **尽力补偿**回原始字节（补偿失败后的读取会自然报 `state`）；不保证
  崩溃/断电时两文件的原子性。

`ledger.light_client.history(path, generation=None, keep=None) -> dict`
查询或裁剪侧车。`generation` 与 `keep` 互斥，且都必须是**非布尔正整数**。
加载时逐代重放（形状、`state_hash`、context 重放、锚点连续性），任何
篡改归 `state`；侧车缺失或不可读写归 `io`；参数畸形归 `input`；查询的
目标代不在留存记录中也归 `state`。成功按键序
`ok, base, record, head, kept` 返回：

- 查询（默认）：`record` 为指定代（缺省末代）的记录，`kept = null`；
- 裁剪（`keep=n`）：仅保留末 `kept = min(n, 原记录数)` 条，`record` 为
  末项；没有删除任何记录时侧车字节**原样不动**，否则 `base` 推进为末条
  被删记录的 `{generation, hash}` 并重写侧车——检查点文件本身永不被
  裁剪改动。

### 检查点历史的签名分页导出与离线校验

在 `history` 查询/裁剪之外，留存的代际历史还可以签名分页导出，供完全
离线的一方校验：

`ledger.light_client.export_history(path, key, after=None, limit=50,
trust_path=None) -> dict`

- `key` 必须是 **64 位小写十六进制**的 Ed25519 私钥种子；公钥由其推导。
- `after` 为 `None`（从 `base` 之后起始）或**非布尔非负整数**，且必须
  命中 `base.generation` 或某个**非末代**留存代；页从该游标之后的下一条
  记录开始。`limit` 必须是 **1–200 的非布尔整数**（缺省 50）。
- 导出在与 `advance`/`history` 相同的按路径锁内严格重载检查点与侧车
  （形状、`state_hash`、逐代重放、锚点连续），侧车末条记录必须复现当前
  检查点。成功返回固定键序 `base, records, next, head, checkpoint,
  auth`：`base`/`records`/`head` 即侧车文档（嵌套键序与既有一致），
  `records` 非空；`checkpoint` 为落盘的五键检查点（与末条记录的检查点
  逐字相同）；`next` 在其后还有页时取**本页末代代号**，否则为 `null`
  （末页恰好取尽留存记录，不产生空尾页）。
- `auth` 键序为 `public_key, signature`：对**去掉 `auth` 后的整页文档**
  按 README canonical_json（`sort_keys`、紧凑分隔符、
  `ensure_ascii=False`）序列化为 UTF-8 字节，取 SHA-256 32 字节摘要，再
  用 `key` 做 Ed25519 签名（十六进制）。
- 失败返回 `{ok:false,error}`：参数畸形（path/key/after/limit/trust_path）
  为 `input`，侧车或信任日志缺失、文件不可读写为 `io`，检查点/侧车/信任
  日志损坏或游标无命中（含指向末代）为 `state`。
- 给 `trust_path` 时（一份持久签名者日志，见下节）：导出先在该日志自己的
  按路径锁内**严格加载**（缺失为 `io`，任何形状/链接/证书失配为
  `state`），再在**下一授权边界前截断**——从游标起保留最长的、其各检查点
  `verified_at` 对应同一把有效 key 的前缀；首个越界记录不进入本页，
  `next` 取本页末代代号（非 null）使下一页从该处继续，恰好取尽留存尾部
  仍以 `null` 收口。页内全程必须有同一把有效 key，且种子 `key` 推导出的
  公钥必须等于它；首条记录处于撤销/首激活前窗口，或页公钥未知/已撤销，为
  `auth`。不给 `trust_path` 时行为与旧版完全一致。

`ledger.light_client.verify_history(pages, public_key) -> dict` 离线
校验按顺序排列的导出页：

- `pages` 必须是**非空数组**，`public_key` 必须是 64 位小写十六进制
  Ed25519 公钥。每页顶层键序必须恰为
  `base, records, next, head, checkpoint, auth`，嵌套文档键序/类型沿用
  检查点与侧车规则（非布尔整数、64 位小写 hex 等），任何形状/类型不符
  为 `input`。
- **信任（auth）**：每页 `auth = {public_key, signature}`（公钥 64 位
  hex、签名 128 位 hex），其公钥必须与钉住的 `public_key` 相同；签名按
  导出端同样的去 auth canonical_json 摘要验签，公钥不符或签名验不过为
  `auth`。
- **跨页一致与链接（integrity）**：各页的 `base`、`head`、`checkpoint`
  与公钥必须相同；记录代号自 `base.generation + 1` 起跨页连续，每条
  `prev` 必须等于前一条记录的 `hash`（首页首条接 `base.hash`），每条
  `hash = SHA256(ASCII(prev) ‖ canonical_json(checkpoint))` 重算一致；
  非末页的 `next` 必须等于其末代代号且下一页恰好续接，缺页、重页、乱页
  或跨页断链均拒绝。
- **检查点重放**：每条记录的检查点都重算 `state_hash` 并按其 context 的
  `verified_at`/trust/documents 重放，复现 anchor/tip/verified_tx_ids，
  相邻检查点锚点连续；任一不符为 `integrity`。
- **末页封闭**：仅末页允许 `next = null`；末页末项记录的 `hash` 必须
  等于 `head`，其 `checkpoint` 必须等于各页共享的 `checkpoint`。

成功返回 `{"ok": true}`；失败返回 `{ok:false,error}`，`error` 仅取
`input`/`auth`/`integrity`，任何畸形输入都不抛异常。

### 检查点历史的签名者轮换/撤销校验

`ledger.light_client.verify_history_trust(pages, trust, root) -> dict`
在 `verify_history` 的页面规则不变的前提下，用一份由根密钥 `root` 锚定
的签名者授权/撤销日志认证各页，因此**各页 `auth.public_key` 可以不同**。

`trust` 必须是对象，顶层键序恰为 `root, records, head`：

- `root` 为 64 位小写 hex 的 Ed25519 公钥，且必须与参数 `root` 完全相等；
- `records` 为**非空数组**，每项键序恰为 `at, key, status, prev,
  signature`：`at` 是**非布尔正整数**且全表**严格递增**；`key`、`prev`
  为 64 位小写 hex；`status` 仅取 `active`/`revoked`；`signature` 为
  128 位小写 hex；
- 链接：首项 `prev` 为 64 个 0，其后每项 `prev` 取**前一项完整
  canonical_json**（`sort_keys`、紧凑分隔符、`ensure_ascii=False`）的
  SHA-256；`head` 取**末项同法哈希**；
- 证书签名：每项的 `signature` 是用 `root` 对**去掉 `signature` 后的该
  项 canonical_json 的 SHA-256 摘要**做出的 Ed25519 签名。

授权语义：`active` 自 `at` 起授权 `key` 直至下一项，`revoked` 自 `at`
起撤销该键直至后续 `active`（以不晚于某时刻 `verified_at` 的最后一项
为准）。对每一页，取其全部记录检查点的 `verified_at`：这些时刻对应的
有效 key（无有效 key 时为 `null`）必须**完全一致**——页面跨越任一授权
边界（轮换到另一把 key，或进入/离开撤销窗口）即为 `integrity`；若整页
都无有效 key，或页面 `auth.public_key` 与该有效 key 不符，则为 `auth`。
随后用该有效 key 对**去 auth 的整页 canonical_json 摘要**验签。

页面本身的形状/嵌套键序类型、共享 `base`/`head`/`checkpoint`、记录
代号连续、`prev`/`hash` 重算、`next` 游标跨页接续、检查点重放（含锚点
连续）与末页封闭，全部沿用 `verify_history` 原规则。

成功返回 `{"ok": true}`；失败返回 `{ok:false,error}` 且不抛异常：

- `input`：trust/记录/root 参数或页面的缺键、多键、键序错、类型或 hex 错；
- `auth`：`root` 与参数不符、证书签名或页面签名验不过、key 未知或已撤销；
- `integrity`：`at` 不严格递增、`prev`/`head` 错、跨授权边界，以及记录
  链/分页/检查点重放等原 `verify_history` 的 integrity 错误。

### 持久签名者日志 `history_trust`

`ledger.light_client.history_trust(path, root_seed=None, at=None, key=None,
status=None) -> dict` 在一个独立文件里维护上面那份签名者授权/撤销日志，
使检查点历史的签名者轮换不依赖任何在线服务。

**读取**：只给 `path`（其余四项缺省）时，严格加载并返回
`verify_history_trust` 契约的 `{root, records, head}` 文档（沿用其键序、
记录形状、`prev`/`head` 链接与根证书签名规则）。日志缺失为 `io`，文件
存在但任何形状/链接/证书损坏为 `state`。

**追加**：更新时 `root_seed`/`at`/`key`/`status` **四项必填**，缺一个或
多一个都是 `input`：

- `root_seed` 为 64 位小写 hex 的 Ed25519 私钥种子，其公钥即日志的
  `root`；`key` 为 64 位小写 hex 公钥；`at` 为**非布尔正整数**；
  `status` 仅取 `active`/`revoked`。
- 首项必须是 `active`（全新日志以撤销开局为 `state` 冲突）；各项 `at`
  **严格递增**；`revoked` 必须撤销**当前有效 key**（以不晚于新 `at` 的
  最后一项为准，无有效 key 或撤销别的 key 为 `state`）；新项的
  `at`/`key`/`status` 与当前末项完全相同为**幂等**成功（文件字节不变）。
- 已存在日志的根公钥必须等于 `root_seed` 推导出的根，否则为 `auth`。
- 文件按声明键序序列化为紧凑 UTF-8、非 ASCII 不转义、末尾恰好一个换行，
  临时文件 fsync 后 `os.replace` 原子换入，同一 `path` 串行；写失败尽力
  恢复原字节并返回 `io`。

成功直接返回该 `{root, records, head}` 文档；失败返回
`{ok:false,error}`：参数形状为 `input`，根不符为 `auth`，损坏/冲突为
`state`，读取缺失或读写 `io`。

### CLI：`history-trust` 与 `history-export`

两个离线子命令（不连接服务端，其余 CLI 与 HTTP 不变），各打印**单行
JSON**，成功/失败退出 0/1：

- `python -m ledger.cli history-trust PATH [--root-key SEED --at N --key PUB
  --status active|revoked]`：无四个选项时读取；更新时四项必填。成功打印
  上述 `{root, records, head}` 文档（保持契约键序），失败打印
  `{ok:false,error}`（退出 1）。`SEED`/`PUB` 为 64 位小写 hex，`N` 为
  非bool 正整数；首项 active、`at` 严格递增、revoke 当前 key、同末项
  幂等等规则同库函数。
- `python -m ledger.cli history-export PATH --key SEED [--after N]
  [--limit N] [--trust PATH]`：调用扩展后的 `export_history`；成功打印
  单个页面文档（键序 `base, records, next, head, checkpoint, auth`），
  失败打印 `{ok:false,error}`。给 `--trust` 时按持久签名者日志在下一
  授权边界前截断并给 `next`，`--key` 必须覆盖页内各 `verified_at`；
  未知/撤销覆盖 key 为 `auth`，坏日志为 `state`，日志缺失为 `io`。

## 节点托管的检查点历史 HTTP 接口

离线的 `history_trust` 与 `export_history` 也可以由节点通过 HTTP 托管，
复用同一套文件与契约。服务启动时加
`--history PATH --history-trust TRUST --history-token TOKEN`：三者**必须
同时给出且非空，或全部缺省**；只给其中一两个（含空值）是配置错误，
进程向 stderr 报错并以退出码 **2** 结束，不加载任何状态。全部缺省时
服务行为与以前完全一致，下面的历史路径返回 404，其余接口不变。

- **令牌闸门**：历史路由先核对 `Authorization: Bearer TOKEN` 请求头。
  闸门接受两类凭据：其一是启动配置的**静态 TOKEN**，全权且恒定时间比较；
  其二是下面 `POST /v1/history/access` 维护的**持久分权凭据**——仅当其
  当前 `status=active`、提供的 token 的 SHA-256 等于存储的 `token_hash`，
  且其权限覆盖所请路由时才放行（`GET /v1/history/trust` 需 `read`，
  `POST /v1/history/trust` 需 `update`，`POST /v1/history/export` 需
  `export`）。缺失、方案错误、token 不匹配、无活动凭据或凭据已撤销一律
  **401** `{"ok":false,"error":"unauthorized"}`；凭据有效但权限不足一律
  **403** `{"ok":false,"error":"forbidden"}`。二者都在读取请求体或访问
  任何状态/文件之前返回，**没有任何副作用**（不追加事件、不改文件）。
  `POST /v1/history/access` **只接受静态 TOKEN**：任何分权凭据（即便持
  全部权限）都无权管理凭据本身。
- **持久分权凭据管理**：`POST /v1/history/access`（仅静态 TOKEN）的 JSON
  体**仅含** `action,token,permissions,expected_version` 四键（键集封闭）。
  - `action="rotate"`：`token` 必须为非空字符串；`permissions` 必须是
    `read`/`update`/`export` 顺序下的**非空、无重复子集**（存储与响应均
    归一化为 read/update/export 顺序）。首次创建针对 `expected_version=0`，
    返回 **201**；此后每次轮换版本 +1、安装新 token 哈希与权限集，返回
    **200**。`expected_version` 必须是非布尔非负整数；格式错误一律
    **400** `{"ok":false,"error":"input"}`，版本不符一律 **409**
    `{"ok":false,"error":"state"}`，二者均无副作用。
  - `action="revoke"`：`token` 与 `permissions` 都必须为 `null`（否则
    400/input），版本相符返回 **200**：保留 `version`、`token_hash` 与
    `permissions`，仅把 `status` 置为 `revoked`；对已撤销凭据以相同版本
    重复撤销是**幂等**的（仍 200，不追加事件、不写盘）。撤销后该 token
    立即不可用（401）；针对被撤销版本再 `rotate` 会以版本 +1 签发一把新的
    active 凭据。
  - 成功响应的键序固定为 `version,token_hash,permissions,status`；
    `token_hash = SHA256(token 的 UTF-8 字节)`（64 位小写十六进制），
    **明文 token 绝不落盘**；`status` 仅取 `active`/`revoked`，首版版本
    为 0。
  - 凭据与一条 `history_credential_changed` 审计事件、审计检查点及
    `generation` 在**同一次原子快照**中落盘；事件载荷为 `action` 后接
    与响应一致的四字段，写盘失败回滚凭据、事件与 generation。快照另存
    顶层 `history_credential`，恰为该响应文档（不存明文），沿旧有序
    序列化（快照按 key 排序写入）；恢复时严格校验其形状并重放全部
    `history_credential_changed` 事件复现它，且把它纳入同代快照冲突比较，
    任何损坏或失配都抛 `ledger.store.StateRecoveryError(path, reason)`。
- **读签名者日志**：`GET /v1/history/trust` 严格加载并返回
  `{root, records, head}` 文档（键序、记录形状、`prev`/`head` 链接与
  根证书签名规则同 `history_trust` 读取契约）；日志缺失为 500/io，
  损坏为 409/state。
- **追加签名者记录**：`POST /v1/history/trust` 的 JSON 体**仅含**
  `root_seed,at,key,status` 四键（键序不限，键集封闭）。追加规则
  完全沿用 `history_trust`：首项必须 `active`、`at` 严格递增、
  `revoked` 必须撤销当前有效 key、与末项 `at/key/status` 完全相同为
  幂等。新增记录返回 **201**；幂等重放（文件字节不变）返回 **200**，
  两者都返回更新后的 `{root, records, head}`。根公钥不符为 403/auth，
  参数形状错误为 400/input，冲突为 409/state。
- **导出检查点历史页**：`POST /v1/history/export` 的 JSON 体**仅含**
  `key,after,limit`（`key` 必填，`after`/`limit` 缺省取库默认；键集
  封闭）。返回 **200** 与单页文档，键序固定
  `base, records, next, head, checkpoint, auth`，分页游标、截页、
  签名与严格重载全部复用 `export_history` 契约（不给 trust_path，故
  不做授权边界截断）。参数畸形 400/input，页签名公钥或验签问题
  403/auth，检查点/侧车损坏或游标无命中 409/state，文件缺失或不可
  读写 500/io。
- **错误体与状态码**：除 401 外，失败一律返回
  `{"ok":false,"error":类别}`（两键以此顺序），类别到状态码的映射为
  `input`→400、`auth`→403、`state`→409、`io`→500。
- **审计事件**：每次成功的 read/update/export 都在账本只增审计流中
  追加恰好一条 `history_access` 事件，载荷键序固定为
  `action,trust_head,history_head`：`action` 为 `read`/`update`/
  `export`，`trust_head` 是签名者日志当前 `head`，`history_head` 是
  检查点侧车当前 `head`，文件尚不存在时对应值为 `null`。
- **共锁与原子性**：信任日志、检查点与侧车、审计事件、
  `audit_checkpoint` 与 `generation` 在同一把锁与同一次原子快照事务中
  串行化——先持有两个文件各自的按路径锁（与离线 CLI/库调用共用），
  外部文件落盘并完成账本快照后才响应。update 时若账本快照写盘失败，
  会尽力把签名者日志恢复为原字节、回滚内存中的审计事件/generation，
  返回 500/io。
- **重启重验与绑定**：配置了这三个选项时，启动恢复在唯一胜出快照
  选定后严格重验签名者日志与检查点/侧车（形状、哈希链、证书签名、
  检查点重放，缺文件为 io、损坏为 state），并要求审计日志中的**末条
  `history_access` 事件**的 `trust_head`/`history_head` 与两文件当前
  头一致（文件未创建即为 null）；任一项失配都抛出
  `ledger.store.StateRecoveryError`，携带 `path`（失配文件）与
  `reason`，绝不静默启动。尚无任何 `history_access` 事件的文件对
  （例如离线 CLI 预先创建）只做重验、不做绑定。

## 审计导出的离线校验

不连接服务端也能核验只增审计流是否被篡改或截断：用
`GET /v1/audit/export` 逐页拉取（或直接使用某一页），交给 CLI
`ledger audit-verify FILE|-`（`-` 从标准输入读）。输入可以是**单个导出页
对象**，也可以是**按顺序排列的多页数组**（对整份导出逐页抓取后的拼接）。

校验逐项进行：

- 每个页面必须具备
  `{items,total,next_cursor,anchor_hash,checkpoint}` 且类型合法；
- 页面的 `anchor_hash` 必须等于当前已验位置的前一哈希（首页为 64 个 0）；
- `items` 的 `event_id` 必须跨页连续（1 起、无缺号），每条 `prev_hash`
  必须等于前一条的 `event_hash`，且每条 `event_hash` 都按上面的规范重算；
- 分页计数自洽：非空 `next_cursor` 恰好接续本页且小于 `total`，为 `null`
  时链头恰好到达 `total`；
- **所有页**的 `checkpoint` 必须完全一致（同一份导出的每一页都钉住同一
  检查点），且每页 `checkpoint.event_id` 等于该页 `total`；
- **最后一页**的链尾（空日志则为 64 个 0）必须与其 `checkpoint` 完全匹配。

输出恒为**单行 JSON**：成功 `{"ok": true, "checkpoint": {event_id,
event_hash}}`，进程退出码 0；失败
`{"ok": false, "error": "input"|"integrity"|"auth"}`，退出码 1。`input`
表示输入无法读取/不是 JSON、或文档结构字段缺失/类型非法；`integrity`
表示锚点、连续编号、任一哈希链接、分页计数、跨页检查点或末页检查点不一致。
`audit-verify` 不发起任何网络请求。

**带信任文档的检查点认证（可选）**：追加 `--trust trust.json`（即
`GET /v1/trust` 的输出）后，除上述哈希链核验外还核对检查点签名：信任
文档的 `genesis_hash` 必须有效，`audit_signers` 必须自版本 1 起连续、首版
`activated_event_id` 为 0；每一页都必须携带同一
`checkpoint_auth = {key_version, signature}` 并钉住同一检查点；
`key_version` 必须命中一个在该检查点事件 id 处（或之前）已激活的签名者，
且 Ed25519 签名必须用该版本公钥验过——先把
`{genesis_hash, checkpoint, key_version}` 序列化为排序紧凑 UTF-8 JSON 再取
SHA-256 摘要作为签名消息。
缺省（不给 `--trust`）行为完全不变；提供信任文档时，缺签名、未知/未激活
密钥版本、跨页认证不一致、创世锚不符或签名验不过均返回新增的 `auth`，
而链本身被篡改仍返回 `input`/`integrity`。

## 快照整体一致性的离线校验

不连接服务端、也不打开任何运行中的账本，就能核验一份持久化快照文档是否
自洽：`ledger.consistency.verify_snapshot(document: object) -> dict` 直接
接收已解码的 JSON 对象，重算文档内一切可自证的派生量。CLI 入口为
`python -m ledger.cli consistency FILE|-`（`-` 从标准输入读）。

文档**必含**顶层键 `state`、`chain`、`pending`、`index`、`accounts`、
`audit_checkpoint`；`audit_events` 可以缺省（视为空日志）；允许扩展
`forks`、`syncs`、`attested_syncs`、`trust_sources`、`allowlist`（这些
区段存在与否不影响本项自洽核验），其余顶层未知键一律拒绝。存在时还会
严格校验 `source_key_history`（见信任扩展）与持久分权历史凭据
`history_credential`：它必须恰为
`{version,token_hash,permissions,status}`，且与重放
`history_credential_changed` 事件得到的凭据逐字一致（首版版本 0、rotate
版本恰 +1、revoke 保留版本/哈希/权限），形状错为 `input`、与事件不符为
`integrity`。

逐项重算并比对：

- 每笔交易的规范化 `tx_id`（SHA-256 of 排序紧凑 JSON）与 Ed25519 签名；
  `amount`/`height` 等数值先在**原始 JSON 值**上校验为非布尔非负（或
  正数）整数，绝不做 `int()` 转换；
- 每个区块的交易按 `tx_id` 升序、Merkle 根、区块哈希，以及连续高度、
  `prev_hash` 链接（创世块锚定 64 个 0）、创世块已确认且无交易、
  pending 块只能位于链尾；
- `pending` 集合内交易唯一、且不与链上（含 pending 尾块）任何交易重复；
- 仅由**已确认**区块重算 `index`（tx_id→高度）与 `accounts`
  （`{sent,received,transactions}`，transactions 保持链上原始顺序），与
  文档记录完全一致；
- 用 `state.initial_balance`（缺省回落到默认 1_000_000）重算已确认账户的
  Merkle `state_root`；文档若记录了 `state.state_root`（64 位小写 hex）
  必须等于重算值；`state.height`/`tip_hash`/`tip_status` 若存在也必须与
  链尾一致；
- 当 `audit_events` 存在时，事件 `event_id` 必须自 1 连续，每条
  `prev_hash` 等于前一条 `event_hash`，且
  `event_hash = SHA256(prev_hash 的 ASCII || 去除 prev_hash/event_hash 两
  字段后的排序紧凑 UTF-8 JSON)`；无论事件列表是否存在，
  `audit_checkpoint = {event_id, event_hash}` 都必须钉住真实链头（空日志
  为 `{0, "0"*64}`）。

输出恒为**单行 JSON**，顶层键序固定为
`ok,error,generation,height,tip_hash,state_root,audit_checkpoint`：

- 成功：`true, null, N, N, H, H, C`——`generation`/`height` 为非负整数，
  `tip_hash`/`state_root` 为 64 位小写十六进制，
  `C = {event_id, event_hash}`；
- 失败：`ok=false`，`error` 为 `"input"` 或 `"integrity"`，其余字段全部
  为 `null`。

错误分类：文档不是对象、必含区段缺失或核心区段类型错误、顶层未知键，或
字段原始类型非法（字符串/浮点/布尔伪装的数值等）均为 `input`；结构合法
但任何重算量与记录不符（交易/签名/Merkle/区块哈希/链接/索引/账户/
state_root、pending 唯一性、审计事件链或检查点）均为 `integrity`。
`consistency` 不发起任何网络请求；文件无法读取或内容不是 JSON 时输出
`{"ok": false, "error": "input"}`，退出码成功 0、任何失败 1。

## 实现说明

代码全部在 `ledger/` 包中：

| 文件 | 职责 |
| --- | --- |
| `ledger/crypto.py` | Ed25519 验签/签名/密钥推导与生成、规范化交易消息、SHA-256 tx_id、Merkle 根与包含证明（单笔 `verify_merkle_proof` 与批量束 `verify_merkle_proof_bundle`）、账户状态叶子/状态根与 `verify_account_proof` 离线验证 |
| `ledger/models.py` | Transaction / Block 模型（含 pending/confirmed 状态）与确定性区块哈希 |
| `ledger/audit.py` | 审计事件哈希链：规范化事件哈希、整链链接、`audit_checkpoint` 计算与严格校验，检查点 Ed25519 认证对象的签名/验签，以及导出页的离线核验（锚点、连续编号、哈希、跨页一致的检查点、末页检查点、可选信任文档下的检查点认证） |
| `ledger/consistency.py` | 快照整体一致性的离线核验：重算交易 tx_id/签名、Merkle 根、区块哈希与链接、pending 唯一性、已确认 `index`/`accounts`、账户 `state_root`，以及审计事件哈希链与检查点；输出固定键序的 `ok,error,generation,height,tip_hash,state_root,audit_checkpoint`，错误分 `input`/`integrity` |
| `ledger/store.py` | 链（含候选分叉）、状态、待打包集合、索引、账户、持久化来源信任注册表、allowlist、可轮换审计检查点 Ed25519 签名者（含历史公钥）与带哈希链/检查点的只增审计事件流（含 `history_access` 绑定）的 JSON 原子持久化（fsync 快照 + 原子改名）、generation、创世区块、候选分叉整链校验、采用时原子换链、启动快照扫描、旧快照补链/签名者迁移与崩溃恢复、节点托管检查点历史文件的启动重验与末条同类事件绑定、持久分权历史凭据（`history_credential` 快照区段与 `history_credential_changed` 事件重放校验） |
| `ledger/service.py` | 提交校验（签名、金额、余额）、打包、确认/回滚状态机、查询，候选分叉的提交校验、链比较与原子采用，来源信任注册/轮换/撤销、keyless allowlist 新增/幂等/删除、审计签名者轮换、信任文档、审计分页、哈希锚定导出（含检查点认证）与同步事件登记、令牌保护的 `/v1/history/trust`
读取/追加（201/200 幂等）与 `/v1/history/export` 签名分页及其
`history_access` 审计事件，以及持久分权凭据 `/v1/history/access`
的 rotate/revoke（201 首创/200 更新，仅存 SHA-256 哈希，分权 Bearer 闸门
read/update/export，401/403 无副作用）与 `history_credential_changed` 事件 |
| `ledger/server.py` | 标准库 `http.server` 实现的 REST 接口 |
| `ledger/light_client.py` | 离线轻客户端：受信来源/过期/Ed25519 验签、从创世锚重算整条候选链、核对 response 与 Merkle proofs；区间导出文档的离线核验（钉住锚点、尾部重算、tip 摘要、plain allowlist / attested `ledger-sync-range-v1` 签名）；`advance` 检查点与代际历史侧车的维护/查询/裁剪，检查点历史的签名分页导出 `export_history`、多页离线连续校验 `verify_history`，以及带签名者轮换/撤销日志（根密钥锚定证书链）的 `verify_history_trust` |
| `ledger/cli.py` | `send` / `mine` / `block` / `account` / `proof` / `proofs` / `state-root` / `state-proof` / `confirm` / `rollback` / `status` / `candidates` / `chain` / `chain-range` / `adopt` / `export` / `index` / `sync` / `sync-range` / `sync-attested` / `sync-range-attested` / `syncs` / `sync-history` / `sync-export` / `sync-range-export` / `trust add|rotate|revoke|export|allowlist-add|allowlist-remove` / `audit` / `audit-export` / `audit-signer-rotate` / 离线 `verify` / 离线 `audit-verify [--trust]` / 离线 `consistency` / 离线 `verify-range` 子命令 |

约定：

- 账户标识即 Ed25519 公钥的十六进制（64 个字符）；`signature` 是对规范化
  消息 `{"amount":N,"from":"...","to":"..."}`（key 升序、无空白的 UTF-8 JSON）
  的 Ed25519 签名十六进制。
- `tx_id = sha256(规范化消息)`；同一笔交易重复提交（待打包或已确认）返回 409。
- 区块与交易文档在所有入口（候选分叉、节点同步、快照恢复、离线 verify）都先校验
  原始 JSON 类型再重算：`height` 必须是非布尔的非负整数且等于数组位置，`amount`
  必须是非布尔的正整数；字符串、浮点数、布尔值一律拒绝（候选/同步 400 且不写任何
  状态、同一幂等键也不回放 200；离线 verify 返回 `input`；canonical 链或待打包集合
  含此类值在恢复时抛 `StateRecoveryError`，仅持久化候选/同步记录含此类值则按缓存
  规则丢弃），绝不做 `int()` 转换后再判断。旧快照缺省 `status=confirmed` 的兼容
  保留，但不因此接受任何数值转换。
- Merkle 树每层做 `sha256(left_hex + right_hex)`，奇数节点与自身配对；
  空列表根为 `sha256(b"")`。包含证明 `merkle_proof(tx_ids, index)` 返回自叶向根
  的兄弟节点列表，每项 `{"direction": "left"|"right", "hash": ...}`，direction 表示
  兄弟节点位于路径节点的左/右侧；`verify_merkle_proof(tx_id, siblings, merkle_root,
  block_hash, expected_block_hash)` 重算根并比对区块哈希，任何畸形输入（非 64 位
  小写十六进制、非法 direction、层级过深等）均返回 `False`。批量束
  `verify_merkle_proof_bundle(bundle, expected_block_hash, expected_merkle_root)`
  在同样的重算规则外，还严格校验顶层与各项的键集/键序、类型、唯一且升序的
  transaction_ids、proof 的 tx_id 唯一升序、index 与全量叶子位置一一映射，
  并直接由 transaction_ids 重算根，使叶子列表无法被独立篡改；畸形或篡改一律
  返回 `False` 而不抛异常。
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

可选 `--history PATH --history-trust PATH --history-token TOKEN` 开启
令牌保护的 `/v1/history/trust` 与 `/v1/history/export` 托管接口（三者须
全给且非空或全缺，部分给出退出码 2，详见「节点托管的检查点历史 HTTP
接口」）。

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
# 交易回执（tx_id 必须 64 位小写十六进制；非法或不存在 404；只查 canonical 与待处理集合）
curl -s localhost:8080/v1/transactions/<tx-id-hex>
# -> 200 {"tx_id":"...","from":"...","to":"...","amount":N,"signature":"...",
#         "status":"pending|confirmed","height":H|null,"block_hash":"...|null","index":I|null}
# 账户状态根与账户状态包含证明（最高块 pending 时均 404；账户不在已确认集 404）
curl -s localhost:8080/v1/state/root
# -> {"state_root":"...","height":N,"block_hash":"...","account_count":K}
# 历史高度：仅重放创世..H 的已确认前缀（未知/非 canonical/pending 高度 -> 404）
curl -s localhost:8080/v1/state/root/H
curl -s localhost:8080/v1/accounts/<pubkey-hex>/proof
# -> {"account":"...","balance":...,"confirmed_transactions":[...],"index":I,
#     "state_root":"...","height":N,"block_hash":"...","siblings":[{direction,hash}...]}
# 历史锚点（非法/重复 height -> 400；锚点不可用或账户当时不存在 -> 404）
curl -s "localhost:8080/v1/accounts/<pubkey-hex>/proof?height=H"
# 已确认交易的 Merkle 包含证明（区块不存在/交易不在该高度/tx_id 非法 -> 404；区块待定 -> 409）
curl -s localhost:8080/v1/blocks/1/proof/<tx-id-hex>
# 批量 Merkle 证明（tx_ids 须非空、互异、各为 64 位小写 hex；畸形请求体 -> 400；
# 未知高度或缺交易 -> 404；区块待定 -> 409；成功顶层键序固定）
curl -s -X POST localhost:8080/v1/blocks/1/proofs \
  -H 'Content-Type: application/json' \
  -d '{"tx_ids":["<tx-id-hex-1>","<tx-id-hex-2>"]}'
# -> {"height":1,"block_hash":"...","merkle_root":"...",
#     "transaction_ids":["<全块叶子，升序>"],
#     "proofs":[{"tx_id":"...","index":I,"siblings":[{direction,hash}...]} 按 tx_id 升序]}

# 状态机
curl -s localhost:8080/v1/blocks/1/status          # -> {"height":1,"status":"pending"}
curl -s -X POST localhost:8080/v1/blocks/1/confirm  # -> 200 {"height":1,"status":"confirmed"}
curl -s -X POST localhost:8080/v1/blocks/1/rollback # 仅待定链尾可用

# 候选分叉（blocks 为完整块数组，第 0 块必须与 canonical 创世块一致）
curl -s -X POST localhost:8080/v1/forks/candidates \
  -H 'Content-Type: application/json' \
  -d '{"blocks":[{...genesis...},{...block1...}]}'
# -> 201 {"tip_hash":"...","height":1,"length":2,"status":"confirmed"}；非法 400，重复 409

# 链视图：canonical、按 tip_hash 升序的 candidates、非 canonical 胜者 adoptable
curl -s localhost:8080/v1/chain

# 采用胜出候选（未知 tip 404，非胜者 409）
curl -s -X POST localhost:8080/v1/forks/<tip-hash>/adopt

# 导出候选分叉（canonical/未知/非法 tip 均 404）；导出文档可原样再提交 candidates
curl -s localhost:8080/v1/forks/<tip-hash>/export
# -> 200 {"tip_hash":"...","height":N,"length":N+1,"status":"...","blocks":[...]}

# 节点间同步：推送他节点候选（来源须先 trust add 注册且仍 active 未过期，否则 403；
# 201；相同 source+request_id 同内容重试 200（即使来源事后轮换/撤销仍回放原结果），
# 内容不同 409，请求过期 410，格式或校验失败 400）
curl -s -X POST localhost:8080/v1/forks/sync \
  -H 'Content-Type: application/json' \
  -d '{"source":"node-2","request_id":"req-7","expires_at":1800000000,"candidate":{...export 文档...}}'
# -> 201 {"tip_hash":"...","height":N,"length":N+1,"status":"...","expires_at":1800000000}

# 增量区间：拉取锚点之后的完整区块（after_height/after_hash 必填，limit 默认100、1-500；
# 高度不存在 404、哈希非法 400、锚点不匹配 409、重复参数 400），pending 尾块同样导出
curl -s 'localhost:8080/v1/chain/range?after_height=2&after_hash=<block-hash>&limit=100'
# -> 200 {"anchor":{"height":2,"block_hash":"..."},"blocks":[{...},...],"canonical":{...},"next_height":4}

# 签名区块头分页（参数规则同 /v1/chain/range；200 键序 anchor,headers,tip,auth；
# 锚点即链尾时 headers 为空；auth.signature = Ed25519(SHA256(UTF8("ledger-headers-v1")
# || canonical_json(去auth)))，离线用 verify_header_page(document, anchor, tip_hash, trust) 校验）
curl -s 'localhost:8080/v1/chain/headers?after_height=2&after_hash=<block-hash>&limit=100'
# -> 200 {"anchor":{"height":2,"block_hash":"..."},"headers":[{"height":3,"prev_hash":"...","merkle_root":"...","block_hash":"...","status":"confirmed"}],"tip":{"tip_hash":"...","height":3,"length":4,"status":"confirmed"},"auth":{"key_version":1,"signature":"..."}}

# 签名最终化凭证（无参数，携带任意查询参数 400；200 键序 finalized,tip,auth；
# finalized 取最后 confirmed 块，pending 链尾只体现在 tip；auth.signature =
# Ed25519(SHA256(UTF8("ledger-finality-v1") || canonical_json(去auth)))，
# 离线用 apply_finality(path, document, trust) 落盘推进 finalized 边界）
curl -s localhost:8080/v1/chain/finality
# -> 200 {"finalized":{"height":2,"block_hash":"..."},"tip":{"tip_hash":"...","height":3,"length":4,"status":"pending"},"auth":{"key_version":1,"signature":"..."}}

# 增量区间：仅推送锚点之后的尾部区块（拼接 canonical 前缀做整链重验；
# 状态优先级 400→403→410→锚点 409→重验/tip 400→重复 409；201 五字段，
# 同 source+request_id 同内容重试 200 首次结果、异内容 409）
curl -s -X POST localhost:8080/v1/forks/sync/range \
  -H 'Content-Type: application/json' \
  -d '{"source":"node-2","request_id":"req-8","expires_at":1800000000,"anchor":{"height":2,"block_hash":"..."},"blocks":[{...}],"tip":{"tip_hash":"...","height":4,"length":5,"status":"confirmed"}}'
# -> 201 {"tip_hash":"...","height":4,"length":5,"status":"confirmed","expires_at":1800000000}

# 同步审计查询（source/mode/min_height/max_height/limit/cursor；
# mode 缺省或 plain 只列普通同步，attested 只列签名同步，all 合并；
# 非法 mode、非法数值或重复参数均 400）
curl -s 'localhost:8080/v1/forks/sync?source=node-2&mode=all&min_height=1&limit=50&cursor=0'
# -> 200 {"items":[{source,request_id,tip_hash,height,length,status,expires_at}...],"total":N,"next_cursor":null}

# 同步生命周期历史（source/tip_hash/kind/mode/min_height/max_height/limit/cursor；
# mode 缺省或 all 全量，plain 含无 mode 旧事件，attested 仅签名事件；
# tip_hash 或 kind 格式错误 400，未知 tip_hash 空页，非法 mode/数值或重复参数 400）
curl -s 'localhost:8080/v1/forks/sync/history?source=node-2&kind=sync_adopted&limit=50&cursor=0'
# -> 200 {"items":[{event_id,kind,at,source,request_id,tip_hash,height,length,status,expires_at}...],"total":N,"next_cursor":null}

# 同步记录导出（source/request_id/mode 三参数必填单值，mode 仅 plain/attested；
# 缺失/重复/未知参数 400，range 记录 409，未知/过期/清理后 404；
# 成功顶层键序固定，plain 的 candidate 为五字段导出文档、attestation 为 null，
# attested 保留签名候选并带冻结 {public_key,version,signature}）
curl -s 'localhost:8080/v1/forks/sync/export?source=node-2&request_id=req-7&mode=plain'
# -> 200 {"source":"node-2","request_id":"req-7","mode":"plain","expires_at":...,
#         "tip_hash":"...","height":N,"length":N+1,"status":"...",
#         "candidate":{...五字段导出文档...},"attestation":null}

# 增量区间记录导出（参数约束同上；整链记录在此端点返回 409；
# 成功顶层键序固定 source,request_id,mode,expires_at,anchor,blocks,tip,attestation，
# tip 由 anchor+blocks 重算，plain 的 attestation 为 null，
# attested 带冻结 {public_key,version,signature}）
curl -s 'localhost:8080/v1/forks/sync/range/export?source=node-2&request_id=req-8&mode=plain'
# -> 200 {"source":"node-2","request_id":"req-8","mode":"plain","expires_at":...,
#         "anchor":{"height":2,"block_hash":"..."},"blocks":[{...}],"tip":{...},
#         "attestation":null}

# 确认链交易索引（tx_id/account/height/limit/cursor，AND 组合，非法 400）
curl -s 'localhost:8080/v1/index/transactions?account=<pubkey-hex>&limit=50&cursor=0'
# -> 200 {"items":[{tx_id,height,block_hash,index,from,to,amount}...],"total":N,"next_cursor":null}

# 持久化来源信任（201 version=1 active；同内容 200；冲突 409；非法 400）
curl -s -X POST localhost:8080/v1/trust/sources \
  -H 'Content-Type: application/json' \
  -d '{"source":"node-2","public_key":"<64-hex-pubkey>","expires_at":1900000000}'
# -> 201 {"source":"node-2","public_key":"...","expires_at":1900000000,"version":1,"status":"active"}

# 轮换公钥（未知/已撤销 404，版本错 409，version 递增）
curl -s -X POST localhost:8080/v1/trust/sources/node-2/rotate \
  -H 'Content-Type: application/json' \
  -d '{"public_key":"<new-64-hex>","expires_at":1900000000,"expected_version":1}'

# 撤销来源（未知 404，版本错 409，重复撤销 200）
curl -s -X POST localhost:8080/v1/trust/sources/node-2/revoke \
  -H 'Content-Type: application/json' -d '{"expected_version":2}'

# keyless allowlist 新增（仅供离线 verify，不授权 forks/sync；
# 201 新条目，同内容重试 200 不追加事件，内容不同 409，非法 400；
# 过期值合法，过期条目不自动删除）
curl -s -X POST localhost:8080/v1/trust/allowlist \
  -H 'Content-Type: application/json' \
  -d '{"source":"keyless-node","expires_at":1900000000}'
# -> 201 {"source":"keyless-node","expires_at":1900000000}

# 删除 allowlist 条目（未知 404；200 {source,removed:true}；不影响同名 trust source）
curl -s -X DELETE localhost:8080/v1/trust/allowlist/keyless-node
# -> 200 {"source":"keyless-node","removed":true}

# 离线验证信任文档（genesis_hash 固定；sources 只含未过期未撤销来源；allowlist 保留）
curl -s localhost:8080/v1/trust
# -> 200 {"genesis_hash":"...","sources":{"node-2":{"public_key":"...","expires_at":...}},"allowlist":{...}}

# 审计事件流（source/kind/cursor/limit，按 event_id 升序分页）
curl -s 'localhost:8080/v1/audit/events?kind=sync_received&limit=50&cursor=0'
# -> 200 {"items":[{event_id,kind,at,...}...],"total":N,"next_cursor":null}

# 哈希锚定审计导出（cursor/limit 分页；重复参数 400）
curl -s 'localhost:8080/v1/audit/export?limit=50&cursor=0'
# -> 200 {"items":[{event_id,kind,at,prev_hash,event_hash,...}...],
#         "total":N,"next_cursor":null,
#         "anchor_hash":"<本页首条的前一哈希>","checkpoint":{event_id,event_hash}}

# 节点托管的检查点历史（服务须以 --history/--history-trust/--history-token
# 启动；先核对 Authorization: Bearer，错误 401 且无副作用）
curl -s -H "Authorization: Bearer <token>" localhost:8080/v1/history/trust
# -> 200 {"root":"...","records":[{at,key,status,prev,signature}...],"head":"..."}
curl -s -X POST localhost:8080/v1/history/trust \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"root_seed":"<64hex 根私钥种子>","at":1700000000,"key":"<64hex 公钥>","status":"active"}'
# -> 201 新记录 / 200 幂等；400 input、403 auth（根不符）、409 state、500 io
curl -s -X POST localhost:8080/v1/history/export \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"key":"<64hex 签名种子>","after":0,"limit":50}'
# -> 200 {"base":...,"records":[...],"next":null,"head":"...","checkpoint":{...},
#         "auth":{"public_key":"...","signature":"..."}}

# 持久分权凭据（仅静态 TOKEN；首创 expected_version=0 返回 201，之后 200）
curl -s -X POST localhost:8080/v1/history/access \
  -H 'Authorization: Bearer <static-token>' -H 'Content-Type: application/json' \
  -d '{"action":"rotate","token":"<新明文token>","permissions":["read","export"],"expected_version":0}'
# -> 201 {"version":0,"token_hash":"<SHA256(token)>","permissions":["read","export"],"status":"active"}
# 轮换（版本+1、新哈希）/ 撤销（保留哈希与权限，status=revoked）
curl -s -X POST localhost:8080/v1/history/access \
  -H 'Authorization: Bearer <static-token>' -H 'Content-Type: application/json' \
  -d '{"action":"rotate","token":"<另一把>","permissions":["update"],"expected_version":1}'
curl -s -X POST localhost:8080/v1/history/access \
  -H 'Authorization: Bearer <static-token>' -H 'Content-Type: application/json' \
  -d '{"action":"revoke","token":null,"permissions":null,"expected_version":2}'
# 格式错 400/input；版本冲突 409/state；此后活动凭据可用其明文 token 按
# read/update/export 分权访问上面三个历史路由（无效 401，缺权 403）。
```

## 命令行

CLI 通过 HTTP 访问服务（默认 `http://127.0.0.1:8080`，可用 `--base-url` 或
`LEDGER_BASE_URL` 覆盖），输出与 HTTP 响应字段完全一致的单行 JSON：

```bash
# 本地用 Ed25519 私钥（PEM 文件或 64 位十六进制）签名后提交
python -m ledger.cli send --signing-key @alice.pem --to <recipient-pubkey-hex> --amount 100
python -m ledger.cli mine
python -m ledger.cli block 1
python -m ledger.cli tx <tx-id-hex>
python -m ledger.cli account <pubkey-hex>
python -m ledger.cli proof 1 <tx-id-hex>
python -m ledger.cli proofs 1 <tx-id-hex-1> <tx-id-hex-2>  # 批量；非 2xx 退出 1
python -m ledger.cli state-root                 # 锚定最高已确认块
python -m ledger.cli state-root --height H      # 历史已确认前缀
python -m ledger.cli state-proof <pubkey-hex>
python -m ledger.cli state-proof <pubkey-hex> --height H
python -m ledger.cli status 1
python -m ledger.cli confirm 1
python -m ledger.cli rollback 1
# 也可以传已有的签名：send --from <pubkey-hex> --signature <sig-hex> --to ... --amount ...

# 候选分叉：candidates 参数为块数组（或 {"blocks":[...]} 对象）的 JSON
python -m ledger.cli candidates '[{"height":0,...},{"height":1,...}]'
python -m ledger.cli chain
python -m ledger.cli adopt <tip-hash>

# 导出候选分叉与确认链交易索引
python -m ledger.cli export <tip-hash>
python -m ledger.cli index [--tx-id <hex>] [--account <pubkey-hex>] [--height N] [--cursor N] [--limit N]

# 节点间候选链同步与审计查询
python -m ledger.cli sync --source node-2 --request-id req-7 --expires-at 1800000000 '<export 文档或块数组 JSON>'
python -m ledger.cli syncs [--source node-2] [--mode plain|attested|all] [--min-height N] [--max-height N] [--cursor N] [--limit N]
python -m ledger.cli sync-history [--source node-2] [--tip-hash <64-hex>] [--kind sync_received|sync_adopted|sync_expired] [--mode plain|attested|all] [--min-height N] [--max-height N] [--cursor N] [--limit N]
# 按幂等键导出一条已接收同步候选（mode 仅 plain|attested；单行 JSON，非 2xx 退出 1）
python -m ledger.cli sync-export --source node-2 --request-id req-7 --mode plain

# 增量区间：chain-range 拉取（可把整页 JSON 直接交给 sync-range 推送，tip 自动派生）
python -m ledger.cli chain-range --after-height 2 --after-hash <block-hash> [--limit 100]
python -m ledger.cli sync-range --source node-2 --request-id req-8 --expires-at 1800000000 '{"anchor":{"height":2,"block_hash":"..."},"blocks":[{...}],"tip":{...}}'
# range 文档也可以是 chain-range 的整页输出，或用 - 从标准输入读取

# 签名认证的增量区间：--signing-key 为 64 位小写十六进制私钥种子，客户端本地按
# domain=ledger-sync-range-v1 对 SHA-256 摘要做 Ed25519 签名；非 2xx 退出码 1
python -m ledger.cli sync-range-attested --source node-2 --request-id req-9 --expires-at 1800000000 --signing-key <64-hex-seed> '{"anchor":{"height":2,"block_hash":"..."},"blocks":[{...}],"tip":{...}}'

# 增量区间记录导出（按幂等键，mode 仅 plain|attested；单行 JSON，非 2xx 退出 1）
python -m ledger.cli sync-range-export --source node-2 --request-id req-8 --mode plain

# 持久化来源信任：注册 / 轮换 / 撤销 / 导出 verify 信任文档
python -m ledger.cli trust add --source node-2 --public-key <64-hex-pubkey> --expires-at 1900000000
python -m ledger.cli trust rotate --source node-2 --public-key <64-hex-pubkey> --expires-at 1900000000 --expected-version 1
python -m ledger.cli trust revoke --source node-2 --expected-version 2
python -m ledger.cli trust export > trust.json

# 只增审计事件流（source/kind/cursor/limit；信任变更与同步接收/采用/过期均可查）
python -m ledger.cli audit [--source node-2] [--kind source_registered] [--cursor N] [--limit N]

# 轮换审计检查点签名密钥（64 位小写十六进制私钥种子；公钥自动推导）
python -m ledger.cli audit-signer-rotate --private-key <64-hex-seed> --expected-version 1

# 哈希锚定审计导出与离线校验（audit-verify 不连接服务端；- 从标准输入读取页或多页数组）
python -m ledger.cli audit-export [--cursor N] [--limit N] > audit-page.json
python -m ledger.cli audit-verify audit-page.json
cat audit-page.json | python -m ledger.cli audit-verify -
# -> 成功单行 {"ok":true,"checkpoint":{"event_id":N,"event_hash":"..."}} 退出 0；
#    失败单行 {"ok":false,"error":"input"|"integrity"} 退出 1
# 给 --trust 还会核对创世锚、密钥版本与 Ed25519 检查点签名（失败新增 "auth"）
python -m ledger.cli audit-verify audit-page.json --trust trust.json

# 快照整体一致性离线核验（consistency 不连接服务端；- 从标准输入读取快照文档）
python -m ledger.cli consistency ledger_state.json
cat ledger_state.json | python -m ledger.cli consistency -
# -> 成功单行 {"ok":true,"error":null,"generation":N,"height":N,
#    "tip_hash":"...","state_root":"...","audit_checkpoint":{...}} 退出 0；
#    失败单行 {"ok":false,"error":"input"|"integrity",...其余 null} 退出 1

# 离线轻客户端验证（不连接服务端；--bundle - 从标准输入读取束 JSON）
python -m ledger.cli verify --bundle bundle.json --trust trust.json
cat bundle.json | python -m ledger.cli verify --bundle - --trust trust.json
# -> 成功单行 {"ok":true,...} 退出 0；失败单行 {"ok":false,"error":"..."} 退出 1

# 区间导出的离线校验（不连接服务端；--export - 从标准输入读取导出文档）
python -m ledger.cli verify-range --export range-export.json --trust trust.json \
    --anchor-height 8 --anchor-hash <64hex>
cat range-export.json | python -m ledger.cli verify-range --export - --trust trust.json \
    --anchor-height 8 --anchor-hash <64hex>
# -> 成功单行 {"ok":true,"source":...,"request_id":...,"mode":...,"anchor":{...},
#    "tip":{...},"verified_tx_ids":[...]} 退出 0；
#    失败单行 {"ok":false,"error":"input"|"auth"|"expired"|"integrity"} 退出 1

# 多页增量区间的离线连续校验（--exports - 从标准输入读取导出文档数组）
python -m ledger.cli verify-range-batch --exports range-exports.json --trust trust.json \
    --anchor-height 8 --anchor-hash <64hex>
cat range-exports.json | python -m ledger.cli verify-range-batch --exports - --trust trust.json \
    --anchor-height 8 --anchor-hash <64hex>
# -> 成功单行 {"ok":true,"anchor":{...},"tip":{...},"pages":N,
#    "verified_tx_ids":[...]} 退出 0；
#    失败单行 {"ok":false,"error":"input"|"auth"|"expired"|"integrity"} 退出 1
```

非 2xx 响应同样打印单行 JSON 并以退出码 1 结束。

## 基础测试

```bash
python -m compileall -q ledger   # 编译检查
python tests/smoke_test.py       # 不依赖网络的全流程冒烟测试
python tests/merkle_proof_test.py  # Merkle 证明（crypto/service/HTTP/CLI）与接口回归
python tests/merkle_proof_bundle_test.py  # 批量 Merkle 证明（verify_merkle_proof_bundle 键序/类型/唯一性/index 映射/路径/根/区块哈希、严格 400、404/409、POST /v1/blocks/{height}/proofs、CLI proofs）
python tests/state_proof_test.py   # 账户状态 Merkle 根与包含证明（canonical 叶子、verify_account_proof、/v1/state/root、/v1/accounts/{account}/proof、pending 404、HTTP/CLI、快照 state_root 恢复拒绝）
python tests/history_state_test.py # 历史高度状态根/账户证明（/v1/state/root/{height}、?height=H 严格校验与 400/404 语义、canonical 前缀确定性重放、历史 proof 离线验证、CLI 转发、重启/分叉采用/回滚/并发一致性）
python tests/confirm_rollback_test.py  # 确认/回滚状态机（service/HTTP/CLI/重启重建）
python tests/recovery_test.py         # generation、多区块一致性、快照恢复、损坏拒绝、并发串行化
python tests/fork_test.py             # 候选分叉校验、链比较、原子采用、内存池去重、重启重校验
python tests/export_index_test.py     # 分叉导出、导出格式候选重验、确认链交易索引与 CLI
python tests/fork_sync_test.py        # 节点间候选链同步（201/200/400/409/410、幂等、审计分页、过期、采用、重启）与 HTTP/CLI
python tests/range_sync_test.py       # 增量区间协议（GET /v1/chain/range 分页/严格参数/404/409/pending 尾块；POST /v1/forks/sync/range 状态优先级、拼接整链重验、201五字段、脱离 canonical 的200重试、最长链采用、失败回滚、重启指纹核验）与 HTTP/CLI
python tests/header_page_test.py      # 签名区块头分页 GET /v1/chain/headers（after_height/after_hash 必填、limit 1–500 默认 100、400/404/409；固定键序 anchor,headers,tip,auth 与头项 height,prev_hash,merkle_root,block_hash,status；anchor=tip 时空 headers；pending 仅链尾；domain=ledger-headers-v1 的 SHA-256+Ed25519 签名；verify_header_page input/auth/integrity、锚点/tip 钉住、重算哈希与链接、分页串联、轮换历史验签）与 HTTP
python tests/header_pages_test.py     # 多页签名区块头离线连续校验 verify_header_pages（非空数组逐页复验、各页 tip 逐字段相同且等于钉住 tip_hash、首锚=入参后锚=前页末头、跨页高度/prev_hash 连续、缺页/重页/乱序/pending 后续页 integrity、pending 只许全批末头、末页必达 tip、空页仅锚点即 tip、成功键序 ok,anchor,tip,pages,verified_block_hashes 按链序不含锚点、input/auth/integrity 分类、跨轮换版本混排可验）
python tests/header_locator_test.py    # 签名区块头分叉定位 POST /v1/chain/headers/locate（仅含顺序键 locators,limit；locators 1–64 项 height,block_hash 严格降序非布尔非负整数/64hex；limit 1–500 默认100、拒布尔；解析/键值非法 400 无副作用；顺序取首个主链同高同哈希命中否则 409；200 键序 anchor,headers,tip,auth 升序至多 limit 空页照签；主链+签名者同锁快照；verify_header_locator_page 成功 ok,anchor,tip,matched_index,verified_block_hashes 索引从0、失败仅 ok,error input/auth/integrity 不抛异常）与 HTTP
python tests/light_client_apply_finality_test.py  # 签名最终化凭证 GET /v1/chain/finality（无参数否则 400；锁内同快照取链与签名者；200 固定键序 finalized,tip,auth，finalized=最后 confirmed 块键序 height,block_hash、tip 沿用 S、auth 键序 key_version,signature；domain=ledger-finality-v1 的 SHA-256+Ed25519 签名、轮换历史可验）与 apply_finality（键序/非布尔整数/64hex/128hex input、未知版本或坏签名 auth、tip 须等于本地重放 tip、finalized 须为分支 anchor/confirmed 头且不倒退否则 integrity、存量解析/键序/摘要/重放 state、缺文件或读写失败 io；同目标幂等不写文件、提高边界 generation+1 沿用 v3 原子换入；失败仅 ok,error、不抛异常、字节不变）与 HTTP
python tests/light_client_apply_finality_pages_test.py  # 可分页最终化历史的轻客户端原子消费 apply_finality_pages（pages 非空数组、逐页严守 GET /v1/chain/finalities 键序/类型/ledger-finality-v1 签名契约；各页 head 逐字段相同且 head.tip 等于本地 tip、首锚=已存 finalized、后锚=前页 next、非末页非空且 next=末项 finalized、末页 next=null 到达 head.finalized、仅单页可在 anchor 已是 head 时为空、凭证连续匹配本地 confirmed 分支且 tip 为对应块的 S，违者 integrity；结构/键序/类型 input、未知版本或坏签名 auth、存量损坏 state、缺文件或读写 io；全批通过才 generation+1 按 v3 原子推进至 head、空终页幂等字节不变；成功键序 ok,generation,finalized,pages,applied；失败仅 ok,error、不抛异常、字节不变）
python tests/attested_range_sync_test.py  # 签名增量区间 POST /v1/forks/sync/range/attested（domain=ledger-sync-range-v1 的 canonical SHA-256+Ed25519；400→403→410→403→409→400→409 优先级；冻结公钥/版本/签名/指纹；重试冻结公钥验签 403/重验 400/不同 409/相同 200；独立幂等命名空间；mode=attested 采用/过期事件、原子落盘回滚、重启重验与静默丢弃；syncs/history 纳入 attested/all）与 HTTP/CLI
python tests/sync_history_test.py     # 同步生命周期历史 GET /v1/forks/sync/history（冻结摘要、过滤/严格数值/重复参数 400、排序分页、采用/过期不改写、重启兼容）与 HTTP/CLI
python tests/sync_mode_query_test.py   # syncs 与 sync-history 的可选 mode 查询（缺省/plain 普通、attested 签名、all 合并；非法/重复 mode 400；合并 (height,tip_hash,source,mode,request_id) 稳定排序分页；item 不新增 mode 字段；两模式同 tip 不互删；CLI --mode 原样转发）与 HTTP/CLI
python tests/sync_export_test.py       # 同步记录导出 GET /v1/forks/sync/export（source/request_id/mode 三参数必填单值，缺失/重复/未知 400；固定键序与类型；plain 五字段 candidate+attestation null、attested 签名候选+冻结公钥/版本/签名并按 domain/冻结公钥/指纹重验；range 记录 409；未知/过期/清理后 404；fork 或 canonical 前缀重建不增副本；签名/摘要失配丢缓存留审计；清理落盘失败恢复并抛 OSError；重启一致）与 HTTP/CLI sync-export
python tests/sync_range_export_test.py  # 区间记录导出 GET /v1/forks/sync/range/export（三参数必填单值 400；未知/过期/清理后 404；整链记录 409；固定键序 source,request_id,mode,expires_at,anchor,blocks,tip,attestation；tip 由 anchor+blocks 重算；attested 冻结公钥/版本/签名按 ledger-sync-range-v1 重验；链/Merkle/指纹/签名失配丢缓存留审计 404；清理落盘失败恢复抛 OSError；采用后 canonical 前缀重建；重启一致）与 HTTP/CLI sync-range-export
python tests/sync_authorization_test.py  # sync 来源授权闸门（403/410/400 优先级、新请求授权）、跨越轮换/撤销/过期的幂等回放、重启重新授权丢弃失效记录并为停机期间到期/失权记录补写去重且连续的 sync_expired（已采用 tip 不动 canonical）、保存失败完整恢复（链/候选/元数据/generation/事件）、HTTP/CLI
python tests/light_client_test.py     # 离线轻客户端验证（input/auth/expired/integrity/proof、Ed25519 验签、重算链、proof 唯一性、pending 禁令、CLI）
python tests/range_export_verify_test.py  # 区间导出离线核验 verify_range_export（固定顶层键序、expected_anchor 严格相等、尾部重算与 pending 末块、tip 摘要、plain allowlist+attestation null、attested 钉住公钥+ledger-sync-range-v1 签名、input/auth/expired/integrity 分类、CLI verify-range 文件/stdin/退出码）
python tests/range_export_batch_verify_test.py  # 多页增量区间离线连续核验 verify_range_exports（非空数组、逐页复验、首锚=expected_anchor 后锚=前页 tip{height,block_hash}、断锚/跳高/重叠 integrity、tx_id 跨页唯一、pending 只许末页、成功键序 ok,anchor,tip,pages,verified_tx_ids 升序、input/auth/expired/integrity 分类、CLI verify-range-batch 文件/stdin/退出码）
python tests/source_key_history_test.py  # 来源公钥历史 source_key_history（注册写版本1及事件号、轮换递增记新事件、撤销保留历史、原子落盘回滚；GET /v1/trust 固定键序 genesis_hash,sources,allowlist,audit_signers,source_key_history 与项键序 version,public_key,activated_event_id；重启逐字节保留、旧快照内存重建不强制写盘、历史结构/事件不符 StateRecoveryError；verify_range_export 按 attestation.version 取历史公钥并匹配 attestation.public_key，未知项 auth、签名错 integrity、无历史旧规、畸形 input；HTTP 线序）
python tests/light_client_state_proof_test.py  # 轻客户端账户状态扩展（state_root/state_height/state_block_hash/state_proofs 全有或全无与严格形状 input、锚点 integrity、账户升序集合/index/唯一性/verify_account_proof proof、verified_accounts、账户 proof 未知/重复参数 400、CLI）
python tests/trust_audit_test.py       # 持久化来源信任（注册201/幂等200/冲突409、轮换404/409、撤销404/409/幂等）、审计分页与过滤、同步接收/采用/过期事件、原子落盘与回滚、重启持久化、损坏与同代冲突恢复拒绝、HTTP/CLI
python tests/audit_chain_test.py       # 审计哈希链向量、检查点、追加失败回滚与恢复补链（旧快照一次补链/错配拒绝）、同代检查点冲突、GET /v1/audit/export 锚点与分页、重复参数 400、CLI audit-export/audit-verify（ok+checkpoint 或 input/integrity、退出码 0/1）
python tests/audit_signer_test.py      # 可轮换 Ed25519 检查点认证：首版密钥生成、POST /v1/audit/signer/rotate（400/409/200、audit_signer_rotated 事件、历史公钥保留）、导出 checkpoint_auth、离线 --trust 核验（创世锚/密钥版本/签名/跨页一致，失败新增 auth）、写盘失败回滚、签名者严格恢复（错配拒绝/无签名旧快照唯一胜者一次性迁移/同代签名者冲突）、HTTP/CLI
python tests/strict_type_validation_test.py  # 跨入口严格类型校验：height/amount 的字符串/浮点/布尔伪装在候选分叉与同步入口 400（不写状态、不回放 200）、离线 verify 返回 input、canonical/pending 恢复抛 StateRecoveryError、持久化候选/同步记录按缓存规则丢弃、旧快照缺省 status 兼容
python tests/consistency_verify_test.py   # 离线快照整体一致性 verify_snapshot：成功摘要与固定键序、缺区段/未知顶层键/类型伪装 input、交易/签名/Merkle/区块哈希/链接/索引/账户/state_root/pending 唯一性/审计链与检查点篡改 integrity、CLI consistency（退出码 1/0/1，IO/非 JSON 为 input）
python tests/history_http_test.py  # 节点托管 /v1/history/trust 与 /v1/history/export（--history/--history-trust/--history-token 全有/全缺否则退出2、Bearer 401 无副作用、读缺失 500/io、追加 201/幂等 200、导出 200 页离线 verify_history_trust 可验、400/403/409/500 与 {"ok":false,"error"}、history_access 事件键序 action,trust_head,history_head 与 null 头、共锁并发、快照写盘失败恢复信任日志原字节与内存事件、重启重验文件并绑定末条 history_access、篡改/坏事件 StateRecoveryError(path,reason)）
python tests/history_credential_test.py  # 持久分权凭据 POST /v1/history/access（仅静态 TOKEN；首创 201 版本0/更新 200 版本+1/撤销保留 hash 与权限/幂等重复撤销；token_hash=SHA256(token UTF8) 不落明文、响应键序 version,token_hash,permissions,status；格式错 400/input、版本冲突 409/state；permissions 归一化 read/update/export；静态全权、活动凭据按 read/update/export 分权、无效 401/unauthorized、缺权 403/forbidden 且无副作用、凭据不能管理凭据；history_credential 快照区段与 history_credential_changed 事件原子落盘、写盘失败回滚、重启保留、篡改区段/事件 StateRecoveryError(path,reason)；特性关闭时 404）
```

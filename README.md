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
  `limit`（默认 50，范围 1–200）、`cursor`（默认 0）。数值参数必须是首位非 0 的
  十进制（`0` 合法），非法值 `400`，`min_height > max_height` 也是 `400`。结果按
  `(height, tip_hash, source)` 升序，返回 `{items, total, next_cursor}`；
  `cursor == total` 返回空页，`cursor > total` 返回 `400`，没有更多结果时
  `next_cursor` 为 `null`。每个 item 含
  `{source, request_id, tip_hash, height, length, status, expires_at}`。
- **生命周期历史查询**：`GET /v1/forks/sync/history` 以只增审计历史为数据源，
  每个同步生命周期的每个阶段一行。支持 `source`、`tip_hash`、`kind`、
  `min_height`、`max_height`、`limit`（默认 50，范围 1–200）、`cursor`（默认
  0）。`tip_hash` 必须是 64 位小写十六进制：格式错误 `400`，未知值只返回空页；
  `kind` 只允许 `sync_received`、`sync_adopted`、`sync_expired`，未知值 `400`。
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

## 持久化来源信任与审计

轻客户端所需的信任文档不再靠手工维护：节点持久化保存**来源信任注册表**、
**allowlist** 与一条**只增审计事件流**，与链、状态、候选分叉和同步记录在同一份
原子快照中落盘；任何一次信任变更都与其审计事件一起提交，写盘失败一并回滚。

- **注册来源**：`POST /v1/trust/sources`，请求体
  `{"source","public_key","expires_at"}`：`source` 必须是非空字符串，
  `public_key` 必须是 64 位小写十六进制（Ed25519 公钥），`expires_at` 必须是
  整数（拒绝布尔）。合法新建返回 `201` 与 `{source, public_key, expires_at,
  version, status}`，其中 `version=1`、`status=active`；同一来源以**完全相同**
  的 `(public_key, expires_at)` 重试是幂等的，返回 `200` 与既有记录（不产生
  新版本或新事件）；内容不同返回 `409`；字段非法返回 `400`。
- **轮换公钥**：`POST /v1/trust/sources/{source}/rotate`，请求体
  `{"public_key","expires_at","expected_version"}`。未知来源或已撤销来源
  返回 `404`；`expected_version` 与当前版本不符返回 `409`；成功则安装新公钥、
  保持 `active`、`version` 递增并返回 `200`。
- **撤销来源**：`POST /v1/trust/sources/{source}/revoke`，请求体
  `{"expected_version"}`。未知来源 `404`；版本不符 `409`；成功置
  `status=revoked` 并返回 `200`，对已撤销来源以记录版本重复撤销是幂等的
  （仍 `200`，不产生第二条事件）。已撤销来源不能再轮换。
- **信任文档**：`GET /v1/trust` 返回离线验证所需的
  `{"genesis_hash","sources","allowlist","audit_signers"}`：`genesis_hash` 固定
  锚定 canonical 创世块；`sources[source] = {public_key, expires_at}` 只包含
  **未过期且未撤销**的来源（`expires_at <= now` 即剔除）；持久化的
  `allowlist[source] = expires_at` 原样保留；`audit_signers` 按 `version`
  升序列出节点曾经持有的**全部**审计检查点签名公钥，每项
  `{version, public_key, activated_event_id}`，首版 `activated_event_id` 为
  `0`。该文档可直接作为 `ledger verify --trust` 的输入，其 `genesis_hash`
  与 `audit_signers` 也供 `ledger audit-verify --trust` 使用。
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
  其事件 id 即新密钥的 `activated_event_id`）。事件一旦写入永不删除：候选
  **采用或过期之后仍可按 source/kind 分页查询**。
- **恢复语义**：信任注册表、allowlist 与审计流是权威配置而非可丢弃缓存，
  快照恢复时逐项严格校验（公钥格式、整数、正版本号、合法状态；`event_id`
  必须从 1 起连续无重复；每条 `prev_hash`/`event_hash` 必须重算一致，
  `audit_checkpoint` 必须钉住真实链头）。审计检查点签名者同样严格校验：
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

## 离线轻客户端验证

不持有链状态、也不连接服务端的客户端，可以凭一份**证明束**（bundle）与本地
**信任文档**（trust）离线核对响应：

- **bundle**：`{source, expires_at, response, candidate, proofs[, signature]}`。
  `expires_at` 是 Unix 秒；`candidate` 是自创世块起的完整块数组（也接受现有
  导出五字段文档）；`proofs` 为 `{height, proof}` 列表，`proof` 即
  `/proof/` 接口返回的 `{height, tx_id, index, merkle_root, block_hash,
  siblings}` 文档；`signature` 可选，为 Ed25519 签名的十六进制。
- **trust**：`{genesis_hash, sources, allowlist}`（`GET /v1/trust` 还会带
  `audit_signers`，轻客户端束验证忽略该额外字段）。`genesis_hash` 锚定创世
  块；`sources[source] = {public_key, expires_at}`；
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

成功返回 `{ok: true, source, S, verified_tx_ids}`（`verified_tx_ids` 为按
tx_id 升序的已验证交易列表）；失败返回 `{ok: false, error}`，`error` 仅取
`input` / `auth` / `expired` / `integrity` / `proof` 五类：

| error | 含义 |
| --- | --- |
| `input` | bundle/trust 结构或字段类型不合法（含非 64 位十六进制公钥、布尔数值） |
| `auth` | 来源不受信、受信来源缺签名，或 allowlist 来源带了无法核对的签名 |
| `expired` | 束或信任条目已过期 |
| `integrity` | 签名错误、链重算不一致（创世块/prev_hash/tx_id/签名/Merkle/block_hash）或 response 与链尾不符 |
| `proof` | proof 重复、字段与区块不一致、Merkle 路径无效或指向 pending 链尾 |


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
- **最后一页**的链尾（空日志则为 64 个 0）必须与其 `checkpoint` 完全匹配。

输出恒为**单行 JSON**：成功 `{"ok": true, "checkpoint": {event_id,
event_hash}}`，进程退出码 0；失败
`{"ok": false, "error": "input"|"integrity"|"auth"}`，退出码 1。`input`
表示输入无法读取/不是 JSON、或文档结构字段缺失/类型非法；`integrity`
表示锚点、连续编号、任一哈希链接、分页计数或末页检查点不一致。
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

## 实现说明

代码全部在 `ledger/` 包中：

| 文件 | 职责 |
| --- | --- |
| `ledger/crypto.py` | Ed25519 验签/签名/密钥推导与生成、规范化交易消息、SHA-256 tx_id、Merkle 根与包含证明 |
| `ledger/models.py` | Transaction / Block 模型（含 pending/confirmed 状态）与确定性区块哈希 |
| `ledger/audit.py` | 审计事件哈希链：规范化事件哈希、整链链接、`audit_checkpoint` 计算与严格校验，检查点 Ed25519 认证对象的签名/验签，以及导出页的离线核验（锚点、连续编号、哈希、末页检查点、可选信任文档下的检查点认证） |
| `ledger/store.py` | 链（含候选分叉）、状态、待打包集合、索引、账户、持久化来源信任注册表、allowlist、可轮换审计检查点 Ed25519 签名者（含历史公钥）与带哈希链/检查点的只增审计事件流的 JSON 原子持久化（fsync 快照 + 原子改名）、generation、创世区块、候选分叉整链校验、采用时原子换链、启动快照扫描、旧快照补链/签名者迁移与崩溃恢复 |
| `ledger/service.py` | 提交校验（签名、金额、余额）、打包、确认/回滚状态机、查询，候选分叉的提交校验、链比较与原子采用，来源信任注册/轮换/撤销、审计签名者轮换、信任文档、审计分页、哈希锚定导出（含检查点认证）与同步事件登记 |
| `ledger/server.py` | 标准库 `http.server` 实现的 REST 接口 |
| `ledger/light_client.py` | 离线轻客户端：受信来源/过期/Ed25519 验签、从创世锚重算整条候选链、核对 response 与 Merkle proofs |
| `ledger/cli.py` | `send` / `mine` / `block` / `account` / `proof` / `confirm` / `rollback` / `status` / `candidates` / `chain` / `chain-range` / `adopt` / `export` / `index` / `sync` / `sync-range` / `syncs` / `trust add|rotate|revoke|export` / `audit` / `audit-export` / `audit-signer-rotate` / 离线 `verify` / 离线 `audit-verify [--trust]` 子命令 |

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

# 增量区间：仅推送锚点之后的尾部区块（拼接 canonical 前缀做整链重验；
# 状态优先级 400→403→410→锚点 409→重验/tip 400→重复 409；201 五字段，
# 同 source+request_id 同内容重试 200 首次结果、异内容 409）
curl -s -X POST localhost:8080/v1/forks/sync/range \
  -H 'Content-Type: application/json' \
  -d '{"source":"node-2","request_id":"req-8","expires_at":1800000000,"anchor":{"height":2,"block_hash":"..."},"blocks":[{...}],"tip":{"tip_hash":"...","height":4,"length":5,"status":"confirmed"}}'
# -> 201 {"tip_hash":"...","height":4,"length":5,"status":"confirmed","expires_at":1800000000}

# 同步审计查询（source/min_height/max_height/limit/cursor；非法数值 400）
curl -s 'localhost:8080/v1/forks/sync?source=node-2&min_height=1&limit=50&cursor=0'
# -> 200 {"items":[{source,request_id,tip_hash,height,length,status,expires_at}...],"total":N,"next_cursor":null}

# 同步生命周期历史（source/tip_hash/kind/min_height/max_height/limit/cursor；
# tip_hash 或 kind 格式错误 400，未知 tip_hash 空页，非法数值或重复参数 400）
curl -s 'localhost:8080/v1/forks/sync/history?source=node-2&kind=sync_adopted&limit=50&cursor=0'
# -> 200 {"items":[{event_id,kind,at,source,request_id,tip_hash,height,length,status,expires_at}...],"total":N,"next_cursor":null}

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

# 候选分叉：candidates 参数为块数组（或 {"blocks":[...]} 对象）的 JSON
python -m ledger.cli candidates '[{"height":0,...},{"height":1,...}]'
python -m ledger.cli chain
python -m ledger.cli adopt <tip-hash>

# 导出候选分叉与确认链交易索引
python -m ledger.cli export <tip-hash>
python -m ledger.cli index [--tx-id <hex>] [--account <pubkey-hex>] [--height N] [--cursor N] [--limit N]

# 节点间候选链同步与审计查询
python -m ledger.cli sync --source node-2 --request-id req-7 --expires-at 1800000000 '<export 文档或块数组 JSON>'
python -m ledger.cli syncs [--source node-2] [--min-height N] [--max-height N] [--cursor N] [--limit N]
python -m ledger.cli sync-history [--source node-2] [--tip-hash <64-hex>] [--kind sync_received|sync_adopted|sync_expired] [--min-height N] [--max-height N] [--cursor N] [--limit N]

# 增量区间：chain-range 拉取（可把整页 JSON 直接交给 sync-range 推送，tip 自动派生）
python -m ledger.cli chain-range --after-height 2 --after-hash <block-hash> [--limit 100]
python -m ledger.cli sync-range --source node-2 --request-id req-8 --expires-at 1800000000 '{"anchor":{"height":2,"block_hash":"..."},"blocks":[{...}],"tip":{...}}'
# range 文档也可以是 chain-range 的整页输出，或用 - 从标准输入读取

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

# 离线轻客户端验证（不连接服务端；--bundle - 从标准输入读取束 JSON）
python -m ledger.cli verify --bundle bundle.json --trust trust.json
cat bundle.json | python -m ledger.cli verify --bundle - --trust trust.json
# -> 成功单行 {"ok":true,...} 退出 0；失败单行 {"ok":false,"error":"..."} 退出 1
```

非 2xx 响应同样打印单行 JSON 并以退出码 1 结束。

## 基础测试

```bash
python -m compileall -q ledger   # 编译检查
python tests/smoke_test.py       # 不依赖网络的全流程冒烟测试
python tests/merkle_proof_test.py  # Merkle 证明（crypto/service/HTTP/CLI）与接口回归
python tests/confirm_rollback_test.py  # 确认/回滚状态机（service/HTTP/CLI/重启重建）
python tests/recovery_test.py         # generation、多区块一致性、快照恢复、损坏拒绝、并发串行化
python tests/fork_test.py             # 候选分叉校验、链比较、原子采用、内存池去重、重启重校验
python tests/export_index_test.py     # 分叉导出、导出格式候选重验、确认链交易索引与 CLI
python tests/fork_sync_test.py        # 节点间候选链同步（201/200/400/409/410、幂等、审计分页、过期、采用、重启）与 HTTP/CLI
python tests/range_sync_test.py       # 增量区间协议（GET /v1/chain/range 分页/严格参数/404/409/pending 尾块；POST /v1/forks/sync/range 状态优先级、拼接整链重验、201五字段、脱离 canonical 的200重试、最长链采用、失败回滚、重启指纹核验）与 HTTP/CLI
python tests/sync_history_test.py     # 同步生命周期历史 GET /v1/forks/sync/history（冻结摘要、过滤/严格数值/重复参数 400、排序分页、采用/过期不改写、重启兼容）与 HTTP/CLI
python tests/sync_authorization_test.py  # sync 来源授权闸门（403/410/400 优先级、新请求授权）、跨越轮换/撤销/过期的幂等回放、重启重新授权丢弃失效记录并为停机期间到期/失权记录补写去重且连续的 sync_expired（已采用 tip 不动 canonical）、保存失败完整恢复（链/候选/元数据/generation/事件）、HTTP/CLI
python tests/light_client_test.py     # 离线轻客户端验证（input/auth/expired/integrity/proof、Ed25519 验签、重算链、proof 唯一性、pending 禁令、CLI）
python tests/trust_audit_test.py       # 持久化来源信任（注册201/幂等200/冲突409、轮换404/409、撤销404/409/幂等）、审计分页与过滤、同步接收/采用/过期事件、原子落盘与回滚、重启持久化、损坏与同代冲突恢复拒绝、HTTP/CLI
python tests/audit_chain_test.py       # 审计哈希链向量、检查点、追加失败回滚与恢复补链（旧快照一次补链/错配拒绝）、同代检查点冲突、GET /v1/audit/export 锚点与分页、重复参数 400、CLI audit-export/audit-verify（ok+checkpoint 或 input/integrity、退出码 0/1）
python tests/audit_signer_test.py      # 可轮换 Ed25519 检查点认证：首版密钥生成、POST /v1/audit/signer/rotate（400/409/200、audit_signer_rotated 事件、历史公钥保留）、导出 checkpoint_auth、离线 --trust 核验（创世锚/密钥版本/签名/跨页一致，失败新增 auth）、写盘失败回滚、签名者严格恢复（错配拒绝/无签名旧快照唯一胜者一次性迁移/同代签名者冲突）、HTTP/CLI
python tests/strict_type_validation_test.py  # 跨入口严格类型校验：height/amount 的字符串/浮点/布尔伪装在候选分叉与同步入口 400（不写状态、不回放 200）、离线 verify 返回 input、canonical/pending 恢复抛 StateRecoveryError、持久化候选/同步记录按缓存规则丢弃、旧快照缺省 status 兼容
```

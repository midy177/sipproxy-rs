# sigproxy-rs Implementation Plan

## 背景

`sigproxy-rs` 当前目标是实现一个七层 stateless SIP-aware 负载均衡/代理服务器。

参考 `rustpbx` 的方向：

- 使用 `rsipstack` 处理 SIP message、header、URI、transport 相关能力。
- 参考 rustpbx 的 REGISTER/location 处理思路。

核心定位：

- 默认模式是 `stateless-lb`。
- 做 SIP-aware affinity/session persistence。
- 不做完整 PBX。
- 不做 B2BUA。
- 不默认维护 SIP transaction。
- 高可用只保留最简单的 active-standby，可选启用。

## 目标

1. 实现七层 SIP-aware LB/proxy。
2. 支持 UDP/TCP SIP 监听。
3. 默认提供 `stateless-lb` 模式：不维护 SIP transaction，但按 SIP 头、URI、Call-ID、dialog-id 做亲和性和会话保持。
4. 支持 REGISTER/location 状态维护，用于 AOR 亲和和后续路由。
5. 支持 INVITE/ACK/BYE/CANCEL/OPTIONS/MESSAGE 等常见 SIP 方法转发，并让相关消息尽量命中同一 upstream。
6. 使用 `clap` 提供子命令式配置、校验和启动入口。
7. 支持可选 active-standby：心跳判活、角色切换、snapshot/pull 状态同步，以及 VIP/EIP hook 边界。

## 非目标

第一阶段不做以下能力：

- 完整 PBX。
- 完整 B2BUA。
- RTP/media proxy。
- IVR、坐席、录音、计费等业务能力。
- active-active 多写集群。
- 内置云厂商 EIP/VIP API 实现。
- 默认主路径不维护完整 SIP transaction。
- 默认主路径不使用完整 `rsipstack::dialog`。

云厂商 EIP、内网 VIP、LB target 切换等入口漂移通过 HA addon hook 扩展。

## 架构

### `sip`

负责 SIP 七层协议处理：

- 基于 `rsipstack::sip` 的 SIP message parser/serializer。
- 使用 `rsipstack` 的 Request/Response/Header/Uri typed API，避免手写协议解析。
- Via、Record-Route、Route、Contact、Call-ID、CSeq、From、To 等关键头处理优先复用 `rsipstack` typed header。
- 构造本地响应，例如 `200 OK`、`404 Not Found`、`503 Service Unavailable`。

原则：不手写 SIP parser、URI parser、header parser、Content-Length framing 和标准 header 渲染；除非 `rsipstack` 没有暴露足够能力，才在本项目里加薄封装。

### `proxy`

负责 SIP-aware LB 主路径：

- 默认 `stateless-lb`：基于 SIP message 解析和轻量路由状态转发，不维护 SIP transaction。
- 静态路由匹配。
- SIP-aware affinity/session persistence。
- REGISTER 处理。
- location registry 查询。
- 请求转发到 upstream 或 registered contact。
- 响应回传。
- 后端健康检查。
- 预留认证、ACL、限流、路由 webhook 扩展点。

`stateless-lb` 仍优先复用 `rsipstack` 能力：

- `rsipstack::sip` 解析和序列化。
- typed `Via`、`Contact`、`Route`、`Record-Route`、`From`、`To`、`Call-ID`、`CSeq`。
- `rsipstack::transport` 的 UDP/TCP transport 和 TCP message framing，若能与 LB 主循环干净集成。
- `rsipstack` 的 URI/HostWithPort/Transport 类型。

### `affinity`

维护 SIP-aware session persistence，不维护 transaction 状态。

支持 key：

- `aor`
- `call-id`
- `dialog-id`
- `from`
- `to`
- `request-uri`
- `via-branch`

维护映射：

- `aor -> upstream`
- `call-id -> upstream`
- `dialog-id -> upstream`
- `branch -> upstream/client peer`
- `registered contact -> upstream/client peer`

用于：

- REGISTER 和后续请求命中同一 registrar/PBX。
- 同一个 INVITE、CANCEL、非 2xx ACK 尽量转发到同一后端。
- dialog 内 BYE/re-INVITE/UPDATE 命中原后端。
- active/standby 切换后恢复关键路由亲和。

### `ha`

HA 是可选部署能力，不改变 stateless SIP-aware proxy 主路径。

当前 active-standby 范围：

- 节点角色状态机。
- 心跳收发。
- failover 检测。
- epoch 管理。
- floating endpoint promote/demote/check。
- fencing hook。
- active 到 standby 状态同步。

floating endpoint 不限定实现，可以是：

- 云 EIP。
- 内网 VIP。
- keepalived/VRRP 管理的 VIP。
- 云 LB 后端权重/target 绑定。
- 防火墙/NAT 规则。
- 其他由脚本或 addon 控制的入口资源。

### `replication`

状态同步属于 active-standby 可选能力，不参与单节点主路径。

当前同步对象：

- REGISTER location。
- affinity binding。
- epoch。
- active 节点元信息。

后续可增强：

- WAL-like append log。
- snapshot checksum。
- 状态压缩。
- SQLite 本地持久化存储。
- active -> standby 增量事件复制。

### `config`

负责配置结构、加载、保存样例和校验：

- node 配置。
- SIP 全局配置。
- proxy listener/upstream/route 配置。
- affinity 配置。

### `bin/sigproxy`

使用 `clap` 提供子命令：

- `sigproxy run --config config.toml`
- `sigproxy config init --output config.toml`
- `sigproxy config check --config config.toml`

## Proxy Mode

### 默认模式：`stateless-lb`

`stateless-lb` 不维护 SIP transaction 状态，不负责重传、transaction timeout、response cache 和 fork transaction。它比四层 LB 更懂 SIP，能基于 SIP 字段做一致路由。

请求路径：

1. 使用 `rsipstack::sip` 解析 SIP message。
2. 使用 typed API 提取 method、Request-URI、Route、Call-ID、From/To tag、AOR、Via branch。
3. 根据 listener 和 route 选择 upstream group。
4. 根据 affinity key 查表。
5. 命中则转发到已绑定 upstream。
6. 未命中则按 upstream group 策略选择后端，并写入 affinity table。
7. 使用 `rsipstack` header 类型添加/更新 proxy Via，必要时 Record-Route。
8. 按代理规则处理 `Max-Forwards`：缺失时补 `70`，大于 0 时递减，等于 0 时返回 `483 Too Many Hops`。
9. 对 INVITE 记录轻量 transaction route，使 CANCEL 和非 2xx ACK 能命中原 INVITE upstream。
10. 直接转发到目标 upstream。

响应路径：

1. 使用 `rsipstack::sip` 解析响应。
2. 读取顶部 Via branch，确认该 branch 是本 proxy 请求转发时生成的 proxy branch。
3. 使用 `branch -> client peer/listener/transport/upstream` 的轻量映射找回客户端方向。
4. 移除 proxy 自己添加的顶部 Via。
5. 将剩余响应回传给原始客户端。
6. 对 UDP upstream，复用稳定的 proxy listener socket 或专门 upstream socket 接收响应，不为每个请求创建临时 UDP socket。
7. 对 INVITE，允许同一个 branch 映射接收多个 provisional/final response，不在第一个响应后立即删除映射。

UDP 主路径执行规则：

1. 请求转发时添加 proxy Via，并记录 `branch -> client peer/listener/transport/upstream`。
2. upstream 响应回来后用 `rsipstack` 解析响应。
3. 确认顶部 Via 是本 proxy 添加的 branch。
4. 移除顶部 proxy Via。
5. 根据 branch 映射把响应发回客户端。
6. INVITE 的 `100 Trying`、`180 Ringing`、`183 Session Progress`、`200 OK` 等多个响应都走同一映射。
7. UDP upstream 响应不能依赖“发送后同步等待一个响应”的临时 socket 模型。

TCP 主路径执行规则：

1. SIP over TCP 是长连接，必须按 `Content-Length` 做 message framing，不能把一次 TCP read 当成一个 SIP message。
2. downstream TCP 连接需要循环读取多个 SIP message。
3. 请求转发时同样添加 proxy Via，并保留该请求的 proxy branch。
4. upstream TCP 响应逐条读取、逐条用 `rsipstack` 解析、校验顶部 Via branch、移除 proxy Via。
5. INVITE 响应需要持续转发多个 provisional response，直到收到 final response。
6. 非 INVITE 第一阶段按一个最终响应处理，后续可扩展为更完整的 transaction-aware 行为。
7. upstream TCP 使用按后端地址复用的长连接池，后台 reader 按 proxy Via branch 分发响应。
8. TCP framing 复用 `rsipstack::transport::stream::SipCodec`，覆盖粘包、半包、短格式 `l:` 和 CRLF keepalive。

`rsipstack::transport::TransportLayer` 不接入当前主路径，因为它会接管 connection/event/endpoint 流程，更适合 transaction endpoint 或 B2BUA。当前 stateless LB 只复用其中可独立使用的 `SipCodec`。

INVITE/CANCEL/ACK 路由规则：

1. INVITE 转发时记录 `client Via branch + Call-ID + CSeq number -> upstream target`，TTL 300 秒。
2. CANCEL 和 ACK 先按上述 lightweight transaction route 查找 upstream。
3. 未命中时退化到 dialog affinity、Call-ID affinity 或普通 upstream 选择。
4. 不实现重传缓存、transaction timeout 状态机、fork transaction 或 response aggregation。

### Kernel / XDP 边界

AF_XDP/XDP 不作为当前七层 SIP proxy 主路径：

1. SIP proxy 必须修改 Via/Record-Route 等 L7 报文，不能只做零拷贝包转发。
2. SIP over TCP 依赖内核 TCP 栈的长连接、重传、拥塞控制和 stream framing，AF_XDP 绕过内核 TCP 后需要自实现或引入用户态 TCP 栈，复杂度过高。
3. UDP SIP 理论上可做 AF_XDP fast path，但需要处理 IP/UDP checksum、分片、GRO/GSO、MTU、报文修改和 userspace routing，收益不适合第一阶段。
4. 第一阶段优先优化普通 socket 路径：稳定 UDP socket、TCP 连接复用、SO_REUSEPORT、socket buffer、批量收发和 worker sharding。
5. XDP 更适合作为 addon：源地址 ACL、DDoS drop、粗粒度分流、metrics、SO_REUSEPORT/eBPF steering。

REGISTER：

1. 使用 `rsipstack` typed header 解析 AOR、Contact、Expires。
2. 更新 location registry。
3. 根据配置写入 AOR affinity。
4. active 将 location/affinity 复制给 standby。

REGISTER 路由模式：

1. 默认使用 `register_routing = "path"`：不改 Contact，只在 REGISTER 上添加 Path，并依赖 PBX/registrar 在后续请求中使用 Route。这是标准 proxy / PLB 优先模式。
2. 可选使用 `register_routing = "contact-rewrite"`：将 Contact 改写为 sigproxy 可达地址，用于 PBX/registrar 不支持 Path 或 NAT 场景的兼容模式。
3. `rewrite_register_contact = true` 仅作为历史配置兼容入口，后续配置和文档优先使用 `register_routing`。

`contact-rewrite` 模式：

1. 将发往 PBX/registrar 的 Contact 重写为 sigproxy 可达地址。
2. rewritten Contact 的 user 部分携带稳定 token，用于区分同一 AOR 下的多设备、多连接、多租户 Contact。
3. 重写后的 Contact 不保留 `;ob`，避免被上游误判为 RFC 5626 outbound flow。
4. 本地保存 `rewritten Contact -> original Contact`，后续 PBX 呼入 rewritten Contact 时转回对应客户端。
5. 该模式不终止 dialog，也不重写 Call-ID / tag / CSeq，因此不是完整 B2BUA；但它会改 Contact，不能称为纯透明 proxy 模式。

后续可增强：

1. 将当前轻量 token 生成切换为 BLAKE3。
2. 支持 keyed BLAKE3，配置 `contact_token_secret`，避免 token 可被外部推测。
3. 生产环境要求显式配置稳定 secret；开发环境可自动生成临时 secret。
4. token 长度可配置，默认保持 16 到 20 个 hex 字符，兼顾低碰撞和 Contact 可读性。
5. 完整 RFC 5626 outbound 支持作为独立模式设计，不与当前轻量 Contact rewrite 混用。

CANCEL / ACK / BYE / re-INVITE / UPDATE：

1. 优先使用 dialog affinity：`Call-ID + From tag + To tag`。
2. tag 不完整时退化到 `Call-ID`。
3. 再退化到 Via branch 或 Request-URI affinity。

### 可选未来模式：`stateful-proxy`

如果后续需要更强 SIP 事务正确性，可新增 `stateful-proxy`：

- 基于 `rsipstack::transaction` 的 server/client transaction 转发。
- 超时、重传、branch、ACK/CANCEL 基础行为交给 `rsipstack::transaction`。

该模式不是当前目标。

### Dialog 边界

第一阶段不使用完整 `rsipstack::dialog`，不把系统变成 B2BUA。

保持透明转发：

- 不生成新的 Call-ID。
- 不重写 From tag / To tag。
- 不拆成两条独立 dialog。
- 不主动处理媒体和 SDP 协商。

只维护轻量 dialog affinity：

- `Call-ID`
- From tag
- To tag
- listener key
- selected upstream group / target
- last seen timestamp

## HA / Replication

当前范围只做 stateless SIP-aware proxy 和最简单的 active-standby 边界：
心跳/优先级决定 active，状态通过轻量 snapshot/pull 同步，floating endpoint
由 addon hook 对接 VIP/EIP/LB target 等外部入口资源。

## 配置样例

```toml
[node]
id = 1

[sip]
external_addr = "sip.example.com:5060"
max_message_bytes = 65535

[proxy]
record_route = true
register_routing = "path"

[proxy.socket]
reuse_port = false
workers_per_listener = 1
recv_buffer_bytes = 4194304
send_buffer_bytes = 4194304
tcp_nodelay = true

[proxy.metrics]
enabled = false
bind_addr = "127.0.0.1:9100"

[proxy.affinity]
enabled = true
key = "dialog-id"
ttl_seconds = 3600

[[proxy.upstream_groups]]
name = "pbx-a"
mode = "round-robin"
servers = ["10.0.1.10:5060", "10.0.1.11:5060"]

[proxy.upstream_groups.health_check]
enabled = true
interval_ms = 5000
timeout_ms = 1000
success_threshold = 2
failure_threshold = 3

[proxy.upstream_groups.health_check.probe]
mode = "options"
transport = "udp"
uri = "sip:healthcheck@pbx-a"
success_codes = [200, 202, 405, 481]

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "udp"
upstream_group = "pbx-a"

[[proxy.listeners]]
bind = "0.0.0.0:5060"
transport = "tcp"
upstream_group = "pbx-a"
```

## 实施阶段

### 阶段 1：配置和 CLI 收敛

交付：

- 默认 stateless SIP-aware proxy 行为，不额外暴露 `proxy.mode`。
- `[proxy.affinity]`。
- listener 到 upstream group 的显式配置。
- upstream health check 配置。
- stateless proxy 示例配置。

验收：

- `cargo check` 通过。
- `sigproxy config init` 生成 stateless proxy 配置。
- `sigproxy config check` 能校验 stateless proxy 配置。

### 阶段 2：SIP-aware affinity

交付：

- `rsipstack::sip` parser/serializer。
- typed header/URI 提取：
  - AOR
  - Call-ID
  - From tag
  - To tag
  - Request-URI
  - Route
  - Via branch
- affinity key 生成。
- affinity table：
  - TTL
  - 首次绑定
  - 后续命中
  - upstream unhealthy 时重绑定策略
- INVITE/CANCEL/ACK/BYE/MESSAGE 按 affinity 转发。

验收：

- 单元测试覆盖 affinity key。
- 单元测试覆盖 affinity table TTL。
- 同一 Call-ID/dialog-id 命中同一 upstream。
- 同一 AOR 的 REGISTER 命中同一 upstream。

### 阶段 3：转发正确性补强

交付：

- `Max-Forwards` 代理规则。
- INVITE lightweight transaction route。
- CANCEL / ACK 命中原 INVITE upstream。
- Record-Route 仅用于 dialog-forming 请求。
- BYE / re-INVITE / UPDATE 更细粒度测试。

验收：

- `Max-Forwards: 0` 返回 `483 Too Many Hops`，不转发 upstream。
- `Max-Forwards > 0` 转发前递减。
- 缺失 `Max-Forwards` 时补 `70`。
- 关闭 affinity 时，CANCEL 仍能命中原 INVITE upstream。

### 阶段 4：Active-standby 状态同步

当前实现使用 event-log 优先、snapshot 兜底的方式同步轻量路由状态：

- standby 优先拉取 active `/ha/events` 增量事件。
- event log 缺口、过期或不可用时 fallback `/ha/snapshot`。
- 同步 REGISTER location。
- 同步 affinity binding。
- 同步 active 节点角色元信息。

实现方式为：active 写内存 + SQLite WAL + event log，standby 拉增量事件，
snapshot 继续作为冷启动、恢复和一致性兜底。SQLite 只作为每个节点的
本地持久化与复制 checkpoint，不直接跨节点共享文件。

设计原则：

- SIP 转发热路径仍以内存 lookup 为主。
- SQLite 写入失败默认 fail-open，只记录 warning/metric；可配置
  `persistence.required = true` 时 fail-closed。
- standby 不接受外部写，只应用 active 的 event/snapshot。
- event 必须幂等，按 key 覆盖同一 contact/affinity binding。
- event 和 snapshot 都携带绝对 `expires_at_epoch_ms`，standby 不能续满 TTL。
- event pull 失败不阻塞 active SIP 转发，standby 依赖下一轮 event 或 snapshot 修正。
- 不同步 in-flight INVITE transaction、TCP 连接、socket/NAT 临时状态、upstream
  health 和 XDP kernel map；这些仍属于节点本地运行态。

SQLite schema 草案：

- `contacts(aor primary key, contact, source, expires_at_epoch_ms, updated_seq)`。
- `affinity(key primary key, target_addr, transport, expires_at_epoch_ms, updated_seq)`。
- `ha_events(seq integer primary key autoincrement, kind, key, payload_json, created_at_epoch_ms)`。
- `meta(key primary key, value)`，保存 `last_applied_seq`、schema version 等。

阶段 4.1：本地持久化恢复（已实现）

- 增加 `persistence` 配置：
  - `enabled`。
  - `path`，默认 `/var/lib/sigproxy-rs/ha/state.db`。
  - `required`，默认 `false`。
  - `event_retention_seconds`。
  - `cleanup_interval_ms`。
- 启动时打开 SQLite，启用 WAL、busy_timeout、foreign_keys。
- 从 SQLite 加载未过期 contacts/affinity 到内存。
- active 写 REGISTER contact 时同步写 SQLite contact 表。
- affinity 写入先只做低风险持久化，可按现有 TTL 写入 SQLite。
- 周期清理过期 contact/affinity 与过期 event。

阶段 4.2：增量事件日志（已实现）

- 每次状态变化 append `ha_events`：
  - `RegisterContact`。
  - `UnregisterContact`。
  - `UpsertAffinity`。
  - `RemoveAffinity`。
  - `ExpireAffinity`。
- active 写入顺序：
  - 内存 apply。
  - SQLite upsert/delete。
  - append event。
- 默认 SQLite/event append 失败不阻断 SIP 转发，但必须打 warning。
- `required = true` 时，SQLite 写失败返回错误，避免状态未落盘仍继续接写。

阶段 4.3：standby 增量拉取（已实现）

- 增加 `GET /ha/events?after=<seq>&limit=<n>`。
- 响应包含：
  - `base_seq`。
  - `events`。
  - `latest_seq`。
  - `snapshot_required`。
- standby 从本地 SQLite `meta.last_applied_seq` 开始拉事件。
- standby 检查 seq 连续性；缺口或 active event 已清理时 fallback `/ha/snapshot`。
- standby apply event 时同时更新内存、SQLite 和 `last_applied_seq`。

阶段 4.4：snapshot 兜底增强（已实现）

- snapshot 增加 `last_seq` 和 checksum。
- standby 安装 snapshot 时：
  - 替换内存 contacts/affinity。
  - SQLite 事务内替换 contact/affinity 表。
  - 更新 `meta.last_applied_seq = snapshot.last_seq`。
- standby 会校验 snapshot checksum，校验失败时拒绝安装。
- snapshot 后继续从 `last_seq` 拉增量。

阶段 4.5：生产化与测试（部分实现）

- metrics（已实现）：
  - SQLite 写失败次数。
  - event append 成功/失败次数。
  - standby event lag。
  - snapshot fallback 次数。
  - event 表大小。
- 单元测试：
  - event 幂等 apply。
  - TTL 不续期。
  - SQLite 重启恢复。
  - event retention 后 standby fallback snapshot（已覆盖 event log gap fallback）。
  - snapshot checksum 拒绝错误快照。
- 集成测试：
  - active REGISTER 后 standby 在一个增量周期内 lookup。
  - active affinity 写入后 standby 在一个增量周期内 lookup。
  - event log 缺口时 standby fallback snapshot 并对齐 `last_applied_seq`。
  - event pull 失败时 fallback snapshot 并恢复一致。
  - `required = true` 时 SQLite 写失败会拒绝写入。

### 阶段 5：生产化增强

交付：

- metrics。
- tracing。
- graceful shutdown。
- ACL/鉴权。
- 配置热加载。
- benchmark：
  - REGISTER RPS
  - OPTIONS RPS
  - INVITE CPS
  - p50/p99 转发延迟
  - affinity table 内存占用

验收：

- 压测结果明确。
- 关键错误有日志和指标。

## 当前优先级

1. 修复 code review 已确认的主线正确性问题。
2. 继续减少手写 SIP 解析，优先复用 `rsipstack` typed header/URI 能力。
3. 保持 active-standby 为可选能力；生产启用前必须先修复 fencing 与 hook 监督问题。

### Code Review 修复计划

主线必修：

- 路由 `domain` 匹配改为解析 Request-URI host 后精确匹配，避免 `contains()` 导致跨租户误命中。
- proxy branch id 改为进程内原子唯一生成，不再依赖系统时间纳秒。
- UDP listener 对单次 `recv_from` 错误记录后继续运行，避免瞬时 IO 错误拖死 listener。
- app 主循环监督 `server`、HA replication、active-standby、leader monitor 子任务，任一任务异常退出时触发整体 shutdown，避免进程假活。
- UDP downstream -> TCP upstream 的响应等待放入后台任务，UDP 收包循环不能被长 INVITE 阻塞。
- TCP upstream 响应等待区分 INVITE 与非 INVITE：INVITE 使用更长 pending timeout，收到 provisional 后继续等待 final；响应超时或 channel closed 计入 passive health failure。
- UDP branch route 插入后若发送失败必须回滚；非 INVITE 或 final response 命中后删除 branch，INVITE provisional 继续保留。
- affinity 命中后需要校验目标 upstream 健康；不健康则 fallback 到 upstream group 重新选择。affinity 记录推迟到请求成功送出后。

已确认不按 review 误报修复：

- CANCEL 和非 2xx ACK 按 SIP transaction 规则通常复用原 INVITE 的 top Via branch，当前 lightweight transaction key 包含 branch 是合理的。2xx ACK 走 dialog/affinity 路径，不应强行复用 INVITE transaction key。

Active-standby 生产启用前必修：

- HA command hook 用作 VIP/EIP fencing 时，promotion 不能在 hook 失败后继续宣称 active。
- HA hook 超时需要确保子进程被终止。
- 配置校验需要在 `active_standby.enabled`、`replication.enabled` 下强制校验必要 peer 字段。

## 当前执行状态

已完成：

- 基础 Rust 工程骨架。
- `clap` 子命令入口基础。
- 配置加载、示例生成和校验基础。
- `rsipstack::sip` 已引入，SIP message parser/serializer 已迁移到薄封装。
- REGISTER AOR/Contact/Expires 解析已使用 `rsipstack` typed header/URI API。
- UDP/TCP SIP listener 骨架。
- OPTIONS 进入普通转发路径。
- REGISTER 进入普通转发路径，不在 proxy 本地 registrar 中直接应答。
- 静态 upstream 路由匹配。
- upstream group 后端健康检查已支持 `options`、`tcp-connect`、成功码、连续成功/失败阈值和真实转发 passive feedback。
- 主动健康检查启动后立即执行，同组后端并发探测；OPTIONS 使用 rsipstack typed API 构造并携带实际探测 socket Via 和 `rport`。
- 上游 UDP/TCP 转发。
- UDP/TCP 响应路径已按 proxy Via branch 校验并移除 proxy Via。
- TCP upstream 已支持按后端地址复用长连接。
- TCP reader 已复用 `rsipstack::transport::stream::SipCodec`，删除自写 TCP Content-Length framing。
- SIP-aware affinity/session persistence 已支持 `dialog-id`、`call-id`、`request-uri`。
- 默认 `dialog-id` affinity 已支持 dialog-id 优先、Call-ID 兜底，覆盖初始 INVITE 无 To tag 后的 BYE/re-INVITE/UPDATE。
- `Max-Forwards` 已支持缺省补 70、转发前递减、0 时返回 `483 Too Many Hops`。
- `Max-Forwards` 写入已使用 `rsipstack::sip::MaxForwards` typed header。
- INVITE lightweight transaction key 已改用 `rsipstack` typed `Call-ID` / `CSeq` API。
- registered Contact 目标解析已改用 `rsipstack` typed `Contact` / `Uri` / `Transport` API，支持完整 Contact header value 和 SIP 默认端口。
- INVITE lightweight transaction route 已支持 CANCEL/ACK 命中原 INVITE upstream。
- Record-Route 已收窄到 dialog-forming 请求。
- ACK/CANCEL/BYE/re-INVITE/UPDATE 方法级测试已补充。
- proxy metrics 已支持 `/metrics` Prometheus text format，覆盖请求、本地响应、上游响应、转发、转发错误、affinity lookup，以及 UDP/TCP branch route、INVITE transaction route、TCP upstream connection、affinity binding、location binding 等实时 gauge。
- SIP 压测脚本已支持 UDP OPTIONS、REGISTER、INVITE 和 mock upstream，输出 RPS 与 p50/p95/p99 延迟。
- upstream 健康检查已支持 OPTIONS 与 TCP connect 两种 probe，支持阈值、可配置成功状态码、被动失败反馈、首轮立即探测和组内并发探测；OPTIONS 请求构造使用 `rsipstack` typed Request/Header/Uri/Via API。
- UDP downstream 转 TCP upstream 已改为复用 TCP upstream 长连接池，按 proxy branch 分发多个 INVITE provisional/final response，并确保 proxy Via transport 使用实际 upstream transport。
- code review 主线修复已完成：路由 domain 精确 host 匹配、原子唯一 proxy branch、UDP 收包循环后台处理、listener 瞬时 IO 错误继续运行、app 子任务监督、INVITE upstream 响应长等待、TCP/UDP branch final 后清理、发送失败回滚、affinity 不健康目标回退、active-standby/replication peer 必填校验。
- 基础测试覆盖配置、SIP 解析、REGISTER、路由和 proxy 处理路径。

待完成：

- 继续审计剩余薄封装，能稳定复用 `rsipstack` typed API 的地方继续替换。
- 启用 active-standby 生产漂移前修复 HA fencing hook 失败处理和 hook 超时子进程终止。

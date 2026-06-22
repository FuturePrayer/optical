# AGENTS.md

本文档供 AI 编程智能体阅读,描述项目功能、代码结构、开发规范和注意事项。

## 项目概述

**optical** 是一个后量子加密隧道转发工具,使用 ML-KEM-768 + ML-DSA-65 + PSK 三重认证和 ChaCha20-Poly1305 AEAD 帧加密。核心功能是将本地端口流量通过加密多路复用隧道转发到远端节点,再由远端节点拨号到最终目标。

### 双节点架构

- **Node1 (Forwarder)**:监听本地 TCP/UDP 端口,通过隧道转发到对端
- **Node2 (Tunnel Server)**:接受隧道连接,处理 OPEN 请求,拨号到最终目标
- 一个节点可同时扮演两个角色

### 数据流

```
用户 → Node1 本地端口 → [加密多路复用隧道] → Node2 → 拨号到目标
```

### 加密设计原则:不引入常规 TLS

**项目明确不计划引入常规 TLS**(如 rustls/openssl/TCP+TLS)。安全通道完全由自研的 PQ 握手 + AEAD 帧加密提供,这是核心设计决策,**新增功能或重构时不得擅自添加 TLS 传输层**(如 `tls://` scheme、`wss://`、TLS 终止等),除非有明确的安全论证并经人工评审。

**加密为何不依赖 TLS:** 加密层建立在"有序可靠字节流"抽象之上,而三种内置传输(TCP / KCP / WS)都恰好提供这一抽象:

- **TCP**:原生有序可靠字节流
- **KCP**:`KcpStream` 在 UDP 之上实现重传+排序,对上层暴露等价于 TCP 的字节流语义(已实现 `AsyncRead/AsyncWrite`)
- **WebSocket**:`WsDuplex` 适配层把 `WebSocketStream` 的消息流(`Stream`/`Sink`)转为有序字节流(WS 跑在 TCP 之上,天然可靠有序)

因此握手(`client_handshake` / `server_handshake`)和隧道(`Tunnel::new`)完全泛型化于 `AsyncRead + AsyncWrite + Unpin`,**不引用任何具体传输类型**,三种传输下加密机制完全等价生效、强度一致。

**WS 的特殊说明**:WS 的 `ws://` 明文回源(配合 CDN Flexible SSL)依赖隧道自身的 ChaCha20-Poly1305 保护——CDN 节点虽可见流量特征(帧大小/时序),但看到的载荷始终是密文。这是有意为之的设计,**不需要也无法用 TLS 替代**(TLS 会终止于 CDN,与 Flexible SSL 回源模型冲突)。

**例外**:`admin/` 管理 API 若需远程访问,仍可考虑加 TLS + token(当前未实现,见"admin API 安全"章节)——admin API 不承载隧道流量,与上述隧道加密设计无关。

## 代码结构

项目是 **Cargo workspace**,由一个共享核心库 + 两个二进制组成:

```
optical/                          # workspace 根
├── Cargo.toml                    # [workspace] 成员声明 + 共享 profile.release-perf
├── config.example.yml            # 配置模板(编译期 include_str! 进 paths.rs)
├── crates/
│   ├── optical-core/             # 共享核心库(lib crate)
│   │   ├── Cargo.toml            #   features: node(默认) / center
│   │   └── src/
│   │       ├── lib.rs            #   模块导出
│   │       ├── app.rs            #   应用编排:加载配置、启动各角色、优雅关闭
│   │       ├── config.rs         #   YAML 配置解析与校验(含 center 块)
│   │       ├── config_manager.rs #   配置热更新(center 下发 → diff → 启停 forwarder)
│   │       ├── cli.rs            #   CLI 子命令实现(两 bin 共用)
│   │       ├── error.rs          #   统一错误类型(thiserror)
│   │       ├── paths.rs          #   AppKind(Node/Center)、平台默认路径、模板渲染、私钥权限
│   │       ├── updater.rs        #   自更新(按 AppKind 选 asset 名)
│   │       ├── crypto/           #   密码学: kdf/pqkem/pqdsa/aead/handshake
│   │       ├── transport/        #   传输层: tcp/kcp/ws + AnyTransport
│   │       ├── proto/            #   隧道协议: frame(含 center 帧类型) + stream
│   │       ├── tunnel/           #   隧道核心: mod/client/server
│   │       ├── forward/          #   前向转发: mod/tcp/udp/reverse
│   │       ├── dial/             #   拨号: tcp/udp
│   │       ├── metrics/          #   指标: mod + history
│   │       ├── service/          #   系统服务: linux/windows(服务名按 AppKind)
│   │       ├── admin/            #   节点 admin API(status/ping/bench)
│   │       ├── center/           #   配置中心
│   │       │   ├── proto.rs      #     center 应用帧编解码(JSON over AEAD)
│   │       │   ├── client.rs     #     CenterClient(节点侧,始终编译)
│   │       │   ├── events.rs     #     EventHub(SSE 广播)
│   │       │   ├── state.rs      #     全局 CenterState(OnceLock)
│   │       │   ├── server.rs     #     #[cfg(center)] center 服务端 + Session
│   │       │   ├── registry.rs   #     #[cfg(center)] NodeRegistry + 白名单 + nodes.json
│   │       │   └── web_admin.rs  #     #[cfg(center)] REST/SSE + 嵌入式 web UI 服务
│   │       └── webui.rs          #   #[cfg(center)] rust-embed 嵌入 webui/dist
│   ├── optical/                  # 节点二进制(bin)
│   │   ├── Cargo.toml            #   依赖 optical-core(默认 features=仅 node)
│   │   └── src/main.rs           #   clap 分发(不含 center 子命令)
│   └── optical-center/           # 配置中心二进制(bin)
│       ├── Cargo.toml            #   依赖 optical-core(features=node+center)
│       ├── build.rs              #   编译时触发 npm build 前端
│       └── src/main.rs           #   clap 分发(节点命令 + center run/init)
└── webui/                        # React 前端(Vite + Ant Design + TanStack Query)
    ├── package.json
    ├── dist/                     # 构建产物(被 optical-center 编译期嵌入)
    └── src/                      #   api/ pages/ + App.tsx
```

### 双二进制与 Feature 门控

| 二进制 | optical-core features | 含 center 服务端代码 | 含前端嵌入 | 编译需 Node.js |
|--------|----------------------|---------------------|-----------|---------------|
| `optical`(节点) | `node`(默认) | ❌ | ❌ | ❌ |
| `optical-center`(中心) | `node` + `center` | ✅ | ✅ rust-embed | ✅ build.rs 调 npm |

- 节点二进制 `optical` **始终内置 CenterClient**(`center/client.rs` 不受 feature 门控),所以节点能被中心纳管,但自身不做中心服务端
- 中心二进制 `optical-center` 双重身份:既是中心服务端,也可同时承担节点角色(转发/隧道)
- `center` feature 门控的代码在节点二进制中**完全不编译进产物**

## 核心设计

### 帧协议

15 字节 header(作为 AEAD AAD)+ 加密 payload:

```
[4B stream_id][8B counter][1B frame_type][2B payload_len][payload (AEAD ciphertext + 16B tag)]
```

帧类型:`Open(0x01)` `OpenAck(0x02)` `Data(0x03)` `Close(0x04)` `Ping(0x05)` `Pong(0x06)` `Echo(0x07)` `EchoReply(0x08)` `RegisterReverse(0x09)` `RegisterReverseAck(0x0A)` `NodeRegister(0x0B)` `ConfigPush(0x0C)` `StatusReport(0x0D)` `ConfigAck(0x0E)`

- `0x01-0x0A`:隧道多路复用帧(在 `Tunnel` 连接上传输)
- `0x0B-0x0E`:配置中心应用帧(仅在 center 会话连接上传输,`stream_id=0`,JSON payload)。隧道 `reader_task` 收到这些帧会静默忽略(防御性)
- `parse_header` 返回原始 `u8` 而非 `FrameType`,调用方负责转换;未知帧类型**静默跳过**而非断连(前向兼容关键,见"协议兼容性")

- `stream_id=0` 用于控制帧(Ping/Pong/Echo/EchoReply/**RegisterReverse**/**RegisterReverseAck**)
- 客户端分配偶数 stream_id (0, 2, 4, ...),服务端分配奇数 stream_id (1, 3, 5, ...)——反向隧道模式下两端都会发 OPEN,按角色区分避免冲突
- 每流维护独立 send/recv counter 用于 AEAD nonce 和防重放

### 隧道核心 (tunnel/mod.rs)

`Tunnel` 结构封装一条已握手的加密连接,运行三个后台 task:

- **writer_task**:从 mpsc channel 取帧 → 加密 → 写入传输层,每帧累加 `bytes_sent`。使用 micro-batch:首帧经 `pack_frame()` 把 header+ciphertext 拼进单个 `Vec`(单次 `write_all`),然后用 `try_recv` 非阻塞抽干 channel 最多 64 帧攒进同一缓冲,单次 `flush`。对 WS 传输尤其重要(避免 header/ciphertext 分两条 WS Binary 消息)
- **reader_task**:从传输层读取 → 解密 → 按 frame_type 路由,每帧累加 `bytes_recv`。Data 帧用 `try_send` 非阻塞投递给流处理器,满则丢弃并累加 `frames_dropped` 指标(消除 head-of-line blocking)。读缓冲用 task-local `Vec` 复用(避免每帧堆分配)。解密失败即断连(TLS 原则)
- **heartbeat_task**:周期发 PING,检测 PONG 超时,记录 PING 发送时间用于 RTT 计算

`TunnelInner` 的关键字段:
- `metrics: Option<Arc<TunnelMetrics>>` — 从全局注册表查找,空则不采集
- `ping_waiter: Mutex<Option<oneshot::Sender<Duration>>>` — `ping_once()` 的等待通道
- `echo_reply_tx: Mutex<Option<mpsc::Sender<Bytes>>>` — bench 测试的回复通道
- `register_ack_waiter: Mutex<Option<oneshot::Sender<(ReverseAckStatus, String)>>>` — `register_reverse()` 的等待通道

### 传输层抽象 (transport/)

`Connect` 和 `Listen` trait 解耦隧道 I/O 与底层网络协议。新增传输(如 KCP)只需实现这两个 trait,返回 `BoxDuplex`(`Box<dyn Duplex>`),隧道代码无需修改。

当前内置三种传输,均通过 `AnyTransport` 统一调度(`transport/mod.rs`):

- **TCP**(`tcp.rs`):默认,向后兼容存量配置。`tune_socket()` 在连接建立后设 `TCP_NODELAY` + `SO_RCVBUF`/`SO_SNDBUF`(由 `socket_buffer_bytes` 配置,默认 4MB)+ `SO_KEEPALIVE`(30s idle)。隧道是单连接多路复用,调大 socket buffer 对高 BDP 跨地域链路至关重要
- **KCP**(`kcp.rs`):基于 tokio-kcp 的可靠低延迟 UDP,使用 `fastest_kcp_config()`(nodelay=true, interval=10ms, resend=2, nc=true, flush_write/flush_acks_input=true)预设,设计为比 TCP 显著更低延迟。`KcpStream` 已实现 `AsyncRead/AsyncWrite`,无需适配层
- **WebSocket**(`ws.rs`):基于 tokio-tungstenite,穿越 HTTP 代理/防火墙,可接入 CDN(Flexible SSL:CDN 终止 TLS,明文 `ws://` 回源)。`WsDuplex` 适配层把 `WebSocketStream` 的 `Stream`/`Sink` 适配为 `AsyncRead`/`AsyncWrite`(读缓冲用 `VecDeque<Bytes>` 零拷贝优化);服务端 `WsTransportListener::accept` 用 `TcpStream::peek` 预判 WS 升级请求,非 WS 的 HTTP 请求返回 200 伪装页面(抗探测 + CDN HTTP 健康检查)。所有连接强制 `TCP_NODELAY`(避免 Nagle 给小帧加 40ms 延迟)

客户端通过 `tunnel` 地址 URL scheme(`tcp://`/`kcp://`/`ws://`,无 scheme 默认 TCP)选择;服务端通过 `Config.tunnel_transport` 字段(`TransportKind` enum,serde 默认 Tcp)选择。两端协议必须匹配,不匹配时连接失败(预期行为)。Transport 是隧道之下的承载层,不触碰帧协议和 PQ 握手协议,故新增传输不受协议兼容性红线约束。

### 反向隧道 (forward/reverse.rs)

反向隧道模式允许 Node2(隧道服务端)监听端口,将连接通过隧道发回给 Node1(隧道客户端),由 Node1 拨号到目标。适用于 Node1 位于 NAT 后无公网 IP 的场景。

**数据流对比:**

| 模式 | listen 方 | OPEN 方向 | dial 方 |
|------|----------|----------|---------|
| 普通 | Node1 | Node1→Node2(偶数 ID) | Node2 |
| 反向 | Node2 | Node2→Node1(奇数 ID) | Node1 |

**协议流程:**
1. Node1 隧道建立后发送 `RegisterReverse(proto, listen, target)` 给 Node2
2. Node2 检查全局 `ReverseRegistry` 是否冲突 → 绑定监听 → 回复 `RegisterReverseAck(status, msg)`
3. Node2 收到连接后用奇数 stream_id 发 OPEN 给 Node1 → Node1 走 `dial::handle_incoming_opens` 拨号
4. 隧道断开时 Node2 的反向监听器随之销毁并释放端口;Node1 重连后重新注册

**关键组件:**
- `ReverseRegistry`:全局 `Arc<Mutex<HashMap<SocketAddr, CancellationToken>>>`,跨所有隧道连接共享,防止端口冲突。陈旧条目(已取消的令牌)自动淘汰。
- `register_reverse_forwarders`:Node1 侧注册循环——等隧道 → 串行注册所有 reverse 项 → 等隧道断开 → 重连后重新注册。任一注册失败(conflict/disabled)返回 `Err`,导致进程退出。
- `handle_reverse_requests`:Node2 侧消费 `IncomingReverse` 通道——检查 `allow_reverse` → 注册 → 绑定 → 回复 ack → spawn 监听器。
- `Tunnel::register_reverse()`:发送 `RegisterReverse` 帧并等待 ack(oneshot + 10s 超时),复用 `register_ack_waiter` 模式(类似 `ping_waiter`)。

**进程级退出:** 反向注册失败时,`run_forwarders` 返回 `Err` → `app.rs` 传播错误 → `main()` 以非零码退出。作为服务运行时,Windows SCM 报告 `ServiceExitCode::ServiceSpecific(1)`,systemd 检测到非零退出码。

### 配置中心 (center/ + config_manager.rs)

配置中心是一个集中服务,管理多个节点的 forwarder 配置。由 `optical-center` 二进制承载(同时也可做节点),节点用 `optical` 二进制被纳管。

**角色与数据流:**
```
浏览器 ──HTTP/REST/SSE──> optical-center (center_admin_listen)
                                │ /api/config/push (表单提交)
                                ↓
                          NodeRegistry.approve() + nodes.json 持久化
                                ↓
                          SessionMap.push() → ConfigPush 帧(AEAD 加密)
                                ↓ (PQ 握手 + 长连接 center_listen)
                          optical 节点
                                ↓ CenterClient 收 ConfigPush
                          ConfigManager.apply() (取消旧 task + 启新 forwarder,热生效)
                                ↓
                          forwarder 监听本地端口 → 经隧道转发
                                ↓ StatusReport (周期上报) → center → 浏览器 SSE 实时刷新
```

**关键组件:**
- `center/proto.rs`:center 应用帧编解码。复用隧道 15B header + AEAD 线格式,但 payload 是 JSON 而非多路复用数据。帧类型 `0x0B-0x0E`(NodeRegister/ConfigPush/StatusReport/ConfigAck),`stream_id=0`
- `center/client.rs`(**始终编译**):节点侧 CenterClient。连中心 → PQ 握手(用 `center.psk`)→ 发 NodeRegister(含 node_id + 版本 + 能力)→ 收 ConfigPush → 回 ConfigAck → 周期 StatusReport。退避带 jitter(避免惊群)。节点 config.yml 有 `center:` 块即启用
- `center/server.rs`(**#[cfg(center)]**):中心服务端。accept → `server_handshake` → 每节点一个 Session(读帧 + 推送通道)。`HandshakeResult.peer_node_id` 从握手的 dsa_pubkey 派生(SHA-256),作为节点身份
- `center/registry.rs`(**#[cfg(center)]**):NodeRegistry(node_id → 记录)。白名单自动批准:在 nodes.json 中的节点连上即放行 + 立即下发已分配配置;未知节点进 Pending。`approve()` bump config_version + 持久化 + 触发推送
- `center/events.rs`:EventHub(broadcast)。节点注册/离线/状态/推送时广播给 SSE 订阅者
- `center/state.rs`:全局 CenterState(OnceLock,registry + sessions + hub),供 web admin 访问
- `center/web_admin.rs`(**#[cfg(center)]**):REST API(`/api/overview`/`/api/nodes`/`/api/pending`/`/api/nodes/:id/approve`/`/api/config/push`/`/api/whitelist`)+ SSE(`/api/events`)+ 嵌入式 web UI 静态资源服务。Bearer token 认证(`center_admin_token`)
- `config_manager.rs`:配置热更新。收到 ConfigPush → 取消旧 forwarder task → 启动新 set → 更新版本号。full-restart 策略(非细粒度 diff),复用 `forward::run_forwarders`
- `webui.rs`(**#[cfg(center)]**):rust-embed 编译期嵌入 `webui/dist/`。SPA fallback 到 index.html

**节点身份:** `node_id = SHA-256(ML-DSA-65 verifying key)`,hex 64 字符(`pqdsa::fingerprint_vk`)。节点的永久身份,与私钥一一对应。`HandshakeResult.peer_node_id` 在握手完成后从对端公钥派生——节点注册是握手的副产品,无需额外鉴权层。

**配置热更新:** ConfigManager 收到新 ConfigPush 时,取消当前 forwarder set 的 CancellationToken + 等待 drain(30s 超时)→ 用新 forwarders 调 `run_forwarders`。在用连接会被中断(MVP 策略;后续可演进到细粒度 diff 只重启变化的 forwarder)。

### 可观测性架构

- **全局 `MetricsRegistry`**(`OnceLock`):避免在所有函数签名中传递 `Arc`
  - `metrics::init()` 在 `app.rs` 启动时调用一次
  - `metrics::try_get()` 在任意代码路径获取注册表
- **隧道指标注册**:两侧角色都会注册 `TunnelMetrics`,通过 `TunnelRole` 区分方向
  - `TunnelRole::Client`("outbound"):由 `run_forwarders`(Node1)预注册,key=配置的 `tunnel_addr`,跨重连复用同一 entry
  - `TunnelRole::Server`("inbound"):由 `tunnel::server::run`(Node2)握手成功后注册,key=TCP 连接对端 `peer_addr`,隧道断开时经 `unregister_tunnel` 注销(带 `Arc` 指针比较防重连误删)
  - `Tunnel::new` 接收 `metrics_key: Option<&str>`,从全局注册表查找对应 `Arc<TunnelMetrics>`;服务端隧道传 `Some(&peer_key)`,未注册时不采集
- **插桩点**:writer/reader task 字节计数、heartbeat RTT、forwarder accept/连接数
- **管理 API**(`admin/`):本地 TCP HTTP-JSON 服务,手写 HTTP 解析(无框架依赖)
  - `GET /status` — 实时快照(含所有已注册隧道,role 字段区分方向)
  - `GET /metrics` — 历史时间序列
  - `POST /ping` — 通过 `Tunnel::ping_once()` 测延迟(仅客户端侧隧道,依赖 `TunnelRegistry`)
  - `POST /bench` — 通过 `Tunnel::bench()` 测吞吐(ECHO 回环)(仅客户端侧隧道)
- **TunnelRegistry**:共享 `TunnelClient` 引用,供 admin API 的 `/ping` `/bench` 调用。仅 forward 模块(Node1)填充,纯节点2 不支持 ping/bench

## 开发规范

### 代码风格

- Rust edition 2024
- 使用 `tracing` 而非 `println!`/`eprintln!` 进行日志输出(CLI 命令的终端输出除外)
- 错误类型统一使用 `crate::error::{OpticalError, Result}`,应用层编排用 `anyhow::Result`
- 公共 API 写文档注释(`///`),复杂逻辑写行内注释(`//`)
- 异步运行行为 `tokio`,长生命周期任务用 `tokio::spawn`
- 取消令牌统一用 `tokio_util::sync::CancellationToken`,父子令牌级联取消

### 插桩指标

新增需要计数的代码路径时:

1. 在 `metrics/mod.rs` 的 `TunnelMetrics` 或 `ForwarderMetrics` 中添加 `AtomicU64`/`AtomicU32` 字段
2. 在 `init()`/`register_tunnel()`/`register_forwarder()` 中初始化
3. 在 `snapshot()` 中读取并加入对应的 `Snapshot` 结构
4. 在插桩点用 `metrics::try_get()` 查找注册表后 `fetch_add` 计数
5. 如需在 CLI 展示,更新 `main.rs` 的 JSON 反序列化结构体和格式化输出

### 新增帧类型

1. `proto/frame.rs` 的 `FrameType` enum 添加变体
2. `from_u8()` 添加 match arm
3. `tunnel/mod.rs` 的 `reader_task` 添加处理分支
4. 如需客户端侧响应,在 `TunnelInner` 添加等待通道(参考 `ping_waiter`/`echo_reply_tx`/`register_ack_waiter`)
5. 如需服务端侧处理,在 `Tunnel::new` 创建 mpsc channel 并由 `reader_task` 投递(参考 `open_tx`/`reverse_tx`),消费端在 `tunnel/server.rs` 中 spawn

> **兼容性注意**:自 v0.1.0 起存在存量用户。`parse_header` 现在返回原始 `u8`,调用方对未知帧类型**静默跳过**(`continue`)而非断连——这意味着新增帧类型(如 `0x0B-0x0E` 的 center 帧)不会破坏旧版本的隧道连接。但旧版本(此容错改动之前)遇到未知帧仍会断连,因此破坏性协议变更仍需走版本协商。详见上文"协议兼容性"章节。

### 新增 CLI 子命令

1. `main.rs` 的 `Commands` enum 添加变体(clap derive)
2. 在 `match cli.command` 中添加 arm,创建 tokio runtime 后 `block_on`
3. 如需查询运行中进程,通过 `admin_request()` 调用管理 API
4. 输出格式参考现有 `cli_status`/`cli_ping`/`cli_bench` 的格式化函数

### 新增传输协议

1. `transport/` 下新建模块,实现 `Connect` 和/或 `Listen` trait,返回 `BoxDuplex`
2. 在 `transport/mod.rs` 的 `AnyTransport` 分发中注册:
   - 客户端:在 `parse_transport_addr` 加 URL scheme 识别,在 `Connect::connect` 的 match 加 arm
   - 服务端:在 `config.rs` 的 `TransportKind` enum 加变体,在 `Listen::listen` 的 match 加 arm
3. 隧道和握手代码无需修改(已泛型化);`app.rs` 用 `AnyTransport::for_server/for_client`(传入 `socket_buffer_bytes` 和 `kcp_config`),无需改动
4. 如传输底层为 TCP(如 WS),务必在连接建立后调用 `tune_socket()`(设 `TCP_NODELAY` + `SO_RCVBUF`/`SO_SNDBUF` + `SO_KEEPALIVE`),否则 Nagle 给小帧(Ping/握手)引入最多 40ms 延迟,致命;默认 socket buffer 在高 BDP 链路上会瓶颈吞吐

## 注意事项

### 协议兼容性

自 v0.1.0 发布起,项目已有存量用户,**协议变更必须考虑前向/后向兼容**。修改帧协议或握手协议时,需确保新旧版本节点能够互通,或至少做到优雅降级而非断连。

**帧协议兼容性约束:**

- 帧类型字段为 1 字节,当前已用 `0x01`-`0x0A`(`Open` 至 `RegisterReverseAck`)
- `parse_header` 对未知帧类型返回原始 `u8`,调用方(`reader_task`)静默 `continue` 跳过(**已实现容错**)。新增帧类型不再需要两步发布,但仍建议破坏性协议变更走版本协商
- 帧头结构(15B: `[4B stream_id][8B counter][1B frame_type][2B payload_len]`)变更属破坏性改动,会阻断新旧端互通

**握手协议兼容性约束:**

- ClientHello / ServerHello / Finished 报文结构变更需保证新旧端握手成功。建议在协议演进时引入版本字段或能力协商,使新端能检测对端版本并回退到兼容行为
- 密钥派生、AEAD 算法等密码学参数变更属破坏性改动,须通过握手协商完成平滑过渡

**版本分发:**

- 版本号遵循 semver,通过 GitHub Releases 分发,用户可用 `optical update` 拉取新版本
- 破坏性协议变更应在主版本号升级时进行,并在 Release Notes 中明确标注兼容性影响

### Metrics 传递方式

使用全局 `OnceLock<MetricsRegistry>` 而非函数参数传递,原因是:
- 避免修改 `Tunnel::new()`、`writer_task()`、`reader_task()` 等所有签名
- 每个进程只有一个注册表
- `try_get()` 返回 `Option`,未初始化时安全降级(不采集)

`Tunnel::new()` 接收 `metrics_key: Option<&str>` 参数,在注册表中查找对应的 `TunnelMetrics`。客户端隧道传 `Some(&addr)`(key=配置的对端监听地址,跨重连复用同一 entry),服务端隧道传 `Some(&peer_key)`(key=TCP 连接对端 `peer_addr`,握手成功时由 `register_tunnel(.., TunnelRole::Server)` 预注册)。服务端隧道断开时通过 `unregister_tunnel`(带 `Arc` 指针比较)注销条目,避免堆积。返回三元组 `(Tunnel, Receiver<IncomingOpen>, Receiver<IncomingReverse>)`——客户端消费 open_rx 用于反向隧道拨号,服务端同时消费 open_rx 和 reverse_rx。

### mark_disconnected 原子性

`mark_disconnected()` 用 `state.swap()` 确保只在 `CONNECTED → DISCONNECTED` 转换时计数重连。reader 和 writer task 退出时都会调用,但只有第一个生效,避免重复计数。

### bench 对生产隧道的影响

`bench` 使用 `stream_id=0` 的 ECHO 帧(与心跳同通道),会占用隧道带宽。CLI 输出中应提示用户。`Tunnel::bench()` 通过 `try_send` 非阻塞填充写通道,避免无限积压。

### admin API 安全

仅监听 `127.0.0.1`,仅本机可访问。如需远程查询,需额外加 TLS + token(当前未实现)。

### Windows CRT 静态链接

`.cargo/config.toml` 配置了 `target-feature=+crt-static`,生成的 `optical.exe` 不依赖 `VCRUNTIME140.dll`。Linux 不需要此配置(glibc 默认存在于所有发行版)。

### 死代码标记

部分 API(如 `Tunnel::cancel()`、`Tunnel::role()`、`StreamHandle::send_data()`)当前未被调用但作为公共 API 保留,已标注 `#[allow(dead_code)]`。删除前确认无外部使用意图。

## 构建与验证

workspace 模式下,用 `-p <crate>` 指定构建哪个二进制;不加 `-p` 则全量构建。

```bash
# 快速检查(不生成二进制,检查整个 workspace)
cargo check --workspace

# 构建(整个 workspace: optical-core + optical + optical-center)
cargo build

# 只构建节点二进制(轻量,不需要 Node.js)
cargo build -p optical

# 只构建配置中心二进制(会自动触发 npm install + npm run build 前端)
cargo build -p optical-center

# Release-perf 构建(fat LTO,用于发布;编译慢)
cargo build --profile release-perf -p optical
cargo build --profile release-perf -p optical-center

# 跳过前端构建(纯 Rust 改动时加速,用上次构建的 dist)
OPTICAL_SKIP_WEBUI=1 cargo build -p optical-center

# 运行测试
cargo test --workspace

# 生成开发用密钥
cargo run -p optical -- keygen --private-key ./keys/dev.key --public-key ./keys/dev.pub
cargo run -p optical -- psk-gen

# 一键初始化节点(生成密钥 + PSK + 配置文件,默认 user scope)
cargo run -p optical -- init
cargo run -p optical -- init --system          # 系统级路径(需 root/管理员)
cargo run -p optical -- init --config-dir ./my-node   # 自定义目录
cargo run -p optical -- init --force           # 覆盖已存在的文件

# 一键初始化配置中心(生成密钥 + PSK + 空 nodes.json + 中心配置模板)
cargo run -p optical-center -- init

# 前台运行(编辑 config.example.yml 后)
cargo run -p optical -- run --config config.example.yml

# 日志级别控制
RUST_LOG=debug cargo run -p optical -- run --config config.example.yml
```

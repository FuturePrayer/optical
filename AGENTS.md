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

## 代码结构

```
src/
├── main.rs              # CLI 入口(clap 子命令分发)
├── app.rs               # 应用编排:加载配置、启动隧道服务+转发器+管理API、优雅关闭
├── config.rs            # YAML 配置解析与校验
├── error.rs             # 统一错误类型(thiserror)
├── service/             # 系统服务管理(install/uninstall/start/stop/restart)
│   ├── mod.rs           #   跨平台 trait + 信号处理
│   ├── linux.rs         #   systemd 实现
│   └── windows.rs       #   SCM (windows-service) 实现
├── crypto/              # 密码学模块
│   ├── mod.rs           #   模块导出
│   ├── kdf.rs           #   HKDF 密钥派生、PSK 生成
│   ├── pqkem.rs         #   ML-KEM-768 密钥封装
│   ├── pqdsa.rs         #   ML-DSA-65 签名、密钥文件 I/O
│   ├── aead.rs          #   ChaCha20-Poly1305 AEAD 加解密
│   └── handshake.rs     #   PQ 握手协议(ClientHello/ServerHello/Finished)
├── transport/           # 传输层抽象
│   ├── mod.rs           #   Connect/Listen trait + Duplex 类型别名
│   └── tcp.rs           #   TCP 传输实现
├── proto/               # 隧道协议
│   ├── frame.rs         #   帧类型定义与编解码(15B header + AEAD payload)
│   └── stream.rs        #   多路复用流句柄、双向复制
├── tunnel/              # 隧道核心
│   ├── mod.rs           #   Tunnel 结构:reader/writer/heartbeat 三个 task
│   ├── client.rs        #   隧道客户端:握手 + 指数退避重连
│   └── server.rs        #   隧道服务端:接受连接 + 握手
├── forward/             # 前向转发(Node1)
│   ├── mod.rs           #   按隧道地址分组、启动转发器、分离 reverse 项
│   ├── tcp.rs           #   TCP 转发器(含 forward_via_tunnel 可复用核心)
│   ├── udp.rs           #   UDP 转发器(含 udp_session_with_tunnel 可复用核心)
│   └── reverse.rs       #   反向隧道:RegisterReverse 注册/监听/冲突检测
├── dial/                # 拨号(Node2)
│   ├── mod.rs           #   处理入站 OPEN 请求
│   ├── tcp.rs           #   TCP 拨号
│   └── udp.rs           #   UDP 拨号
├── metrics/             # 指标采集(可观测性)
│   ├── mod.rs           #   MetricsRegistry(全局 OnceLock)、TunnelMetrics、ForwarderMetrics
│   └── history.rs       #   环形缓冲时间序列(10s 采样,60min 保留)
├── paths.rs             # 平台默认路径(system/user scope)、配置模板渲染、私钥权限加固
└── admin/               # 管理 API(可观测性)
    └── mod.rs           #   本地 HTTP-JSON 服务 + TunnelRegistry
```

## 核心设计

### 帧协议

15 字节 header(作为 AEAD AAD)+ 加密 payload:

```
[4B stream_id][8B counter][1B frame_type][2B payload_len][payload (AEAD ciphertext + 16B tag)]
```

帧类型:`Open(0x01)` `OpenAck(0x02)` `Data(0x03)` `Close(0x04)` `Ping(0x05)` `Pong(0x06)` `Echo(0x07)` `EchoReply(0x08)` `RegisterReverse(0x09)` `RegisterReverseAck(0x0A)`

- `stream_id=0` 用于控制帧(Ping/Pong/Echo/EchoReply/**RegisterReverse**/**RegisterReverseAck**)
- 客户端分配偶数 stream_id (0, 2, 4, ...),服务端分配奇数 stream_id (1, 3, 5, ...)——反向隧道模式下两端都会发 OPEN,按角色区分避免冲突
- 每流维护独立 send/recv counter 用于 AEAD nonce 和防重放

### 隧道核心 (tunnel/mod.rs)

`Tunnel` 结构封装一条已握手的加密连接,运行三个后台 task:

- **writer_task**:从 mpsc channel 取帧 → 加密 → 写入传输层,每帧累加 `bytes_sent`
- **reader_task**:从传输层读取 → 解密 → 按 frame_type 路由,每帧累加 `bytes_recv`
- **heartbeat_task**:周期发 PING,检测 PONG 超时,记录 PING 发送时间用于 RTT 计算

`TunnelInner` 的关键字段:
- `metrics: Option<Arc<TunnelMetrics>>` — 从全局注册表查找,空则不采集
- `ping_waiter: Mutex<Option<oneshot::Sender<Duration>>>` — `ping_once()` 的等待通道
- `echo_reply_tx: Mutex<Option<mpsc::Sender<Bytes>>>` — bench 测试的回复通道
- `register_ack_waiter: Mutex<Option<oneshot::Sender<(ReverseAckStatus, String)>>>` — `register_reverse()` 的等待通道

### 传输层抽象 (transport/)

`Connect` 和 `Listen` trait 解耦隧道 I/O 与底层网络协议。新增传输(如 KCP)只需实现这两个 trait,返回 `BoxDuplex`(`Box<dyn Duplex>`),隧道代码无需修改。

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

> **兼容性注意**:自 v0.1.0 起存在存量用户。新增帧类型时,旧版本节点的 `parse_header` 遇到未知帧类型会返回 `Err` 并断开隧道。引入新帧类型前,应先发布能静默跳过未知帧类型的容错版本(修改 `parse_header` 行为),或通过握手版本协商规避。详见上文"协议兼容性"章节。

### 新增 CLI 子命令

1. `main.rs` 的 `Commands` enum 添加变体(clap derive)
2. 在 `match cli.command` 中添加 arm,创建 tokio runtime 后 `block_on`
3. 如需查询运行中进程,通过 `admin_request()` 调用管理 API
4. 输出格式参考现有 `cli_status`/`cli_ping`/`cli_bench` 的格式化函数

### 新增传输协议

1. `transport/` 下新建模块,实现 `Connect` 和/或 `Listen` trait
2. 返回 `BoxDuplex`
3. 在 `app.rs` 中将 `TcpTransport` 替换为新传输(或按配置选择)
4. 隧道和握手代码无需修改(已泛型化)

## 注意事项

### 协议兼容性

自 v0.1.0 发布起,项目已有存量用户,**协议变更必须考虑前向/后向兼容**。修改帧协议或握手协议时,需确保新旧版本节点能够互通,或至少做到优雅降级而非断连。

**帧协议兼容性约束:**

- 帧类型字段为 1 字节,当前已用 `0x01`-`0x0A`(`Open` 至 `RegisterReverseAck`)
- `parse_header` 对未知帧类型返回 `Err`(**非静默跳过**)— 这是一个关键兼容性风险点:新版本引入新帧类型后,旧版本节点遇到该帧会报错并断开整条隧道。引入新帧类型前,应先发布一个能"静默跳过未知帧类型"的容错版本,等待足够比例的用户升级后再发布实际使用新帧类型的版本;或通过握手阶段的版本协商机制规避
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

```bash
# 快速检查(不生成二进制)
cargo check

# Debug 构建
cargo build

# Release 构建
cargo build --release

# 运行测试
cargo test

# 生成开发用密钥
cargo run -- keygen --private-key ./keys/dev.key --public-key ./keys/dev.pub
cargo run -- psk-gen

# 一键初始化节点(生成密钥 + PSK + 配置文件,默认 user scope)
cargo run -- init
cargo run -- init --system          # 系统级路径(需 root/管理员)
cargo run -- init --config-dir ./my-node   # 自定义目录
cargo run -- init --force           # 覆盖已存在的文件

# 前台运行(编辑 config.example.yml 后)
cargo run -- run --config config.example.yml

# 日志级别控制
RUST_LOG=debug cargo run -- run --config config.example.yml
```

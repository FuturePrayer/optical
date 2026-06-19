# optical

后量子加密隧道转发工具 (ML-KEM + ML-DSA + PSK)。

将本地端口流量通过加密多路复用隧道转发到远端节点,再由远端节点拨号到最终目标。传输层使用 ChaCha20-Poly1305 AEAD 加密,握手层采用 ML-KEM-768 密钥封装 + ML-DSA-65 数字签名 + PSK 预共享密钥三重认证。

## 架构

```
Node1 (Forwarder)                    Node2 (Tunnel Server)
┌─────────────────┐                  ┌─────────────────┐
│ 本地端口监听     │                  │ 隧道端口监听     │
│  (TCP/UDP)      │                  │  (TCP/KCP/WS)  │
│      ↓          │   加密隧道       │      ↓          │
│ 多路复用隧道     │ ←─────────────→ │ 多路复用隧道     │
│      ↓          │  (PQ 握手+AEAD)  │      ↓          │
│ 前向转发         │                  │ 拨号到目标       │
└─────────────────┘                  └─────────────────┘
```

一个节点可同时扮演 Node1(前向转发)和 Node2(隧道服务端)角色。

### 反向隧道

上述为正向转发模式(Node1 监听 → Node2 拨号)。反向隧道模式将方向翻转:由 Node2(隧道服务端)监听端口,将连接通过隧道发回给 Node1(隧道客户端),由 Node1 拨号到目标。适用于 Node1 位于 NAT 后无公网 IP 的场景。

| 模式 | 监听方 | OPEN 方向 | 拨号方 |
|------|--------|----------|--------|
| 正向 | Node1 | Node1→Node2 | Node2 |
| 反向 | Node2 | Node2→Node1 | Node1 |

在 forwarder 配置中设置 `reverse: true` 即可启用,Node2 侧可通过 `allow_reverse: false` 硬禁用此功能。

### 传输协议

隧道传输层支持三种协议,通过 `tunnel_transport`(Node2 监听)和 forwarder 的 `tunnel` 地址 URL scheme(Node1 连接)选择,两端协议必须匹配:

| 协议 | Node2 配置 | Node1 `tunnel` 地址 | 适用场景 |
|------|------------|---------------------|----------|
| TCP | `tunnel_transport: tcp`(默认) | `host:port` 或 `tcp://host:port` | 通用,向后兼容存量配置 |
| KCP | `tunnel_transport: kcp` | `kcp://host:port` | 延迟敏感:基于 UDP 的可靠传输,比 TCP 低 30-40% 延迟,代价是更高带宽开销 |
| WebSocket | `tunnel_transport: ws` | `ws://host:port[/path]` | 穿越 HTTP 代理/防火墙;可接入 CDN(Flexible SSL:CDN 终止 TLS,明文 `ws://` 回源) |

WebSocket 服务端对非 WebSocket 的普通 HTTP 请求返回 `200 OK` 伪装页面,使端口对外表现为普通网站,支持 CDN HTTP 健康检查(期望 200)与抗主动探测。optical 隧道自身已有 ChaCha20-Poly1305 AEAD 加密,WS 明文传输不泄露数据机密性,仅暴露流量特征。

## 安装

### 从源码安装(推荐)

```bash
cargo install --git https://github.com/FuturePrayer/optical.git
```

安装后 `optical` 命令即可全局使用。

### 本地编译

```bash
git clone https://github.com/FuturePrayer/optical.git
cd optical
cargo build --release
# 二进制位于 target/release/optical
```

## 快速开始

### 1. 一键初始化(推荐)

`optical init` 会自动生成 ML-DSA-65 密钥对、随机 PSK,并从模板渲染配置文件:

```bash
# 用户级路径(默认,前台/开发场景)
optical init

# 系统级路径(生产/服务部署,需 root 或管理员权限)
optical init --system

# 自定义目录
optical init --config-dir /opt/my-node

# 覆盖已存在的文件
optical init --force
```

生成的目录结构:

```
<base_dir>/
├── config.yml          # 从模板生成,内含随机 PSK 和密钥路径
├── keys/
│   ├── node.key        # ML-DSA-65 私钥(32 字节 seed)
│   └── node.pub        # ML-DSA-65 公钥(1952 字节)
└── logs/               # 按日滚动的日志文件(init 自动配置 log_dir 指向此处)
```

#### 默认路径

| Scope | 平台 | 路径 |
|-------|------|------|
| User(默认) | Linux | `$XDG_CONFIG_HOME/optical/` 或 `~/.config/optical/` |
| User(默认) | Windows | `%APPDATA%\optical\` |
| System | Linux | `/etc/optical/` |
| System | Windows | `%PROGRAMDATA%\optical\` |

> **私钥权限**:Linux 上 `init` 和 `keygen` 会自动将私钥设为 `0600`(仅属主可读写)。Windows 上依赖目录 ACL 继承,生产环境建议手动确认 `%PROGRAMDATA%\optical\` 的 ACL 仅限 SYSTEM 和 Administrators。

### 2. 编辑配置

`init` 生成的配置文件包含全部注释和示例,需根据节点角色修改:

```yaml
# 预共享密钥(所有节点相同,init 已自动生成)
psk: "hex:a1b2c3..."

# ML-DSA 密钥路径(init 已自动填入)
mldsa_private_key: "/etc/optical/keys/node.key"
mldsa_public_key: "/etc/optical/keys/node.pub"

# 日志目录(按日滚动,init 已自动填入)
# 设为 null 或省略则仅输出到 stdout
log_dir: "/etc/optical/logs"

# Node2 角色:隧道服务端(接受入站隧道)
# 不需要此角色则删除或注释掉
tunnel_listen: "0.0.0.0:9000"

# 隧道传输协议(Node2 监听侧):tcp(默认)/kcp/ws
# Node1 侧通过 forwarder 的 tunnel 地址 URL scheme 选择,两端必须匹配
#   ws 可接入 CDN(Flexible SSL),非 WebSocket 的 HTTP 请求返回 200 伪装页面
tunnel_transport: tcp

# 是否接受对端的反向隧道注册(Node2 角色)
# 设为 false 可在此节点硬禁用反向隧道;默认 true
allow_reverse: true

# Node1 角色:本地端口转发器
# 不需要此角色则留空或删除整个列表
# tunnel 地址可通过 URL scheme 选择传输协议(须与对端 tunnel_transport 匹配):
#   "host:port"=TCP(默认) / "kcp://host:port" / "ws://host:port[/path]"
forwarders:
  - listen: "127.0.0.1:8080"       # 本地监听
    proto: tcp                      # 协议(tcp/udp)
    tunnel: "peer.example.com:9000" # 隧道对端地址(默认 TCP)
    target: "10.0.0.5:80"           # 最终目标地址

  - listen: "127.0.0.1:5353"
    proto: udp
    tunnel: "peer.example.com:9000"
    target: "8.8.8.8:53"

  # WebSocket 传输:穿越 HTTP 代理或接入 CDN(对端须 tunnel_transport: ws)
  - listen: "127.0.0.1:8443"
    proto: tcp
    tunnel: "ws://peer.example.com:9000"
    target: "10.0.0.5:443"

  # 反向隧道:对端(Node2)监听 9090,连接通过隧道发回本节点(Node1)拨号
  # 适用于本节点位于 NAT 后无公网 IP 的场景
  - listen: "0.0.0.0:9090"
    proto: tcp
    tunnel: "peer.example.com:9000"
    target: "192.168.1.100:22"
    reverse: true

# 隧道参数
tunnel:
  heartbeat_interval_secs: 15
  heartbeat_timeout_secs: 45
  reconnect_initial_secs: 1
  reconnect_max_secs: 30
  udp_idle_secs: 60

# 管理 API(可观测性,可选)
admin_listen: "127.0.0.1:9100"
```

> **重要**:根据节点角色删除不需要的配置项。一个节点可同时担任 Node1 和 Node2,但至少需配置其中之一。所有节点须共享同一 PSK。

### 3. 手动初始化(可选)

如需对密钥和配置分别管理,也可手动操作:

```bash
# 生成 32 字节 PSK
optical psk-gen
# 输出: hex:a1b2c3...

# 生成 ML-DSA-65 密钥对(省略路径则使用默认 user scope 路径)
optical keygen
# 或指定路径
optical keygen --private-key ./keys/node.key --public-key ./keys/node.pub
# 或使用系统级默认路径(需 root)
optical keygen --system

# 复制 config.example.yml,手动填入 PSK 和密钥路径
cp config.example.yml config.yml
```

### 4. 运行

**控制台模式**(前台运行):

```bash
optical run --config config.yml
```

**系统服务模式**:

```bash
# 安装为系统服务(Linux: systemd / Windows: SCM)
optical install --config /path/to/config.yml

# 服务控制
optical start
optical stop
optical restart
optical uninstall
```

## 可观测性

配置 `admin_listen` 后,可使用以下命令监控隧道状态:

### 查看实时状态

```bash
optical status --admin 127.0.0.1:9100
```

输出示例:
```
optical — status (uptime: 1h 30m)

Tunnels:
  peer.example.com:9000       CONNECTED     RTT: 1.20ms   up: 1h 28m   ↑1.0MB  ↓2.0MB  reconnects: 0

Forwarders:
  127.0.0.1:8080 (tcp) → 10.0.0.5:80            streams: 3/42     ↑512KB  ↓1.0MB
  127.0.0.1:5353 (udp) → 8.8.8.8:53             streams: 1/7      ↑4KB    ↓8KB
```

### 测量隧道延迟

```bash
optical ping --admin 127.0.0.1:9100 --tunnel peer.example.com:9000 --count 10
```

复用隧道心跳 PING/PONG 协议,零额外连接。

### 测量隧道吞吐

```bash
optical bench --admin 127.0.0.1:9100 --tunnel peer.example.com:9000 --duration 10 --size 65535
```

使用 ECHO/ECHO_REPLY 帧进行大块数据回环测试。

### 直接调用 API

管理端点为本地 HTTP-JSON 服务,也可用 `curl` 直接查询:

```bash
# 实时快照
curl http://127.0.0.1:9100/status

# 历史时间序列(60 分钟,每 10 秒一个采样点)
curl http://127.0.0.1:9100/metrics
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `optical init [--system\|--user\|--config-dir <dir>] [--force]` | 一键初始化:生成密钥 + PSK + 配置文件 |
| `optical run --config <path>` | 前台运行隧道节点 |
| `optical install --config <path>` | 安装为系统服务 |
| `optical uninstall` | 卸载系统服务 |
| `optical start` / `stop` / `restart` | 控制系统服务 |
| `optical keygen [--system] [--private-key <p> --public-key <p>]` | 生成 ML-DSA-65 密钥对(省略路径用默认) |
| `optical psk-gen` | 生成 32 字节 PSK |
| `optical status --admin <addr>` | 查看隧道和转发器实时状态 |
| `optical ping --admin <addr> --tunnel <addr> -c <n>` | 测量隧道延迟(RTT) |
| `optical bench --admin <addr> --tunnel <addr> -d <s> -s <bytes>` | 测量隧道吞吐 |
| `optical update [--check] [--force] [--restart]` | 检查并更新到最新版本(从 GitHub Releases 下载) |

## 自我更新

`optical update` 从 GitHub Releases 检查最新版本,下载对应平台的裸二进制并原地替换当前可执行文件。无需手动下载、解压或停止服务。

### 基本用法

```bash
# 检查是否有新版本(不下载)
optical update --check

# 更新到最新版本
optical update

# 强制重新安装当前版本
optical update --force

# 更新后自动重启系统服务
optical update --restart
```

### 工作原理

1. 查询 GitHub Releases API 获取最新版本号,与编译期嵌入的当前版本做语义化版本比较
2. 从 Release assets 中匹配当前平台的二进制文件,流式下载到临时文件
3. 原地替换:
   - **Windows**:将运行中的 exe 重命名为 `.bak`,写入新 exe(`.bak` 在下次更新时自动清理)
   - **Linux**:写入同目录临时文件后原子 `rename`,并复制原文件权限位
4. `--restart` 标志会调用 `service::restart()` 重启已注册的系统服务

### 发布约定

GitHub Release 的 asset 按以下命名约定上传(由 [GitHub Actions 工作流](.github/workflows/release.yml) 自动完成):

| 平台 | Asset 文件名 |
|------|-------------|
| Windows x86_64 | `optical-x86_64-pc-windows-msvc.exe` |
| Linux x86_64 | `optical-x86_64-unknown-linux-musl` |

> Linux 发布版使用 musl 静态链接,零 glibc 依赖,可在任意 Linux 发行版上运行(无需关心系统 GLIBC 版本)。本项目所有依赖(含 TLS)均为纯 Rust 实现,无 C 库依赖。

推送 `v*` 格式的 tag(如 `v0.2.0`)即可触发自动构建发布。Release 使用 `release-perf` 编译 profile(fat LTO + codegen-units=1),对密码学运算密集场景有性能优化。

> **注意**:`optical update` 仅替换二进制文件。如以系统服务方式运行,需配合 `--restart` 或手动执行 `optical restart` 使新版本生效。

## 本地开发

### 环境要求

- Rust 工具链(stable,edition 2024)
- Windows: MSVC 构建工具("Desktop development with C++" 工作负载)
- Linux: 无需额外系统库(所有依赖均为纯 Rust 实现,TLS 使用 rustls 而非 OpenSSL)

### 构建

```bash
# Debug 构建
cargo build

# Release 构建
cargo build --release

# 极致优化构建(用于发布分发:fat LTO + codegen-units=1)
cargo build --profile release-perf

# 运行测试
cargo test

# 检查(不生成二进制)
cargo check
```

`release-perf` profile 继承自 `release`,额外启用跨 crate 全局优化(`lto = "fat"`)和单 codegen unit(`codegen-units = 1`),对密码学运算密集场景(ML-KEM/ML-DSA/ChaCha20-Poly1305)有性能收益,代价是编译时间显著增加。GitHub Actions 发布工作流默认使用此 profile。

### Windows 静态链接 CRT

项目已配置 `.cargo/config.toml`,在 Windows MSVC 目标上静态链接 C 运行时,生成的 `optical.exe` 不依赖 `VCRUNTIME140.dll`,可直接部署到未安装 VC++ 运行时的机器。

### Linux musl 静态构建

GitHub Actions 发布工作流使用 `x86_64-unknown-linux-musl` 目标构建 Linux 发布版,产生完全静态链接的二进制,零 glibc 依赖,可在任意 Linux 发行版上直接运行(不会遇到 `GLIBC_x.xx not found` 错误)。

本地如需 musl 构建:

```bash
# 安装 musl 工具链(Ubuntu/Debian)
sudo apt-get install -y musl-tools
# 构建
cargo build --release --target x86_64-unknown-linux-musl
# 产物在 target/x86_64-unknown-linux-musl/release/optical
```

### 配置文件调试

开发时可使用相对路径的配置:

```bash
# 一键初始化到当前目录
optical init --config-dir .

# 或手动生成开发用密钥
optical keygen --private-key ./keys/dev.key --public-key ./keys/dev.pub
optical psk-gen

# 编辑 config.example.yml 填入密钥后运行
cargo run -- run --config config.example.yml
```

### 日志

日志级别通过 `RUST_LOG` 环境变量控制:

```bash
# Linux/macOS
RUST_LOG=debug cargo run -- run --config config.yml

# Windows PowerShell
$env:RUST_LOG="debug"; cargo run -- run --config config.yml
```

配置文件中设置 `log_dir` 后,日志在输出到 stdout 的同时额外写入按日滚动的文件(如 `optical.log.2026-06-19`),便于服务部署时留存历史日志。`init` 默认将 `log_dir` 设为 `<base>/logs`。设为 `null` 或省略则仅输出到 stdout。

## 安全说明

- **PSK**:所有共享同一 PSK 的节点构成一个信任域。任一节点泄露,攻击者可冒充该域内任意节点。
- **ML-DSA-65**:用于握手签名认证,防止中间人攻击。
- **ML-KEM-768**:用于密钥交换,提供后量子安全性。
- **ChaCha20-Poly1305**:帧级 AEAD 加密,每帧含计数器防重放。
- 管理 API 仅监听 `127.0.0.1`,仅本机可访问。

## 许可证

Apache License 2.0 (Apache-2.0)

Copyright 2026 Wang Zefeng

详见 [LICENSE](LICENSE) 文件。

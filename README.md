# optical

后量子加密隧道转发工具 (ML-KEM + ML-DSA + PSK)。

将本地端口流量通过加密多路复用隧道转发到远端节点,再由远端节点拨号到最终目标。传输层使用 ChaCha20-Poly1305 AEAD 加密,握手层采用 ML-KEM-768 密钥封装 + ML-DSA-65 数字签名 + PSK 预共享密钥三重认证。

## 架构

```
Node1 (Forwarder)                    Node2 (Tunnel Server)
┌─────────────────┐                  ┌─────────────────┐
│ 本地端口监听     │                  │ 隧道端口监听     │
│  (TCP/UDP)      │                  │  (TCP)          │
│      ↓          │   加密隧道       │      ↓          │
│ 多路复用隧道     │ ←─────────────→ │ 多路复用隧道     │
│      ↓          │  (PQ 握手+AEAD)  │      ↓          │
│ 前向转发         │                  │ 拨号到目标       │
└─────────────────┘                  └─────────────────┘
```

一个节点可同时扮演 Node1(前向转发)和 Node2(隧道服务端)角色。

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

### 1. 生成密钥

所有节点共享同一个 PSK 和 ML-DSA 公私钥对。

```bash
# 生成 32 字节 PSK
optical psk-gen
# 输出: hex:a1b2c3...

# 生成 ML-DSA-65 密钥对
optical keygen --private-key ./keys/node.key --public-key ./keys/node.pub
```

### 2. 编写配置

复制 `config.example.yml` 并修改:

```yaml
# 预共享密钥(所有节点相同)
psk: "hex:a1b2c3..."

# ML-DSA 密钥路径
mldsa_private_key: "./keys/node.key"
mldsa_public_key: "./keys/node.pub"

# Node2 角色:隧道服务端(接受入站隧道)
tunnel_listen: "0.0.0.0:9000"

# Node1 角色:本地端口转发器
forwarders:
  - listen: "127.0.0.1:8080"       # 本地监听
    proto: tcp                      # 协议(tcp/udp)
    tunnel: "peer.example.com:9000" # 隧道对端地址
    target: "10.0.0.5:80"           # 最终目标地址

  - listen: "127.0.0.1:5353"
    proto: udp
    tunnel: "peer.example.com:9000"
    target: "8.8.8.8:53"

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

### 3. 运行

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
| `optical run --config <path>` | 前台运行隧道节点 |
| `optical install --config <path>` | 安装为系统服务 |
| `optical uninstall` | 卸载系统服务 |
| `optical start` / `stop` / `restart` | 控制系统服务 |
| `optical keygen --private-key <p> --public-key <p>` | 生成 ML-DSA-65 密钥对 |
| `optical psk-gen` | 生成 32 字节 PSK |
| `optical status --admin <addr>` | 查看隧道和转发器实时状态 |
| `optical ping --admin <addr> --tunnel <addr> -c <n>` | 测量隧道延迟(RTT) |
| `optical bench --admin <addr> --tunnel <addr> -d <s> -s <bytes>` | 测量隧道吞吐 |

## 本地开发

### 环境要求

- Rust 工具链(stable,edition 2024)
- Windows: MSVC 构建工具("Desktop development with C++" 工作负载)
- Linux: `pkg-config` 及 OpenSSL 开发库(如需要)

### 构建

```bash
# Debug 构建
cargo build

# Release 构建
cargo build --release

# 运行测试
cargo test

# 检查(不生成二进制)
cargo check
```

### Windows 静态链接 CRT

项目已配置 `.cargo/config.toml`,在 Windows MSVC 目标上静态链接 C 运行时,生成的 `optical.exe` 不依赖 `VCRUNTIME140.dll`,可直接部署到未安装 VC++ 运行时的机器。

### 配置文件调试

开发时可使用相对路径的配置:

```bash
# 生成开发用密钥
optical keygen --private-key ./keys/dev.key --public-key ./keys/dev.pub
optical psk-gen

# 编辑 config.example.yml 填入密钥后运行
cargo run -- run --config config.example.yml
```

### 日志

通过环境变量控制日志级别:

```bash
# Linux/macOS
RUST_LOG=debug cargo run -- run --config config.yml

# Windows PowerShell
$env:RUST_LOG="debug"; cargo run -- run --config config.yml
```

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

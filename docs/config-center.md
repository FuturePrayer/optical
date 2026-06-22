# 配置中心使用文档

optical 配置中心(`optical-center`)是一个集中服务,用于管理多个隧道节点(`optical`)的转发配置。本文档涵盖架构、部署、Web 管理后台、REST API 和运维操作。

## 目录

- [概览](#概览)
- [架构与数据流](#架构与数据流)
- [部署配置中心](#部署配置中心)
- [部署被纳管节点](#部署被纳管节点)
- [Web 管理后台](#web-管理后台)
- [节点身份与白名单](#节点身份与白名单)
- [配置热更新](#配置热更新)
- [REST API 参考](#rest-api-参考)
- [SSE 实时事件](#sse-实时事件)
- [配置文件参考](#配置文件参考)
- [运维操作](#运维操作)
- [故障排查](#故障排查)

---

## 概览

配置中心解决的核心问题:**多个节点的转发规则如何集中管理**。

传统模式下,每个节点的 `forwarders` 写在本地 `config.yml` 里,改配置要逐台登录编辑 + 重启进程。配置中心模式下:

- 转发规则由中心集中存储、通过加密隧道下发
- 变更后**热生效**(节点不重启进程,自动启停对应的 forwarder task)
- 浏览器 Web UI 可视化管理,无需命令行操作
- 节点身份基于后量子公钥指纹,密码学自证明

### 适用场景

| 场景 | 推荐模式 |
|------|---------|
| 单台机器自用,配置基本不变 | 独立节点(`optical init`,无需中心) |
| 多台节点,偶发增删转发规则 | 独立节点(每台本地配) |
| **多台节点,频繁调整,需统一管理** | **配置中心**(`optical-center`) |
| 多团队/多租户共享一个中心 | 配置中心(基于 node_id 细粒度授权) |

---

## 架构与数据流

```
┌─────────────────────────────────────────────────────────────┐
│              optical-center (一个进程,三重身份)               │
│                                                             │
│  ① 隧道服务端 (tunnel_listen)                                │
│     节点的 forwarder 流量经此隧道转发                         │
│                                                             │
│  ② 配置中心服务端 (center_listen)                            │
│     节点连这里:注册身份、接收 ConfigPush、上报状态             │
│     (中心自身也作为节点连这里——自注册)                        │
│                                                             │
│  ③ Web 管理后台 (center_admin_listen)                        │
│     浏览器访问:REST API + SSE 实时事件 + 嵌入式 React UI      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ NodeRegistry (内存 + nodes.json 持久化)                │   │
│  │   node_id → { 公钥、审批状态、配置版本、forwarders }     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
          ▲                          ▲
          │ PQ 握手 + AEAD 长连接      │ HTTP/REST/SSE
          │ (center_psk 信任域)        │ (center_admin_token)
          │                          │
┌─────────┴────────┐         ┌───────┴────────┐
│  optical 节点 A   │         │   浏览器        │
│  CenterClient     │         │  React SPA     │
│  ConfigManager    │         └────────────────┘
│  forwarder (热启停)│
└──────────────────┘
```

> **中心自注册**:`optical-center` 启动时会自动作为节点连自己的 `center_listen`(经 `127.0.0.1` loopback),把自己的 node_id 加入白名单。因此中心**始终出现在自己的节点列表里**(状态在线),和其它节点统一管理——整个网络没有"孤立"的组件。中心的本地 forwarders(如果配了)会被 seed 进注册表作为初始配置,可通过 Web UI 像管理普通节点一样修改。

### 关键组件

| 组件 | 位置 | 作用 |
|------|------|------|
| **CenterClient** | 节点侧(始终编译进 `optical`) | 连中心、注册、收 ConfigPush、上报 StatusReport |
| **Center Server** | 中心侧(`center` feature) | accept 节点连接、握手、管理 Session |
| **NodeRegistry** | 中心侧 | 节点注册表 + 白名单 + 持久化 `nodes.json` |
| **ConfigManager** | 节点侧 | 收到 ConfigPush 后 diff + 启停 forwarder task |
| **Web Admin** | 中心侧 | REST API + SSE + 嵌入式前端 |
| **EventHub** | 中心侧 | SSE 广播(节点上下线、状态、配置推送) |

---

## 部署配置中心

### 1. 初始化

```bash
optical-center init --template center
```

生成:
- `keys/node.key` + `keys/node.pub`(ML-DSA-65 密钥对)
- `config.yml`(配置中心模板,**含两个随机 PSK**)
- `logs/` 目录

### 2. 编辑配置

```bash
vi config.yml
```

必改项:
- `center_admin_token`:改成你自己的强密码(浏览器登录用)

可选调整:
- `tunnel_listen`:隧道服务监听端口(节点 forwarder 拨入,默认 9000)
- `center_listen`:配置中心服务监听端口(节点注册连接,默认 7000)
- `center_admin_listen`:Web 管理后台端口(浏览器访问,默认 9100)

### 3. 启动

```bash
# 前台运行(调试)
optical-center run --config config.yml

# 注册为系统服务(生产)
optical-center install --config /path/to/config.yml
optical-center start
```

启动成功后日志会显示:
```
center self-approved in whitelist, node_id=32c032cf..., 0 forwarder(s) seeded
config center server enabled on 0.0.0.0:7000
config center web admin enabled on 0.0.0.0:9100
TCP tunnel server listening on 0.0.0.0:9000
center self-registering as a node (managed by itself)
```

中心启动时会自动把自己加入白名单并自注册为节点(连 `127.0.0.1:<center_listen 端口>`)。

### 4. 打开 Web UI

浏览器打开 `http://<center-ip>:9100`,输入 `center_admin_token` 登录。

此时"总览"页应显示 **1 节点在线**——就是中心自己。后续每台连入的 `optical` 节点会追加到列表。

---

## 部署被纳管节点

每台需要被纳管的节点:

### 1. 初始化

```bash
optical init --template managed-node
```

生成含 `center:` 块的配置。日志会打印出该节点的 `node_id`(SHA-256 公钥指纹,64 字符),**记下来**——用于在中心注册。

### 2. 编辑配置

```bash
vi config.yml
```

必改项:
- `center.address`:填配置中心的地址(如 `tcp://center.example.com:7000`)
- `center.psk`:填配置中心的 `center_psk`(从中心的 config.yml 里复制)
- `psk`:填隧道的 PSK(从中心的 config.yml 的 `psk` 字段复制,与中心一致)

### 3. 启动

```bash
optical run --config config.yml
# 或注册服务
optical install --config /path/to/config.yml && optical start
```

节点启动后会:
1. 连接配置中心(center_listen 端口)
2. PQ 握手(用 center.psk)
3. 发送 `NodeRegister`(携带 node_id + 版本)
4. 等待中心的 `ConfigPush`(若已在白名单则立即收到)

### 4. 在中心批准节点

回到中心的 Web UI:
- **若节点 node_id 已在白名单**:自动批准,立即下发已分配的配置
- **若不在白名单**:节点出现在"待审批"页 → 点"批准并配置" → 分配 forwarder → 下发

节点收到配置后立即热启动 forwarder,无需重启。

---

## Web 管理后台

浏览器打开 `http://<center-ip>:<center_admin_listen>`(默认 9100)。

### 页面一览

| 页面 | 功能 |
|------|------|
| **总览** | KPI 卡片(总数/在线/离线/待审批)、异常节点表、在线节点表 |
| **节点列表** | 所有节点,支持搜索、按状态筛选,显示版本/配置版本/转发规则数 |
| **待审批** | 白名单外的未知节点,批准/拒绝/拉黑 |
| **节点详情** | 单节点的生效配置、隧道连接(实时 RTT/吞吐)、历史状态 |
| **配置下发** | 选目标节点 → 表单填写转发规则(或 YAML 导入)→ 正式下发 |
| **设置** | 管理 token、白名单 CRUD、批量导入 node_id |

### 配置下发的两种方式

**方式一:表单填写**

1. 进入"配置下发"页,选目标节点
2. 点"+ 添加规则",逐条填写监听地址、协议、隧道对端、目标
3. 点"正式下发"

**方式二:YAML 导入**(批量迁移友好)

1. 进入"配置下发"页,展开"YAML 快速导入"
2. 粘贴标准 forwarders YAML:
   ```yaml
   forwarders:
     - listen: 0.0.0.0:8080
       proto: tcp
       tunnel: tcp://peer:9000
       target: nginx:80
     - listen: 0.0.0.0:8443
       proto: tcp
       tunnel: tcp://peer:9000
       target: httpsvc:443
   ```
3. 点"解析并填充表单" → 自动填充 → 检查后"正式下发"

### 实时刷新

页面通过 SSE(`/api/events`)接收实时事件:
- 节点上线/下线 → 总览 KPI 和节点列表自动刷新
- 状态上报 → 节点详情的隧道数据更新
- 配置推送 → 推送结果反馈

---

## 节点身份与白名单

### node_id 的生成

```
node_id = SHA-256(ML-DSA-65 验证公钥的 1952 字节原始编码) → hex(64 字符)
```

特性:
- **永久不变**:由密钥对唯一决定,只要不重新 `keygen` 就永远是同一个
- **密码学自证明**:握手时节点用私钥签名,中心验签即证明身份,无需额外鉴权
- **不泄露私钥**:单向哈希,可安全公开

查看节点 node_id 的方法:
```bash
# init --template managed-node 时会打印出来
optical init --template managed-node

# 或手动计算(对公钥文件做 SHA-256)
sha256sum keys/node.pub
```

### 白名单模型

配置中心采用**白名单自动批准**模型:

| 节点状态 | 含义 | 如何进入 |
|---------|------|---------|
| `approved` | 已批准,在白名单中 | 通过 Web UI 批准,或预先写入 nodes.json,或**中心自注册**(启动时自动) |
| `pending` | 待审批(不在白名单) | 新节点首次连接且不在白名单 |
| `rejected` | 已拒绝/拉黑 | 通过 Web UI 拒绝 |

- 白名单内的节点连上即自动放行 + 下发已分配配置
- 白名单外的节点进 `pending`,需人工批准
- 批准时可同时分配初始配置(一组 forwarders)
- **中心自身**在启动时自动加入白名单(self-approved),无需手动操作

### 中心自注册

`optical-center` 启动时:

1. 把自己的 node_id 加入 NodeRegistry 白名单(若尚未存在),用本地配置的 `forwarders`(如果有)作为初始配置 seed
2. 启动 center server + web admin
3. 额外启动一个 CenterClient,经 `127.0.0.1:<center_listen 端口>` 连自己的 center server,完成 PQ 握手 + 注册

因此中心**始终作为在线节点出现在自己的节点列表里**,与其它节点统一管理。你可以像管理普通节点一样,通过 Web UI 给中心下发/修改 forwarder 配置。

### 预置白名单(免审批)

在中心机器上编辑 `nodes.json`(center_data_dir 目录):

```json
[
  {
    "node_id": "07efaeea0fe26c0fae58fd2c8e80cc2f75ed14e6ceeb3587d6c771b59f85b35e",
    "status": "approved",
    "config_version": 1,
    "forwarders": [
      {
        "listen": "0.0.0.0:18080",
        "proto": "tcp",
        "tunnel": "tcp://127.0.0.1:9000",
        "target": "127.0.0.1:80",
        "reverse": false
      }
    ],
    "last_version": null
  }
]
```

节点连上后立即收到这份配置。

---

## 配置热更新

当中心下发新配置时,节点侧的 `ConfigManager` 执行:

1. **取消旧 forwarder set** 的 CancellationToken
2. **等待旧 task 退出**(30s 超时,超时则放弃等待)
3. **用新 forwarders 启动新 task**(调用 `run_forwarders`)
4. **更新已应用版本号**

> **注意**:当前采用 full-restart 策略(每次下发重启全部 forwarder),在用连接会被短暂中断。后续会演进到细粒度 diff(只重启变化的 forwarder)。

### 断线重连与配置同步

节点与中心断开后:
- CenterClient 用指数退避(带 jitter,1s→2s→4s→...→30s)自动重连
- 重连后重新发 `NodeRegister`
- 中心比对版本号:若节点版本落后,立即重推最新配置;若一致则不重发

节点本地保留上次下发的配置继续运行,断线期间不受影响(除非中心推了新配置但节点收不到)。

---

## REST API 参考

所有 `/api/*` 端点需要 Bearer token 认证(头 `Authorization: Bearer <center_admin_token>`,SSE 端点用 `?token=` query 参数)。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/overview` | KPI 聚合(总数/在线/离线/待审批/已批准/已拒绝) |
| GET | `/api/nodes` | 所有节点列表(含 online 字段) |
| GET | `/api/nodes/:id` | 单节点详情 |
| GET | `/api/pending` | 待审批节点(白名单外) |
| POST | `/api/nodes/:id/approve` | 批准节点 + 分配配置(body = forwarders JSON 数组) |
| POST | `/api/nodes/:id/reject` | 拒绝并拉黑节点 |
| DELETE | `/api/nodes/:id` | 移除节点(从 registry 删除) |
| GET | `/api/whitelist` | 白名单 node_id 列表 |
| POST | `/api/config/push` | 下发配置(body = `{node_id, forwarders}`) |

### 示例

```bash
TOKEN="your-center-admin-token"
BASE="http://127.0.0.1:9100"

# 查看所有节点
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/nodes"

# 批准节点并分配配置
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -d '[{"listen":"0.0.0.0:8080","proto":"tcp","tunnel":"tcp://peer:9000","target":"127.0.0.1:80","reverse":false}]' \
  "$BASE/api/nodes/07efaeea.../approve"

# 下发配置更新
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"node_id":"07efaeea...","forwarders":[...]}' \
  "$BASE/api/config/push"
```

---

## SSE 实时事件

`GET /api/events?token=<token>` 建立 SSE 长连接,推送 JSON 事件:

| 事件类型 | payload | 触发时机 |
|---------|---------|---------|
| `NodeRegistered` | `{node_id, version}` | 节点完成注册 |
| `NodeOnline` | `{node_id}` | 节点握手成功 |
| `NodeOffline` | `{node_id}` | 节点断开 |
| `NodeStatus` | `{node_id}` | 节点周期状态上报 |
| `ConfigPushed` | `{node_id, config_version}` | 配置下发到节点 |
| `PendingRequest` | `{node_id}` | 白名单外新节点等待审批 |

浏览器用原生 `EventSource` 订阅,自动重连。前端收到事件后使对应缓存失效并重新拉取。

---

## 配置文件参考

### 配置中心配置(完整)

```yaml
# 隧道 PSK(中心同时做隧道服务端,节点的 psk 要与此一致)
psk: "hex:..."

mldsa_private_key: "keys/node.key"
mldsa_public_key: "keys/node.pub"

# 角色①:隧道服务端
tunnel_listen: "0.0.0.0:9000"
tunnel_transport: tcp
allow_reverse: true

# 角色②:配置中心服务端
center_listen: "0.0.0.0:7000"
center_psk: "hex:..."                     # 中心管理域 PSK(节点的 center.psk 要一致)
center_data_dir: "."                       # nodes.json 存放目录

# 角色③:Web 管理后台
center_admin_listen: "0.0.0.0:9100"
center_admin_token: "your-strong-secret"   # 浏览器登录 token

# 节点角色 admin API(本机诊断)
admin_listen: "127.0.0.1:9101"

log_dir: "logs"
tunnel:
  heartbeat_interval_secs: 15
  heartbeat_timeout_secs: 45
```

### 被纳管节点配置(完整)

```yaml
# 隧道 PSK(与中心的 psk 一致)
psk: "hex:..."

mldsa_private_key: "keys/node.key"
mldsa_public_key: "keys/node.pub"

# 连配置中心
center:
  address: "tcp://center.example.com:7000"
  psk: "hex:..."                           # 中心的 center_psk
  status_report_interval_secs: 15

# 本机 admin API
admin_listen: "127.0.0.1:9100"

log_dir: "logs"
tunnel:
  heartbeat_interval_secs: 15
  heartbeat_timeout_secs: 45

# 注意:不配 forwarders —— 由中心下发
# 注意:不配 tunnel_listen —— managed node 一般不做 Node2
```

### 两个 PSK 的区别

| PSK | 字段名 | 用途 | 谁要一致 |
|-----|--------|------|---------|
| 隧道 PSK | `psk` | 节点 forwarder ↔ 中心隧道服务端的连接 | 所有节点 + 中心的 `psk` |
| 中心 PSK | `center_psk` / `center.psk` | 节点 CenterClient ↔ 中心 center server 的连接 | 所有节点的 `center.psk` + 中心的 `center_psk` |

这两个 PSK 可以相同(简化部署)也可以不同(安全分层)。`init --template center` 默认生成两个不同的随机 PSK。

---

## 运维操作

### 添加新节点

1. 新节点执行 `optical init --template managed-node`,记下 node_id
2. 编辑 config.yml 填 center 地址和 PSK
3. 启动节点
4. 中心 Web UI "待审批"页批准 → 分配配置

或预置白名单:直接编辑 `nodes.json` 加入 node_id,节点连上即自动批准。

### 移除节点

- Web UI:节点详情 → "移除"(从 registry 删除,断开连接)
- CLI:`curl -X DELETE -H "Authorization: Bearer $TOKEN" .../api/nodes/<id>`

### 轮换 PSK

1. 生成新 PSK:`optical psk-gen`
2. 编辑中心 config.yml 的 `center_psk` + 所有节点的 `center.psk`
3. 逐个重启节点(或全部重启)

> 轮换期间,未更新 PSK 的节点会握手失败、退避重连,更新后自动恢复。

### 备份

关键数据:`nodes.json`(白名单 + 节点配置)。定期备份 `center_data_dir` 目录。

---

## 故障排查

### 节点连不上中心

检查日志中的握手错误:

| 错误信息 | 原因 | 解决 |
|---------|------|------|
| `ClientFinished HMAC verification failed (wrong PSK?)` | center.psk 不匹配 | 核对节点的 `center.psk` 与中心的 `center_psk` |
| `connection refused` | 中心未启动 / 端口不对 / 防火墙 | 确认 center_listen 端口可达 |
| 一直退避重连 | 网络问题 | 检查 `center.address` 地址是否正确 |

### 节点连上但不收配置

- 检查 Web UI 该节点状态:若为 `pending`,需批准
- 若为 `approved` 但无 forwarders:在"配置下发"页分配规则

### Web UI 显示节点离线但实际在线

刷新页面。SSE 事件驱动刷新,若 SSE 断开会回退到轮询。

### 配置下发后节点没变化

检查节点日志是否有 `received config push` + `config applied`。若没有,说明 SSE 推送通道未送达——确认节点 Session 在中心仍活跃(Web UI 节点列表显示在线)。

### 重新生成前端后二进制仍显示旧页面

`rust-embed` 是编译期嵌入。改前端后必须重新编译 `optical-center`:

```bash
cd webui && npm run build && cd ..
cargo build -p optical-center
```

或设 `OPTICAL_SKIP_WEBUI=0`(默认)让 build.rs 自动触发 npm build。

# beacon

主机与网络可观测性平台：资源监控 + 流量异常 + 防火墙/端口审计，面向"一台家里的机器 + 几台云主机"的规模。

- **agent 主动出站上报**，云主机不用开安全组入站端口、不需要公网 IP
- **单二进制 agent**，1C1G 云主机常驻 < 40MB
- **指标走 Prometheus 协议**，不锁死私有格式
- 存储/查询/图形/通知复用成熟组件，自研只做三件没人做好的事

## 快速开始

```bash
make build
./bin/beacon agent check          # 能力探测：nft / ss / psi / conntrack / metadata
./bin/beacon agent run --once     # 采集一次，打印 Prometheus 文本格式
./bin/beacon agent run            # 常驻，指标在 127.0.0.1:9100/metrics
```

国内网络下 `proxy.golang.org` 不通，Makefile 已默认 `GOPROXY=https://goproxy.cn,direct`。

### 中心（M1）

```bash
export BEACON_ENROLL_TOKEN=$(openssl rand -hex 16)
docker compose -f deploy/docker-compose.yml up -d
curl -s localhost:8428/health        # VictoriaMetrics
```

### 被监控主机

```bash
./bin/beacon agent enroll -server http://<center>:8080 -token $BEACON_ENROLL_TOKEN
BEACON_TRANSPORT_ENDPOINT=http://<center>:8080/api/v1/write ./bin/beacon agent run
./bin/beacon transport test          # 逐层验证 DNS/TCP/TLS/认证/写入
```

### 审计（M2）

```bash
./bin/beacon audit fw          # 防火墙快照 + 与上次的 diff + 危险规则
./bin/beacon audit ports       # 监听端口 + 新增/移除/绑定地址扩大
./bin/beacon audit exposure    # 监听 ∩ 外部可达 ∩ 安全组（未知时显式标注）
./bin/beacon audit fw --json   # 机器可读
```

事件会写入中心的 SQLite，按主机与时间回溯：

```bash
curl -H "Authorization: Bearer $BEACON_ENROLL_TOKEN" \
  'localhost:8080/api/v1/events?host=<host>&type=port_added'
```

断网演练：`./scripts/netloss-test.sh`（在中心侧运行，见脚本头部说明）。

### 告警（M3）

飞书自定义机器人即可，不需要企业自建应用：

```bash
export BEACON_FEISHU_WEBHOOK='https://open.feishu.cn/open-apis/bot/v2/hook/xxx'
export BEACON_FEISHU_SECRET='签名密钥'            # 可选，开启后按官方算法签名
export BEACON_PUBLIC_URL='http://<center>:8080'  # 卡片按钮要能从浏览器打开
docker compose -f deploy/docker-compose.yml up -d
```

链路：`vmalert → Alertmanager → beacon-server /hooks/alert → 飞书卡片`。

自检（发一张真实卡片，验证 webhook、签名和渲染）：

```bash
BEACON_FEISHU_WEBHOOK='https://open.feishu.cn/open-apis/bot/v2/hook/xxx' \
BEACON_FEISHU_SECRET='...' \
./bin/beacon notify test feishu
```

卡片包含：级别色条、主机、摘要、证据（JSON）、开始时间，以及两个按钮——
「查看曲线」打开预置好查询的 vmui，「静默 1 小时」调用 Alertmanager API 创建 silence。

## 状态

M0 完成：CPU/内存/网络/磁盘采集、能力探测、本地 `/metrics`。
M1 完成：传输抽象、WAL 存储转发、注册凭证、`beacon-server` 网关、systemd/安装脚本、中心 compose。
M2 完成：防火墙四后端解析与 diff、端口审计、暴露面模型、事件入库（SQLite）、`beacon audit` CLI。
M3 完成：vmalert 规则集、Alertmanager 路由/抑制、飞书卡片、去重限流、签名静默链接。

实测：
- 断网 60 秒缓冲 51 KB，恢复后 3 秒排空，窗口内心跳样本完整补传
- 新监听端口 8 秒内产生 `port_added` P0 事件，并出现在中心事件库
- 端口告警经 vmalert/Alertmanager 送达飞书卡片；点击「静默 1 小时」后告警变为 suppressed

## 文档

| 文档 | 内容 |
|---|---|
| [docs/00-oss-landscape.md](docs/00-oss-landscape.md) | 现成开源方案调研：能力矩阵、三条路线、为什么不全自研 |
| [SPEC.md](SPEC.md) | 实施方案：架构、指标清单、异常检测、告警规则、里程碑 |
| [TODO.md](TODO.md) | 可执行任务清单（M0–M6），每个任务带 Done when |

## 三个差异化点

1. **防火墙审计**：`nft -j` 快照 + hash + 规则 diff + auditd 关联操作者
2. **端口暴露面**：`主机监听 ∩ 云安全组 ∩ 外部实探` 三方差集
3. **轻量流量异常**：conntrack 采样 + 同小时基线，不抓包、不要特权

## 架构（目标形态）

```
云主机 / 家庭主机                       中心
┌──────────────────┐            ┌──────────────────────────┐
│ beacon-agent     │  出站 443  │ VictoriaMetrics (存储)    │
│  采集 + 本地判定  │ ─────────► │ vmalert (规则)            │
│  WAL 缓冲        │  remote_   │ Alertmanager (通知)        │
│  无监听端口       │  write     │ Grafana (面板, v0.3)      │
└──────────────────┘            └──────────────────────────┘
```

## 技术栈

Go 1.27（静态单二进制）· VictoriaMetrics · vmalert · Alertmanager · Grafana（v0.3）。选型理由见 [SPEC.md](SPEC.md) ADR-003。


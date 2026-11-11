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

## 状态

M0 已完成：四个采集器（CPU/内存/网络/磁盘）、能力探测、本地 `/metrics`，186 条序列。
M1（出站上报）进行中。MVP 不包含 Grafana，告警渠道只做飞书。

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


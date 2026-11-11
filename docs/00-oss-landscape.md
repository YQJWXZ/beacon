# 现成开源方案调研

> 调研日期：2026-11-11 · 版本号取自当日 GitHub Releases 与仓库元数据
> 目的：确认「主机资源 + 流量异常 + 防火墙/端口 + 云主机远程接入」这套需求，能不能直接买/装现成的，而不是自己造轮子。

---

## 0. 一句话结论

**能覆盖 70–85%，但没有一个项目能覆盖全部。** 主机指标、告警、Web 面板是彻底的红海（Beszel 用 12MB 内存就做完了），
真正没有轻量开源方案的只有三块：

1. **防火墙规则的「状态 + 变更审计」**（不是防火墙本身，是"谁在什么时候把哪条规则改了"）
2. **端口审计**——尤其是「主机内部监听端口」与「云安全组/外部实际可达端口」的**差集**
3. **面向单机/小机群的流量基线异常检测**（不是抓包分析，是"这台机器平时不该在这个时间往这个 IP 传这么多"）

所以正确策略不是「全自研」也不是「全现成」，而是：**复用成熟底座，自研只做这三个缺口。**

---

## 1. 需求拆解（能力域）

把原始需求拆成 9 个可比较的能力域，后文所有矩阵都按这个维度打分。

| 编号 | 能力域 | 说明 | 优先级 |
|---|---|---|---|
| A | 主机资源指标 | CPU / 内存 / 磁盘 / 负载 / 温度的采集与历史曲线 | 必须 |
| B | 网络吞吐与连接 | 每接口 bps/pps/错误/丢包，TCP 连接状态、conntrack | 必须 |
| C | 异常流量检测 | 扫描、爆破、突发外联、挖矿、DDoS、基线偏离 | 核心差异点 |
| D | 防火墙状态与审计 | nftables/iptables/ufw/firewalld 规则、默认策略、变更 diff | 核心差异点 |
| E | 端口与服务审计 | 监听端口快照/变更、进程归属、对外暴露面 | 核心差异点 |
| F | 远程接入方式 | 云主机不开入站端口，agent 主动出站上报 | 硬约束 |
| G | 告警与通知 | 阈值/事件/基线告警，聚合、抑制、恢复、多渠道 | 必须 |
| H | 资源占用与部署成本 | 1C1G 云主机能否长期跑 | 硬约束 |
| I | 开放性 | 能否接入自定义指标/事件，是否有 API | 决定能否补缺口 |

---

## 2. 候选项目

### 2.1 轻量主机监控（最接近需求形态）

| 项目 | Star | 版本 | 语言 | 协议 | 备注 |
|---|---|---|---|---|---|
| [Beszel](https://github.com/henrygd/beszel) | 27.1k | v0.21.1 | Go | MIT | Hub + Agent 双二进制，PocketBase 存储，自带面板与告警 |
| [哪吒监控 Nezha](https://github.com/nezhahq/nezha) | 10.4k | v2.6.1 | Go | WTFPL | Agent → Dashboard gRPC 上报，中文生态，带终端/定时任务 |
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | 93.5k | — | JS | MIT | 只做可用性/证书探测，无主机指标 |
| [Netdata](https://github.com/netdata/netdata) | 81.4k | v2.12.3 | Go/C | GPL-3.0 | 秒级指标 + 内置无监督异常检测 + parent/child 汇聚 |

### 2.2 标准指标栈（可组合，但组件多）

| 项目 | Star | 版本 | 说明 |
|---|---|---|---|
| [Prometheus](https://github.com/prometheus/prometheus) | 67.6k | v3.16.0 | 拉取模型 + PromQL + 规则告警 |
| [node_exporter](https://github.com/prometheus/node_exporter) | 13.9k | — | 主机指标事实标准，覆盖 A/B 的 90% |
| [blackbox_exporter](https://github.com/prometheus/blackbox_exporter) | 5.9k | — | 外部视角探测 TCP/HTTP/ICMP/证书 |
| [Grafana](https://github.com/grafana/grafana) | 77.8k | v13.3.1 | 展示层事实标准 |
| [VictoriaMetrics](https://github.com/VictoriaMetrics/VictoriaMetrics) | 18.1k | v1.156.0 | 单二进制时序库，兼容 PromQL/remote_write，比 Prometheus 省资源 |
| [Alloy](https://github.com/grafana/alloy) / [Vector](https://github.com/vectordotdev/vector) | 3.7k / 22.8k | — | 采集管道，解决"出站 push"和协议转换 |
| [Telegraf](https://github.com/influxdata/telegraf) | 17.9k | — | 插件最多的采集器，可写 Prometheus/Influx/OTLP |

### 2.3 流量与异常检测

| 项目 | 说明 | 与需求的距离 |
|---|---|---|
| [ntopng](https://github.com/ntop/ntopng) | 基于 nDPI 的流量画像与行为分析，能识别应用协议、做流量基线 | 最强，但偏网关/镜像口场景，部署重，需要特权网卡访问 |
| [Zeek](https://zeek.org/) / [Suricata](https://suricata.io/) | 全量协议解析 / 特征 IDS | 重，日志量大，需要单独调优，不是"主机监控"形态 |
| Netdata 内置 anomaly detection | 对每个指标做无监督聚类，输出 anomaly rate | 通用异常，不理解"流量语义"，但零配置 |
| [Coroot](https://github.com/coroot/coroot) / Pixie | eBPF 采集，服务拓扑 + 根因 | 面向 K8s，单机场景过重 |
| `vnstat` / `iftop` / `bandwhich` / `nethogs` | 单机流量查看 | 只有"当下"，没有历史、没有基线、没有告警 |

### 2.4 安全与主机审计

| 项目 | 说明 | 与需求的距离 |
|---|---|---|
| [osquery](https://github.com/osquery/osquery) + Fleet | 把系统状态变成 SQL 表，可定时查询差异（监听端口、进程、用户、内核模块） | 能力完全够，但 C++ 重、概念重、要额外 Fleet 服务 |
| [Wazuh](https://github.com/wazuh/wazuh) | HIDS/SIEM，含 FIM、日志分析、合规基线 | 完整但很重（≥4GB 内存起步），远超需求 |
| [Falco](https://github.com/falcosecurity/falco) | 运行时行为检测（eBPF） | 只做安全事件，不做资源监控 |
| [CrowdSec](https://github.com/crowdsecurity/crowdsec) | 日志驱动的 IPS + 社区封禁名单 | 值得作为可选增强，不解决审计 |
| auditd / fail2ban | 内核审计 / 暴力破解封禁 | 是"数据源"，不是"监控系统" |

### 2.5 一体化可观测平台

| 项目 | 说明 | 判断 |
|---|---|---|
| [Zabbix](https://www.zabbix.com/) | 老牌，agent 主动/被动都支持，模板生态大 | 能覆盖 A/B/E/G/F，UI 与配置体系偏重，D/C 仍需自研 |
| [OpenObserve](https://github.com/openobserve/openobserve) | 单二进制，指标/日志/链路 + 告警 | 是"存储+展示"，不产生数据，可作为后端备选 |
| Checkmk / 夜莺 Nightingale | 企业向 | 偏重，本地单机场景收益低 |

---

## 3. 能力矩阵

图例：● 原生支持且好用 · ◐ 部分支持/需绕 · ○ 不支持

| 能力域 | Beszel | Nezha | Netdata | Prom 栈 | Zabbix | ntopng | osquery/Wazuh |
|---|---|---|---|---|---|---|---|
| A 主机资源 | ● | ● | ● | ● | ● | ○ | ◐ |
| B 网络吞吐/连接 | ◐ | ◐ | ● | ● | ◐ | ● | ○ |
| C 异常流量 | ○ | ○ | ◐ | ◐ | ◐ | ◐ | ○ |
| D 防火墙审计 | ○ | ○ | ○ | ○ | ○ | ○ | ◐ |
| E 端口审计 | ○ | ◐ | ◐ | ◐ | ◐ | ◐ | ● |
| F 出站上报 | ● | ● | ● | ◐ | ◐ | ○ | ◐ |
| G 告警 | ● | ● | ● | ● | ● | ◐ | ● |
| H 轻量 | ● | ● | ○ | ◐ | ◐ | ◐ | ○ |
| I 开放性 | ◐ | ◐ | ● | ● | ◐ | ◐ | ◐ |

---

## 4. 关键结论（逐条论证）

### 4.1 主机资源监控不该自研

第三方实测（2026）：Beszel agent 常驻 8–15MB，Netdata 100–350MB，Prometheus + Grafana 组合 400MB–1GB。
`node_exporter` 已经把 `/proc`、`/sys` 的坑趟完了（几百个指标、各种发行版兼容、容器内降级）。
自己用 gopsutil 写一遍，最多是"又一个更差的 node_exporter"。**这部分必须复用。**

### 4.2 云主机接入是选型分水岭

- **Beszel**：默认 hub → agent（TCP 45876）；但 agent 支持 `HUB_URL` 反向模式，可以主动连回 hub，无需开入站端口。
- **Nezha**：agent 主动连 dashboard 的 gRPC 端口，天然适合 NAT/安全组受限的云主机。
- **Netdata**：child 通过 streaming 协议主动连 parent，同样可行。
- **Prometheus 原生**：拉取模型，云主机必须暴露端口；要出站就得加 Alloy/Vector/remote_write 或 Pushgateway。

这条决定了：**要么选带反连能力的 agent 方案，要么接受多一个管道组件。**

### 4.3 防火墙审计：没有轻量现成方案

业内做法基本是三条：

1. **auditd 监控 `nft`/`iptables`/`ufw` 的 execve** —— 只能知道"有人执行了命令"，不知道改了什么；
2. **配置漂移检测**（Ansible/Puppet/Chef 或自研 hash 比对）—— 需要已有 IaC，普通云主机没有；
3. **osquery/Wazuh** —— 能查 `nftables`/`iptables` 表，但要拖一个重平台进来。

而实现这件事的成本其实极低：`nft -j list ruleset` 直接给 JSON，解析后算 hash、做 diff、匹配危险规则，
一个几百行的 Go 模块就够。**这是性价比最高的自研点。**

### 4.4 端口审计：现有工具只做了一半

- `ss -tulpn` 能看到监听端口，但没人做**变更检测 + 基线白名单 + 绑定地址变化**（`127.0.0.1` 改成 `0.0.0.0` 是最典型的"配置事故"）。
- `blackbox_exporter` 能从外部探测端口，但它是独立心跳，**不与主机内部监听列表做关联**。
- 云厂商安全组是第三份真相（控制台里）。三者的差集才是真正的"暴露面"：

```
主机监听集合  ∩  安全组放行集合  ∩  外部实际可达集合
        ↑ 差集 = 真正的风险与配置错误
```

这个视角，我调研的所有开源项目都没有做。**这是本项目的核心差异化。**

### 4.5 异常流量：算法不难，难在"轻"

ntopng/Zeek 能做，但要求镜像口或特权抓包，1C1G 云主机上不现实；
Netdata 的 anomaly detection 是通用指标异常，不懂"22 端口突然有 2000 个源 IP 在试密码"。
真正可行的轻量做法是**基于连接元数据的统计基线**（conntrack + `ss` 采样 + 按协议/端口/目的前缀聚合），
不抓包、不需要特权，误报可控。这部分值得自研，但只做统计层，不做 DPI。

### 4.6 一体化平台没有赢家

能力越全越重。Zabbix 装完是 3–5 个进程 + MySQL/PG；Wazuh 起步 4GB。
对"家里一台机器 + 几台云主机"的规模，投入产出比很差。

---

## 5. 三条可选路线

### 路线 A：零开发，先用起来（半天）

```
Beszel Hub（家里机器，Docker）
  ├── 本机 agent（unix socket）
  └── 云主机 agent（HUB_URL 反连，不开端口）
```

- 覆盖：A/B/G/F/H，全部开箱即用
- 缺口：C/D/E 完全没有
- 适合：**先要一个能看的看板**，缺口靠巡检脚本补

### 路线 B：自研薄采集层 + 成熟数据面（推荐）

```
beacon-agent（自研，单二进制，出站 push）
        │  Prometheus remote_write / 文本格式
        ▼
VictoriaMetrics（单二进制时序库）
        ├── vmalert（规则告警）
        ├── Alertmanager（聚合/抑制/通知）
        └── Grafana（展示，v0.3 起）
```

- 自研范围：**采集器 + 规则**（正是三个缺口所在）
- 复用范围：存储、查询、图形、通知、时序协议
- 代价：比路线 A 多写代码，但每行代码都在解决"别人没解决的事"
- 保留"单二进制 agent"的部署体验，同时不重造数据库和面板

### 路线 C：纯 Prometheus 生态

`node_exporter + blackbox_exporter + Prometheus + Alertmanager + Grafana + 自研 exporter`

- 最标准、最可扩展、招聘友好
- 代价：4–6 个进程、YAML 配置分散、拉取模型要额外解决云主机出站
- 结论：**除非以后要接几十上百台机器或对接公司现有体系，否则不划算**

---

## 6. 推荐

**路线 B。** 理由：

1. 满足硬约束 F（agent 主动出站）与 H（1C1G 可跑）；
2. 不重造时序库、查询语言、图形面板、通知渠道 —— 这些成熟度差距是数量级的；
3. 自研只落在三个真实缺口上，每个都能用一两千行 Go 说清楚；
4. 指标格式用 Prometheus 明文/remote_write，**不锁定私有协议**，将来切换到 Prometheus、Thanos、Mimir、云厂商托管都是平移；
5. 保留了"一个 agent 装到任何机器上"的产品形态，这是 Beszel/Nezha 受欢迎的真正原因。

如果只想今天就看到东西：**先按路线 A 装 Beszel**，它和路线 B 不冲突，后面可以并存或退役。

详细设计见 [`../SPEC.md`](../SPEC.md)。

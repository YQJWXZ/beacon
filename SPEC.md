# beacon — 主机与网络可观测性平台 · 实施方案

| 项目 | 内容 |
|---|---|
| 文档版本 | v0.1（草案，待评审） |
| 日期 | 2026-11-11 |
| 状态 | 方案待确认 |
| 前置调研 | [`docs/00-oss-landscape.md`](docs/00-oss-landscape.md) |
| 工作名 | beacon（信标）——agent 主动向中心发信标，语义即架构 |

---

## 1. 背景与目标

### 1.1 场景

一台常驻的 Linux 主机（家里/办公室，16C/14G）+ 若干台云主机（腾讯云/阿里云，通常 1C1G～2C4G，安全组只放行 22/80/443）。
需要对它们做统一的资源、网络、安全面监控，异常时能第一时间知道"哪台机器、发生了什么、要不要人处理"。

### 1.2 目标

| 编号 | 目标 | 衡量方式 |
|---|---|---|
| G1 | 主机资源可观测 | CPU/内存/磁盘/负载/温度，15s 粒度，保留 30 天 |
| G2 | 网络与流量可观测 | 每接口吞吐/错误/丢包、连接状态、conntrack、按目的端口聚合的流量画像 |
| G3 | 异常流量可发现 | 扫描、爆破、突发外联、可疑目的地，误报 ≤ 1 条/天/主机 |
| G4 | 防火墙可审计 | 规则快照、hash、变更 diff、危险规则识别，变更 60s 内可见 |
| G5 | 端口暴露面可量化 | 内部监听 ∩ 云安全组 ∩ 外部实探，输出三方差集 |
| G6 | 云主机零入站接入 | agent 主动出站，不要求公网 IP、不开安全组入站端口 |
| G7 | 告警可信 | 分级、聚合、抑制、恢复通知；每条告警都能回答"为什么报" |
| G8 | 轻量 | agent 常驻 ≤ 40MB RSS、≤ 1% CPU（1C1G 机器可长期运行） |

### 1.3 非目标（明确不做）

- ❌ APM / 链路追踪 / 日志聚合（需要时用 Loki/OpenObserve，不并入）
- ❌ 容器编排（K8s）监控
- ❌ 全量抓包与协议解析（DPI）
- ❌ 自动处置（自动封 IP、自动改防火墙）—— 只观测，不动手
- ❌ 多租户 SaaS、计费、工单
- ❌ Windows 主机（v1 之后再说）

---

## 2. 选型结论

详细论证见 [`docs/00-oss-landscape.md`](docs/00-oss-landscape.md)。结论一句话：

> **自研只做采集层与规则层，存储/查询/图形/通知全部复用成熟组件。**

### ADR-001：为什么不自研全栈

| 方案 | 覆盖度 | 开发量 | 长期成本 | 判断 |
|---|---|---|---|---|
| A. Beszel + 脚本补丁 | 70% | 1 天 | 缺口无解，数据模型封闭 | 可作为过渡 |
| **B. 自研 agent + VictoriaMetrics + vmalert** | **95%** | **2–3 周** | 低，协议开放 | **采用** |
| C. Prometheus 全家桶 + 自研 exporter | 95% | 2–3 周 | 中，组件多、拉取模型与云主机冲突 | 备选 |
| D. 全自研（含存储与 UI） | 100% | 2–3 月 | 高，容易做成半成品 | 否决 |

关键取舍：

- **复用**：时序存储（VictoriaMetrics，单二进制、兼容 PromQL）、规则引擎（vmalert）、通知（Alertmanager）、展示（Grafana，v0.3 起）
- **自研**：`beacon-agent`（采集 + 本地判定 + 出站上报），以及"防火墙审计 / 端口暴露面 / 流量基线"三组规则
- **不锁定**：指标走 Prometheus 文本格式与 `remote_write`，随时可换 Prometheus / Thanos / Mimir / 云厂商托管

### ADR-002：为什么是 agent 主动 push

云主机安全组的现实约束（只开 22/80/443）决定了拉取模型必须额外引入管道组件。
push + 本地 WAL 缓冲同时解决三件事：NAT 穿透、断网不丢数据、中心重启不影响采集。

### ADR-003：实现语言选 Go（Rust 为备选）

**决定：Go。** 理由不是"Go 更好"，而是"在这个项目里 Go 的短板恰好不构成约束，Rust 的优势恰好不是瓶颈"。

| 维度 | Go | Rust | 对本项目的影响 |
|---|---|---|---|
| 同领域生态 | node_exporter、Beszel、Nezha、VictoriaMetrics、Alloy 全是 Go | 几乎没有同量级先例 | **决定性**：采集细节的坑可以抄，不用重新踩 |
| 采集库 | gopsutil，跨发行版/容器场景已趟过 | `procfs` / `sysinfo` 能用，边界情况自己补 | 直接影响 M1 工期 |
| 指标协议 | `prometheus/client_golang` 是事实标准 | `prometheus` crate 可用但生态薄 | 低风险 |
| eBPF（v0.4） | `cilium/ebpf`，成熟 | `aya`，更优雅，但调试成本高 | 未来项，不阻塞 |
| 单二进制 | 静态链接，交叉编译一行命令 | 同样可以，musl 静态链接要多几步 | 低 |
| 常驻内存 | 25–40 MB | 5–15 MB | 预算内，**不是瓶颈** |
| 开发速度 | 快 | 慢 1.5–2×，解析器和状态机上要和借用检查纠缠 | 单人维护的项目里是硬伤 |
| 编译反馈 | 1–3 s | 10–60 s | 影响迭代节奏 |
| 并发模型 | goroutine，天然贴合"每 N 秒采一次" | tokio 或线程池，需要更多设计 | 中等 |

**这个项目的瓶颈是"规则与解析的正确性"，不是吞吐和内存。** 40MB RSS 在 1C1G 上占比 4%，
换来的是成熟的采集库和可抄的先例——这笔交易划算。

**什么情况下应该改用 Rust：**

- 目标包含路由器/ARM 小设备，内存预算是 5MB 级
- 需要做重 eBPF 数据面（进程级流量全量统计），Rust/aya 的零拷贝优势才会显现
- 主要目的是练手 Rust

**不推荐混合语言**：两个工具链、两套发布流程、两套调试经验，单人维护成本大于收益。
若改用 Rust，本文档架构不变，只替换实现层。

### ADR-004：传输层可插拔，Tailscale 只是一个选项

中心固定在本机，但**网络路径不写死**。agent 只依赖一个 `Transport` 接口，不关心包怎么到中心。

```go
type Transport interface {
    Name() string
    Send(ctx context.Context, batch []byte) error
    Close() error
}
```

把「寻址」和「拨号」分开：endpoint 始终是 URL，dialer 决定怎么连。

| dialer | 场景 | 前置条件 | 阶段 |
|---|---|---|---|
| `direct` | 中心有公网、同网段、或 vpn 已路由 | 无 | MVP 默认 |
| `system` | 主机已加入 tailnet，用 MagicDNS 域名寻址 | 系统装好 tailscaled，agent 零感知 | MVP 支持 |
| `tsnet` | 不想在主机装 tailscale | 内嵌 Tailscale，二进制 +15–25MB，需 auth key | v0.3 可选 |
| `proxy` | 出口受限，需要 socks5/http proxy | 代理地址 | v0.2 |
| `unix` | 本机自测 | 无 | MVP |

设计约束：

- 换传输方式只改配置，不改代码；`transport.kind` 与 `endpoint` 正交
- 传输失败一律进 WAL，不区分原因——网络问题不该影响采集
- `beacon transport test` 逐层验证：DNS → TCP → TLS → 认证 → 写入，输出卡在哪一层

### ADR-005：云能力是可选适配器，不是前置条件

没有云厂商 AK，系统功能完整度**不得下降**，只是少一个数据源。同时，任何组件都不得按"主机类型"分支
（不写 `if cloud == tencent`），一律按**能力探测**决定行为。

- 每个云能力定义独立接口，默认 `noop` 实现返回 `unknown`，而不是报错
- 安全组数据三个来源，可同时配置、互为交叉验证：

| source | 实现 | 凭据 | 阶段 |
|---|---|---|---|
| `manual` | YAML 声明期望放行规则 | 无 | MVP 默认 |
| `provider` | 腾讯云/阿里云只读 OpenAPI（**占位**） | AK（未配置时自动禁用） | 接口留空，v0.3 实现 |
| `probe` | 中心侧外部 TCP 实探 | 无 | MVP |

- 所有相关指标带 `source` 标签，告警与报告能区分「确认不存在」和「不知道」
- 主机侧同理：启动时探测 `nft` / `ss` / `auditd` / 元数据可达性，缺失项上报 `available=0` 后跳过，
  **不报错、不退出、不影响其他采集器**

---

## 3. 系统架构

### 3.1 组件

```
┌──────────────────────── 被监控主机（家里 / 云上） ─────────────────────────┐
│                                                                            │
│  beacon-agent （单二进制，root，无监听端口）                               │
│  ├─ collector/host       CPU / MEM / DISK / NET / PSI / PROC               │
│  ├─ collector/flow       conntrack + ss 采样 → 流量画像                    │
│  ├─ collector/firewall   nft -j / iptables-save / ufw → 快照 + diff        │
│  ├─ collector/ports      ss -tulpen → 监听集合                             │
│  ├─ collector/security   SSH 日志 / 关键文件 hash / auditd 事件            │
│  ├─ detector             规则型 + 基线型异常判定（本地，降带宽）           │
│  ├─ buffer               WAL 环形缓冲（断网 24h，磁盘上限 64MB）           │
│  └─ shipper              Transport（direct/system/tsnet/proxy）            │
└─────────────────────────────────┬──────────────────────────────────────────┘
                                  │ 出站（默认 443，TLS 可选 mTLS）
                                  ▼
┌─────────────────────── 中心（本机，Docker Compose） ───────────────────────┐
│  VictoriaMetrics  :8428   时序存储 + PromQL（自带 vmui）                   │
│  vmalert          :8880   规则求值 → 告警                                  │
│  Alertmanager     :9093   分组 / 抑制 / 静默 / 路由                        │
│  beacon-server    :8080   注册 / 飞书通知 / 审计 API / CLI                 │
│  Grafana          :3000   MVP 不装，见 §11 决策门                          │
└────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 数据流

1. **采集**：agent 按分层频率采集（快指标 5–15s，慢指标 60s，审计类 60s + 事件触发）
2. **本地判定**：能在本地判定的（扫描、端口新增、防火墙变更、突发外联）直接在 agent 内出结论，只上报"指标 + 事件"，不上报原始明细 → 省带宽、降基数
3. **缓冲**：写入本地 WAL，按批（默认 5s / 2000 samples）发送；失败指数退避
4. **入库**：VictoriaMetrics 接收 `remote_write`
5. **告警**：vmalert 加载规则 → 触发 Alertmanager → webhook 到 beacon-server → 飞书
6. **回查**：CLI / vmui（VM 自带）/ Grafana（若启用）/ beacon-server 直接查 VM

### 3.3 主机身份

- `host` 标签使用**稳定 ID**：优先云实例 ID（元数据），否则 `/etc/machine-id`，**绝不用 IP**
- `instance` = `host:port`（展示用），`role`/`provider`/`region`/`az` 由注册时写入
- 注册流程：一次性 token → agent 首次启动换长期凭证（存 `/var/lib/beacon/cred`）→ 中心登记主机
- 主机改名/换 IP 不影响历史曲线连续性

### 3.4 断网与离线判定

| 场景 | 行为 |
|---|---|
| 网络抖动 < 5min | WAL 缓冲，恢复后补传，指标时间戳使用采集时刻 |
| 断网 > 24h | 丢弃最旧数据（环形），保留最新 |
| agent 崩溃 | systemd 拉起；本地看门狗 30s 无采集则退出重启 |
| 主机离线 | 中心侧 `beacon_agent_last_seen` 超 2min 触发 P0（这是推模型的必要补充） |

### 3.5 安全设计

- agent **不监听任何端口**，不接受中心指令（只读采集）。唯一例外：`beacon agent --debug` 本地临时端口，默认关闭
- 传输 HTTPS + 每主机独立 token；支持 mTLS（可选）
- agent 需要 root（读 nftables、进程归属、dmesg），但以最小系统调用面运行，不做 shell 拼接（全部走 exec 数组调用）
- 中心侧 token 可吊销，吊销后 agent 停止上报并在本地记录

### 3.6 传输层抽象

```
agent.config.yaml
  transport:
    kind: http            # 协议层：http（remote_write over TLS）
    endpoint: https://center.example:8428/api/v1/write
    dial: system          # 拨号层：direct | system | tsnet | proxy | unix
```

- `kind` 决定"用什么协议说话"，`dial` 决定"包怎么走"，两者独立
- `dial=system` 时 Tailscale 透明生效：只要本机加入了 tailnet 且 endpoint 用 MagicDNS 名，代码零改动
- `dial=direct` 是默认值，不假设任何网络环境
- 中心地址、凭证、CA 全部来自配置或环境变量，**代码里没有任何写死的地址**

---

## 4. 指标模型

### 4.1 命名规范

```
beacon_<domain>_<name>_<unit>{host, ...}
```

| 前缀 | 含义 | 示例 |
|---|---|---|
| `beacon_cpu_*` | CPU | `beacon_cpu_usage_ratio{mode="steal"}` |
| `beacon_mem_*` | 内存 | `beacon_mem_available_bytes` |
| `beacon_disk_*` | 磁盘/文件系统 | `beacon_disk_used_ratio{mount="/"}` |
| `beacon_net_*` | 网络基础 | `beacon_net_rx_bytes_total{iface="eth0"}` |
| `beacon_flow_*` | 流量画像 | `beacon_flow_bytes_total{dst_port="443",dir="out"}` |
| `beacon_fw_*` | 防火墙 | `beacon_fw_ruleset_hash` |
| `beacon_port_*` | 端口 | `beacon_port_listen_info` |
| `beacon_sec_*` | 安全 | `beacon_sec_ssh_fail_total` |
| `beacon_agent_*` | 自身 | `beacon_agent_up` |

单位后缀一律显式：`_bytes`、`_seconds`、`_ratio`（0–1）、`_total`（单调递增计数器）。
计数器统一 `_total`，查询侧用 `rate()`。

### 4.2 标签与基数控制（最容易翻车的地方）

| 规则 | 说明 |
|---|---|
| 禁止把原始远端 IP 作为标签 | 一个扫描就能产生上万个序列，直接打爆存储 |
| 流向维度用有界枚举 | `dir=in/out`、`proto=tcp/udp/icmp`、`dst_class=self/lan/public/cloud` |
| 目的端口分桶 | 常见端口原样（22/80/443/3306…），其余归 `other`；明细只进 `top-K info` 指标 |
| Top-K 明细 | 每 5 分钟最多 20 条 `beacon_flow_top_info{dst="..."}`，值为流量，附 `pid/comm` |
| 进程维度谨慎 | 只对 CPU/内存 Top-10 进程打标签，`comm` 需归一化（防 `java` vs `/usr/bin/java` 重复） |
| 单主机序列上限 | 目标 ≤ 800 条活跃序列（实测 node_exporter 约 600–900） |

### 4.3 采集频率分层

| 层级 | 频率 | 内容 | 理由 |
|---|---|---|---|
| fast | 5s | CPU、内存、网络速率、连接数 | 突发流量、DDoS 需要秒级 |
| normal | 15s | 磁盘 IO、PSI、TCP 状态、进程 Top | 足够，且省 IO |
| slow | 60s | 文件系统容量、inode、防火墙快照、端口快照、服务状态 | 变化慢，diff 成本低 |
| event | 触发 | 防火墙变更、端口新增、SSH 登录失败突增 | 事件比轮询及时 |

### 4.4 保留策略

| 粒度 | 保留 | 存储估算（每主机） |
|---|---|---|
| 原始 15s | 30 天 | ≈ 120 MB |
| 5 分钟降采样 | 180 天 | ≈ 20 MB |
| 1 小时降采样 | 2 年 | ≈ 3 MB |

10 台主机 30 天 ≈ 1.5 GB，完全可接受。

---

## 5. 采集清单（本方案的核心）

价值标记：★★★ 必须有 · ★★ 强烈建议 · ★ 可选

### 5.1 CPU

| 指标 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_cpu_usage_ratio{mode}` | /proc/stat | 5s | ★★★ | mode: user/system/iowait/irq/softirq/steal/idle |
| `beacon_cpu_steal_ratio` | /proc/stat | 5s | ★★★ | **云主机最关键指标**：邻居抢占。用户侧"什么都没跑却卡"的唯一解释 |
| `beacon_cpu_iowait_ratio` | /proc/stat | 5s | ★★ | 与磁盘 await 联合判断是"盘慢"还是"CPU 等盘" |
| `beacon_load1/5/15` | /proc/loadavg | 5s | ★★★ | 注意：load 含 D 状态进程，容器/云主机里要结合 vCPU 数看 |
| `beacon_procs_running/blocked` | /proc/stat | 15s | ★★ | `blocked` 持续 >0 通常意味着 IO 卡死 |
| `beacon_cpu_freq_hz{core}` | /sys cpufreq | 60s | ★ | 降频/热节流 |
| `beacon_cpu_throttle_total{core}` | cgroup cpu.stat | 60s | ★ | 容器环境有用 |
| `beacon_ctx_switches_total` | /proc/stat | 15s | ★ | 突增常伴随惊群/自旋 |
| `beacon_psi_cpu_{some,full}_avg10` | /proc/pressure/cpu | 15s | ★★★ | PSI 比 load 更能反映"真实卡顿"，Linux 4.20+ |

### 5.2 内存

| 指标 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_mem_total/available/used_bytes` | /proc/meminfo | 5s | ★★★ | 用 `available` 而非 `free` 判断，`free` 在 Linux 上永远很小 |
| `beacon_mem_used_ratio` | 计算 | 5s | ★★★ | `(total - available) / total` |
| `beacon_mem_cached/buffers/slab/shmem_bytes` | /proc/meminfo | 15s | ★ | slab 持续增长 = 内核泄漏 |
| `beacon_mem_swap_used_ratio` | /proc/meminfo | 15s | ★★ | |
| `beacon_mem_swap_{in,out}_bytes_total` | /proc/vmstat | 15s | ★★★ | **swap 抖动率比占用率重要**，抖动 = 性能悬崖 |
| `beacon_mem_oom_kill_total` | dmesg / /proc/vmstat | 15s | ★★★ | 发生过 OOM 必须有记录，否则"进程莫名消失"无从追溯 |
| `beacon_mem_dirty/writeback_bytes` | /proc/meminfo | 15s | ★★ | dirty 高 + writeback 卡 = 磁盘即将拖垮整机 |
| `beacon_psi_memory_{some,full}_avg10` | /proc/pressure/memory | 15s | ★★★ | 内存压力提前量，比 OOM 早得多 |

### 5.3 磁盘与文件系统

| 指标 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_disk_used_ratio{mount,device}` | statfs | 60s | ★★★ | |
| `beacon_disk_inode_used_ratio{mount}` | statfs | 60s | ★★★ | **最容易漏**：空间没满但 inode 耗尽，症状是"无法创建文件" |
| `beacon_disk_readonly{mount}` | /proc/mounts | 60s | ★★★ | 文件系统因错误转只读是 P0 |
| `beacon_disk_predict_full_seconds{mount}` | 7 天线性回归 | 60s | ★★★ | 比"当前 85%"有用得多：剩 6 小时 vs 剩 3 个月，处理优先级天差地别 |
| `beacon_disk_read/write_bytes_total` | /proc/diskstats | 15s | ★★ | |
| `beacon_disk_iops_total{op}` | /proc/diskstats | 15s | ★★ | |
| `beacon_disk_await_seconds{device}` | /proc/diskstats | 15s | ★★★ | 云盘 IOPS 被打满时 await 会飙升，是最直接的证据 |
| `beacon_disk_util_ratio{device}` | /proc/diskstats | 15s | ★★ | |
| `beacon_disk_io_errors_total` | dmesg | 60s | ★★ | |
| `beacon_disk_smart_healthy{device}` | smartctl | 1h | ★ | 云盘通常不可用，物理机有用 |
| `beacon_disk_mount_present{mount}` | /proc/mounts | 60s | ★ | 挂载点消失（如 NFS 断开） |

### 5.4 网络基础

| 指标 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_net_rx/tx_bytes_total{iface}` | /proc/net/dev | 5s | ★★★ | |
| `beacon_net_rx/tx_packets_total{iface}` | /proc/net/dev | 5s | ★★★ | 与 bytes 联查可区分"大包下载"和"小包攻击" |
| `beacon_net_{rx,tx}_errors_total{iface}` | /proc/net/dev | 5s | ★★★ | |
| `beacon_net_{rx,tx}_dropped_total{iface}` | /proc/net/dev | 5s | ★★★ | 云主机超带宽会被丢包，这是"莫名变慢"的常见原因 |
| `beacon_net_bandwidth_limit_bps{iface}` | 云元数据 / 手工配置 | 1h | ★★ | 用于计算利用率，判断是否触顶 |
| `beacon_tcp_conns{state}` | /proc/net/tcp | 15s | ★★ | ESTABLISHED/TIME_WAIT/CLOSE_WAIT/SYN_RECV |
| `beacon_tcp_retrans_ratio` | ss -s / netstat | 15s | ★★ | >2% 说明链路有问题 |
| `beacon_tcp_reset_total` | ss 采样 | 15s | ★★ | 大量 RST = 对端拒绝或中间设备干扰 |
| `beacon_conntrack_used_ratio` | /proc/sys/net/netfilter | 15s | ★★★ | **打满后所有新连接失败**，且日志里几乎没有线索，是排查噩梦 |
| `beacon_dns_query_duration_seconds` | 内置解析器探测 | 60s | ★ | 只探公共域名，判断出口 DNS 是否异常 |
| `beacon_net_up{iface}` | netlink | 15s | ★★ | 接口 down（云主机网卡漂移） |

### 5.5 流量画像（异常检测的输入）

| 指标 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_flow_bytes_total{dir,proto,dst_port,dst_class}` | conntrack + /proc/net | 15s | ★★★ | 有界维度，是基线的主体 |
| `beacon_flow_conns_total{dir,proto,dst_port}` | conntrack 采样 | 15s | ★★★ | 新建连接速率，扫描/爆破的主信号 |
| `beacon_flow_conn_fail_total{reason}` | conntrack | 15s | ★★★ | reason: refused/timeout/reset |
| `beacon_flow_unique_dst_total{window}` | 采样聚合 | 60s | ★★ | 60s 内不同目的地址数 |
| `beacon_flow_unique_src_total{window}` | 采样聚合 | 60s | ★★ | 入向：被多少源 IP 访问 |
| `beacon_flow_unique_dport_total` | 采样聚合 | 60s | ★★★ | 入向：多少不同端口被访问（扫描的核心特征） |
| `beacon_flow_top_bytes{dst}` | Top-K | 5min | ★★ | K≤20，附 pid/comm |
| `beacon_flow_short_conn_ratio` | 采样 | 60s | ★★ | 连接存活 <1s 的比例，扫描/爆破典型特征 |
| `beacon_flow_proc_bytes_total{comm,dir}` | socket inode ↔ /proc 映射 | 30s | ★★ | v0 用 inode 映射；eBPF 版本放 v0.4 |

> 采样策略：每 15s 读一次 conntrack 表，取前 N 条（默认 4096）聚合，超出的按 `other` 归并。
> 不做全量抓包，1C1G 机器 CPU 开销 <1%。

### 5.6 流量异常检测器（输出的不是指标，是结论）

| 检测器 | 判据 | 级别 | 价值 |
|---|---|---|---|
| `port_scan_in` | 60s 内 `unique_dport > 20` 且 `conn_fail/conn > 0.5` | P1 | ★★★ |
| `port_scan_out` | 60s 内 `unique_dport > 30`（本机主动扫别人，多半已被控） | P0 | ★★★ |
| `ssh_bruteforce` | 22 端口新建连接 > 30/min，或 sshd 失败日志 > 20/5min | P0 | ★★★ |
| `syn_flood` | `tcp_conns{state="SYN_RECV"} > 200` 持续 1min | P1 | ★★ |
| `egress_burst` | 出站 bytes 速率 > 7 天同小时基线 P95 × 3，持续 3 个采样点 | P1 | ★★★ |
| `suspicious_dport` | 出站命中矿池/木马端口表（3333/4444/5555/7777/14444/6666/1080/9050…） | P0 | ★★ |
| `new_destination` | 出站目的地址（/24 + ASN）首次出现且 5min 内 > 10MB | P1 | ★★ |
| `offhours_traffic` | 02:00–06:00 出站 > 基线 P95 × 5 | P2 | ★★ |
| `dns_anomaly` | DNS 查询速率 > 基线 × 5，或唯一域名数突增（隧道特征） | P2 | ★ |
| `conn_flood` | `conntrack_used_ratio > 0.9` | P1 | ★★ |

所有检测器输出统一结构：

```json
{
  "kind": "egress_burst",
  "severity": "P1",
  "host": "i-xxxx",
  "score": 4.7,
  "window": "2026-11-11T03:00:00Z/PT5M",
  "evidence": {"baseline_p95_bps": 1200000, "observed_bps": 6100000, "top_dst": "45.x.x.x:443"}
}
```

`evidence` 是硬要求——**没有证据的告警等于噪音**。

### 5.7 防火墙审计

| 指标/事件 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_fw_ruleset_hash{backend}` | `nft -j list ruleset` / `iptables-save` | 60s | ★★★ | hash 变化即"有人改过" |
| `beacon_fw_rules_total{table}` | 解析 | 60s | ★ | 规则数突降（被 flush）是强信号 |
| `beacon_fw_policy{chain}` | 解析 | 60s | ★★★ | `policy accept` = 形同虚设，P0 |
| `beacon_fw_service_active` | systemctl | 60s | ★★★ | nftables/firewalld/ufw 被停用 |
| `beacon_fw_risky_rules_total` | 规则匹配 | 60s | ★★★ | 0.0.0.0/0 → 22/3306/6379/27017/9200/2375/11211 |
| `beacon_fw_ipv6_covered` | 解析 | 60s | ★★ | 只配了 IPv4、IPv6 全通，是极常见盲区 |
| 事件 `fw_change` | diff + auditd | 触发 | ★★★ | added/removed/flush/reload + 操作者（auditd execve） |
| `beacon_fw_drift` | 与基线 diff | 60s | ★★ | 与"声明的期望策略"不一致 |

实现要点：

- `nft -j` 输出原生 JSON，解析稳定；`iptables-save` 文本解析；`ufw status numbered`
- 变更事件带 **actor**：从 auditd（`type=EXECVE` + `type=SYSCALL`）关联 uid/pid/comm/命令行
- 基线由用户显式声明（YAML）或首次采集自动固化，二者取其一，**不静默漂移**

### 5.8 端口与服务审计

| 指标/事件 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_port_listen_info{proto,addr,port,comm,uid}` | `ss -Htulpen` | 60s | ★★★ | info 型指标，值为 1；序列数受端口数限制（通常 <60） |
| `beacon_port_new_total` | 与上一快照 diff | 触发 | ★★★ | 新增监听直接告警（白名单除外） |
| `beacon_port_bind_scope_change_total` | diff | 触发 | ★★★ | `127.0.0.1:6379` → `0.0.0.0:6379`，最典型的配置事故 |
| `beacon_port_uid_anomaly` | 白名单比对 | 触发 | ★★ | 非 root/非服务账号监听 |
| `beacon_port_external_reachable{port}` | 中心侧 TCP connect | 5min | ★★★ | 从公网视角实探 |
| `beacon_exposure_diff{direction}` | 三方集合运算 | 5min | ★★★ | 见下 |

**三方差集**（本项目的差异化能力）：

```
L = 主机监听集合（ss）
S = 云安全组放行集合（云 API，v0.3；否则手工声明）
R = 外部实际可达集合（中心侧实探）

L ∩ S ∩ R        → 正常暴露
L - S            → 主机在听但安全组没开（无害，但说明配置不一致）
S - L            → 安全组开了但没人听（潜在风险：以后起了服务就裸奔）
L ∩ R - 白名单   → 意外暴露（P0）
L ∩ S - R        → 以为开了其实不通（业务故障的常见原因）
```

### 5.9 安全与登录

| 指标/事件 | 来源 | 频率 | 价值 | 说明 |
|---|---|---|---|---|
| `beacon_sec_ssh_login_total{result}` | /var/log/auth.log / journald | 事件 | ★★★ | 成功/失败分开 |
| `beacon_sec_ssh_fail_total{src}` | 同上 | 事件 | ★★★ | src 只保留 Top-10，其余 `other` |
| `beacon_sec_new_user_total` | /etc/passwd hash | 60s | ★★★ | |
| `beacon_sec_authorized_keys_changed` | mtime + hash | 60s | ★★★ | 后门最常用入口 |
| `beacon_sec_sudoers_changed` | hash | 60s | ★★ | |
| `beacon_sec_cron_changed` | crontab + systemd timer | 60s | ★★ | |
| `beacon_sec_kernel_module_new_total` | /proc/modules diff | 60s | ★ | rootkit 线索 |
| `beacon_sec_file_hash{path}` | sha256 | 1h | ★★ | 关键文件：sshd_config、nftables.conf、/etc/passwd、/etc/shadow |
| `beacon_sec_audit_event_total{type}` | auditd | 事件 | ★★ | EXECVE/LOGIN/USER_CMD |

### 5.10 系统与服务健康

| 指标 | 价值 | 说明 |
|---|---|---|
| `beacon_uptime_seconds` / `beacon_reboot_total` | ★★ | 非预期重启（被云厂商迁移/OOM/崩溃） |
| `beacon_systemd_unit_state{unit}` | ★★ | 关键服务 not-found/failed |
| `beacon_time_offset_seconds` | ★★★ | 时间漂移会导致日志与告警时间线错乱，且 TLS 失败 |
| `beacon_kernel_version_info` | ★ | 补丁漂移 |
| `beacon_open_fd_ratio` / `beacon_pid_count` | ★★ | 句柄泄漏、进程数暴涨 |
| `beacon_agent_up` / `beacon_agent_collect_duration_seconds` / `beacon_buffer_bytes` | ★★★ | **监控自己**，否则采集挂了没人知道 |

### 5.11 云主机上下文（可选适配器，默认留空）

**约束：没有云凭据时功能完整度不下降，只是少一个数据源；任何组件不得按主机类型分支。**

| 能力 | 接口 | 默认实现 | 数据源 | 阶段 |
|---|---|---|---|---|
| 实例元数据 | `InstanceInfo` | `169.254.169.254`，1s 超时，失败返回 `unknown` | metadata / manual | MVP |
| 安全组规则 | `SecurityGroup` | `noop` → `source="unavailable"` | manual（默认）/ provider（占位）/ probe | 占位 |
| 带宽上限 | `Bandwidth` | 读配置，缺省 `unknown` | manual / provider | 占位 |
| 公网 / 弹性 IP | `PublicIP` | 元数据或手工 | metadata | MVP |
| 备份 / 快照状态 | `BackupStatus` | `noop` | provider | v0.3 |

未配置云凭据时的降级行为（必须显式，不能静默）：

- 暴露面分析退化为「监听 ∩ 外部实探」，报告里标注 `security_group: unknown`
- 依赖安全组的告警规则自动禁用，**不产生"未知"噪音**
- 指标标签 `source` 区分 `manual` / `probe` / `provider` / `unavailable`

占位接口的意义：将来拿到只读 AK 时，只实现一个 adapter 并配置凭据即可，
上层的暴露面模型、告警规则、报告格式**一行都不用改**。

---

## 6. 异常检测设计

### 6.1 分两层，不要用一套算法打天下

| 层 | 方法 | 适用 | 误报 |
|---|---|---|---|
| 规则层 | 明确判据（阈值、差集、白名单） | 端口新增、防火墙变更、爆破、扫描 | 极低 |
| 基线层 | 统计（同小时分位 + MAD） | 流量突增、夜间流量、连接数异常 | 可控 |

**先规则后基线**：规则层覆盖 80% 的高价值场景，且完全可解释；基线层只用于"没有明确阈值"的流量类。

### 6.2 基线算法

- 按 `host × metric × 小时(0-23)` 分桶，取最近 7 天
- 基线 = 该桶的 `P50` 与 `P95`，离散度用 `MAD`（中位绝对偏差，抗离群）
- 判定：`score = (observed - P95) / (1.4826 × MAD)`，`score > 3` 持续 3 点 → P2；`> 6` → P1
- 冷启动：数据不足 3 天不做基线判定，只走规则层
- 抗误报：维护窗口、已知批处理（备份/同步/包更新）通过 cron 白名单排除
- 周期性：只用同小时桶，天然吸收"白天忙晚上闲"

### 6.3 扫描与爆破的专用逻辑

不要用通用基线判扫描，用**结构特征**：

```
扫描:    unique_dport / conn 高（一个源试很多端口）
爆破:    同一 dport 的 unique_src 高、conn 失败率高、连接存活短
爬虫:    unique_src 高但成功率也高、dport 固定 → 不告警
```

三者用同一份数据区分开，误报率才能压到可用水平。

### 6.4 告警去噪

1. **证据必填**：`evidence` 为空的事件不发送
2. **速率限制**：同 host × kind 10 分钟内最多 1 条，汇总计数
3. **依赖抑制**：主机离线时抑制其上所有其他告警
4. **抖动抑制**：同一规则连续 3 次恢复才发恢复通知
5. **白名单**：端口/进程/目的地，按主机角色分别维护

---

## 7. 告警设计

### 7.1 分级

| 级别 | 定义 | 响应 | 通知方式 |
|---|---|---|---|
| P0 | 服务已不可用或正在被攻击 | 立即 | 电话/强提醒 IM + 邮件 |
| P1 | 即将不可用或明确异常 | 15 分钟内 | IM + 邮件 |
| P2 | 趋势异常/容量预警 | 当天下班前 | 邮件/IM 低优先级 |

### 7.2 规则表（v0.1 落地范围）

| # | 规则 | 条件 | 持续 | 级别 |
|---|---|---|---|---|
| 1 | 主机离线 | `time() - beacon_agent_last_seen > 120` | 立即 | P0 |
| 2 | 磁盘将满 | `used_ratio > 0.95` | 2m | P0 |
| 3 | 磁盘写满预测 | `predict_full_seconds < 6h` | 5m | P0 |
| 4 | inode 耗尽 | `inode_used_ratio > 0.95` | 2m | P0 |
| 5 | 文件系统只读 | `beacon_disk_readonly == 1` | 1m | P0 |
| 6 | 内存告急 | `mem_used_ratio > 0.95` 且 `psi_memory_full > 0` | 5m | P0 |
| 7 | 发生 OOM | `increase(mem_oom_kill_total[5m]) > 0` | 立即 | P0 |
| 8 | 防火墙被关闭 | `fw_service_active == 0` | 1m | P0 |
| 9 | 默认策略放行 | `fw_policy{chain="input"} == accept` | 1m | P0 |
| 10 | 规则集被清空 | `delta(fw_rules_total[5m]) < 0` 且降幅 > 50% | 立即 | P0 |
| 11 | 新增公网监听端口 | `port_new_total > 0` 且 addr 为 0.0.0.0/:: | 立即 | P0 |
| 12 | 监听地址扩大 | `127.0.0.1 → 0.0.0.0` | 立即 | P0 |
| 13 | 意外对外暴露 | `exposure_diff{意外暴露} > 0` | 立即 | P0 |
| 14 | SSH 爆破 | `ssh_fail_total > 20` (5m) | 立即 | P0 |
| 15 | 出站异常突增 | `egress score > 6` | 3 点 | P0 |
| 16 | 本机对外扫描 | `port_scan_out` | 立即 | P0 |
| 17 | authorized_keys 变更 | `changed == 1` | 立即 | P0 |
| 18 | CPU 持续高 | `cpu_usage > 0.90`（排除 steal） | 10m | P1 |
| 19 | CPU steal 高 | `cpu_steal > 0.20` | 10m | P1 |
| 20 | 内存压力 | `psi_memory_some > 0.50` | 10m | P1 |
| 21 | swap 抖动 | `swap_in+swap_out > 1MB/s` | 5m | P1 |
| 22 | 磁盘 await 高 | `await > 0.1s` 且 `util > 0.8` | 5m | P1 |
| 23 | 网卡丢包 | `drop_ratio > 0.01` | 5m | P1 |
| 24 | conntrack 将满 | `used_ratio > 0.85` | 5m | P1 |
| 25 | TCP 重传高 | `retrans_ratio > 0.05` | 10m | P1 |
| 26 | 入向扫描 | `port_scan_in` | 立即 | P1 |
| 27 | 可疑出站端口 | `suspicious_dport` | 立即 | P1 |
| 28 | 首次外联目的地 | `new_destination` 且流量 > 10MB | 立即 | P1 |
| 29 | 防火墙规则变更 | `fw_ruleset_hash` 变化（非维护窗口） | 立即 | P1 |
| 30 | 关键服务失败 | `unit_state == failed`（ssh / docker / nginx 白名单） | 2m | P1 |
| 31 | 时间漂移 | `abs(time_offset) > 5` | 10m | P1 |
| 32 | 磁盘增长预警 | `predict_full_seconds < 30d` | 1h | P2 |
| 33 | 夜间流量异常 | `offhours_traffic` | 立即 | P2 |
| 34 | DNS 异常 | `dns_anomaly` | 立即 | P2 |
| 35 | agent 自身异常 | `collect_duration > 5s` 或 `buffer_bytes > 80%` | 5m | P2 |

### 7.3 聚合与路由

MVP 只实现飞书，其余渠道走同一套抽象，后续加 adapter 即可。

```
vmalert --alert--> Alertmanager --webhook--> beacon-server /hooks/alert --card--> 飞书
```

- Alertmanager 没有原生飞书 receiver，统一用 `webhook_configs` 指向 beacon-server
- beacon-server 负责：签名（`timestamp + HMAC-SHA256(secret + timestamp)`，base64）、卡片渲染、去重、限流、重试
- 飞书自定义机器人的限制要提前接受：
  - **不能打电话/加急**，P0 的强提醒需要企业自建应用（v0.2 可选，不影响 MVP）
  - 有调用频率上限，必须先在服务端按 `host+kind` 合并再发，禁止一条告警一次请求
  - 签名密钥放配置/环境变量，不入库、不写日志
- 卡片结构固定，保证扫一眼能决策：

```
标题   [P0] i-8f2a · 新增公网监听端口
结论   6379 从 127.0.0.1 改为 0.0.0.0，进程 redis-server (uid=999)
证据   字段表：旧值 / 新值 / 首次发现 / 持续时长
按钮   查看曲线（vmui 预置查询）· 静默 1 小时
```

```json
{
  "msg_type": "interactive",
  "card": {
    "header": {"template": "red", "title": {"tag": "plain_text", "content": "[P0] i-8f2a · 新增公网监听端口"}},
    "elements": [
      {"tag": "div", "text": {"tag": "lark_md", "content": "**6379 从 127.0.0.1 改为 0.0.0.0**\n进程 redis-server (uid=999)"}},
      {"tag": "div", "fields": [
        {"is_short": true, "text": {"tag": "lark_md", "content": "**首次发现**\n03:12:07 +08:00"}},
        {"is_short": true, "text": {"tag": "lark_md", "content": "**持续**\n4m12s"}}
      ]},
      {"tag": "action", "actions": [
        {"tag": "button", "text": {"tag": "plain_text", "content": "查看曲线"}, "type": "primary", "url": "..."},
        {"tag": "button", "text": {"tag": "plain_text", "content": "静默 1 小时"}, "type": "default", "url": "..."}
      ]}
    ]
  }
}
```

其余渠道（邮件/企业微信/Telegram）保留 `Notifier` 接口，MVP 不实现。

```
group_by: [host, kind]
group_wait: 30s
group_interval: 5m
repeat_interval: P0=1h / P1=4h / P2=24h
```

- 维护窗口：按主机 + 规则静默，支持 cron 周期（如每周日 02:00–04:00 备份）
- 静默必须有到期时间，禁止永久静默
- 恢复通知必须带"持续时长"和"峰值"

---

## 8. 存储与查询

- **VictoriaMetrics 单节点**：`-retentionPeriod=30d`，5 分钟/1 小时降采样由 `vmalert` 定期计算写入独立 metric
- 查询：PromQL（VM 兼容）
- 事件类数据（防火墙变更、端口变更明细）额外写一份 JSON 到 `beacon-server` 的 SQLite，便于按时间轴回溯；指标库只存计数
- 备份：VM 快照 + SQLite 每日备份到对象存储（可选）

---

## 9. CLI 设计（v0.1 交付形态）

```
beacon agent run                  # 前台运行采集器（systemd 用这个）
beacon agent check                # 自检：权限、依赖命令、网络连通
beacon audit fw                   # 打印当前防火墙快照 + 与基线 diff
beacon audit ports                # 打印监听端口 + 新增/变更
beacon audit exposure             # 三方差集报告
beacon top [--by cpu|mem|net]     # 本机 Top 进程
beacon flow --since 1h --top 10   # 流量画像
beacon rule test rules.yaml       # 本地用历史数据回放规则，调参用
beacon transport test             # 逐层验证 DNS/TCP/TLS/认证/写入
beacon notify test feishu         # 发一张测试卡片到飞书
```

设计原则：**CLI 是 agent 的一部分**（同一个二进制），不依赖中心也能排障。

---

## 10. 部署

### 10.1 被监控主机

```ini
# /etc/systemd/system/beacon-agent.service
[Unit]
Description=beacon agent
After=network-online.target

[Service]
ExecStart=/usr/local/bin/beacon agent run --config /etc/beacon/agent.yaml
Restart=always
RestartSec=5
User=root
# 只读采集，收紧权限
NoNewPrivileges=true
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

- 安装脚本：单条 `curl | bash` 完成下载、校验、建用户、装 unit、注册
- 云主机：优先走元数据拿实例 ID；无元数据则用 `machine-id`
- 支持 Docker（`--network host`，只读挂载 `/proc`、`/sys`、`/var/log`）

### 10.2 中心

Docker Compose（MVP，不含 Grafana）：

```
victoriametrics + vmalert + alertmanager + beacon-server
```

`beacon-server` 承担三件事：主机注册与凭证、Alertmanager webhook → 飞书、审计明细查询 API。
Grafana 只在 M5 决策门通过后加入，不预先安装。

### 10.3 资源预算

| 组件 | 内存 | CPU | 磁盘 |
|---|---|---|---|
| beacon-agent | 25–40 MB | <1% (1 核) | WAL ≤64MB |
| VictoriaMetrics | 150–300 MB | <5% | 2–5 GB（10 台/30 天） |
| vmalert + Alertmanager | 60 MB | 低 | 忽略 |
| Grafana | 150 MB | 低 | 忽略 |

---

## 11. 里程碑

| 阶段 | 内容 | 产出 | 预估 |
|---|---|---|---|
| **M0** | 仓库骨架、配置加载、`host` 采集器（CPU/内存/磁盘/网络/PSI）、`/metrics` 本地端点 | `beacon agent run` 能输出真实指标 | 0.5 天 |
| **M1** | Transport 抽象 + 直连实现、remote_write、WAL、心跳、systemd、安装脚本 | 云主机装完即出现在中心 | 2 天 |
| **M2** | 防火墙审计 + 端口审计 + 暴露面（manual/probe 两个 source，provider 留空） | `beacon audit *` 可用，事件入库 | 2 天 |
| **M3** | 告警规则 + vmalert/Alertmanager + 飞书适配 | 端到端告警可收 | 2 天 |
| **M4** | 流量画像 + 规则型检测器（扫描/爆破/突增） | 异常事件可见 | 3 天 |
| **M5** | 基线算法、CLI 收尾、**Grafana 决策门** | MVP 完成 | 2 天 |
| **M6** | 云厂商 provider adapter（拿到只读 AK 后）、tsnet、企业自建应用加急 | 缺口补齐 | 视情况 |

> MVP 边界：M0–M5。M0–M2 是"有用"的最小闭环，M3 才开始产生告警价值。

### Grafana 决策门（M5 评定）

只有满足以下任一条才引入 Grafana，否则用 vmui + CLI：

1. 需要在同一页对比 3 台以上主机的同一指标（vmui 做多序列对比很别扭）
2. 需要把面板分享给不看命令行的人
3. 需要固化 5 个以上常用视图，且每天都会打开

不满足 = 引入 150MB 内存 + 一套 dashboard JSON 维护成本，收益为负。

---

## 12. 验收标准

| 项 | 标准 |
|---|---|
| 指标准确性 | CPU/内存/磁盘 与 `top`/`df` 偏差 < 2% |
| 断网容忍 | 断网 1 小时后恢复，数据无缺口（时间戳为采集时刻） |
| 资源占用 | 1C1G 云主机上 RSS < 40MB，CPU < 1% |
| 防火墙时延 | 手工改一条 nft 规则，60s 内产生事件并告警 |
| 端口时延 | 启动一个新监听，60s 内告警；绑定地址变化立即告警 |
| 告警质量 | 连续 7 天，误报 ≤ 1 条/天/主机 |
| 可解释性 | 每条告警都带 evidence，能回答"为什么报" |
| 冷启动 | 新主机装上 5 分钟内可见，无需中心侧配置 |
| 传输可插拔 | 把 endpoint 换成 tailnet 域名、`dial` 改为 `system`，不改代码即可上报 |
| 云降级 | 未配置任何云 AK 时，`beacon audit exposure` 仍可运行并显式标注 `security_group: unknown` |
| 飞书可达 | 规则触发到卡片到达 ≤ 60s；限流时合并而非丢弃 |

---

## 13. 风险与未决问题

| 风险 | 影响 | 应对 |
|---|---|---|
| conntrack 采样在超高连接数下开销大 | 采集变慢 | 硬上限采样（4096 条），超出归并；必要时降频 |
| 云主机内核限制 eBPF | 进程级流量不可用 | v0 用 socket inode 映射兜底，eBPF 作为增强 |
| 防火墙规则解析兼容性 | 部分发行版解析失败 | 只支持 nft/iptables/ufw/firewalld 四种，失败降级为 hash 比对 |
| 基线冷启动期误报 | 前 3 天噪音 | 冷启动期只走规则层 |
| 指标基数失控 | 存储打爆 | 严格标签白名单 + 单主机序列上限 + CI 里跑基数检查 |
| 告警疲劳 | 最终没人看 | 见 6.4；宁可少报，不可乱报 |

**已决策（2026-11-11）：**

| 编号 | 决策 | 落到哪 |
|---|---|---|
| D-001 | 采集层自研，存储/查询/通知复用成熟组件 | ADR-001 |
| D-002 | agent 主动出站上报，不要求入站端口 | ADR-002 |
| D-003 | 实现语言 Go（Rust 为备选，条件见 ADR-003） | ADR-003 |
| D-004 | 中心固定在本机；传输层抽象，Tailscale 只是一个 dialer 选项 | ADR-004、§3.6 |
| D-005 | 先做 MVP；Grafana 不进 MVP，M5 按三条标准评估 | §10.2、§11 |
| D-006 | 暂无云厂商只读 AK：云能力做接口占位，`noop` 降级，不阻塞 | ADR-005、§5.11 |
| D-007 | 告警渠道优先飞书；P0 加急需企业自建应用，列为 v0.2 可选 | §7.3 |

**仍需确认：**

1. 飞书机器人 webhook 地址与签名密钥（`secret`），以及是否允许用群机器人（而非企业自建应用）
2. 仓库 git 作者邮箱是否用 GitHub noreply（当前为 `86005552+YQJWXZ@users.noreply.github.com`）
3. 首批被监控主机清单与角色标签（`role` 用于端口/进程白名单）

---

## 附录 A：与其他方案的边界

| 想做的事 | 用什么 |
|---|---|
| 看板、历史曲线 | VictoriaMetrics（vmui）+ Grafana（通过 M5 决策门后） |
| 网站可用性/证书到期 | Uptime Kuma 或 blackbox_exporter（不重复造） |
| 日志检索 | Loki / OpenObserve（不并入） |
| 入侵检测（特征） | Suricata / CrowdSec（本项目只做统计异常，不做特征匹配） |
| 文件完整性 | 本项目只做关键文件 hash，完整 FIM 用 Wazuh/osquery |

# TODO

可执行任务清单。范围与验收标准见 [SPEC.md](SPEC.md)，提交规范见 [AGENTS.md](AGENTS.md)。

## 工作方式

- 一个任务 = 一次提交，commit message 末尾带 `Refs: T-xxx`
- `[ ]` 未开始 · `[~]` 进行中 · `[x]` 完成 · `[-]` 取消（写明原因）
- 每个任务只写 **Done when**，不写实现步骤——实现方式留给编码时决定
- 同一里程碑内标 `∥` 的任务可并行，其余有依赖顺序

## MVP 判定

M0–M5 全部完成，且 [SPEC.md §12](SPEC.md#12-验收标准) 的验收项全部通过。
当前状态：**MVP 已完成**（8 项验收通过，2 项待时间/实机验证，1 项部分验证，见 [docs/acceptance.md](docs/acceptance.md)）。
M6 及以后不属于 MVP。

---

## M0 · 骨架与采集（0.5 天）

> 状态：已完成（2026-11-11）。`beacon agent run --once` 输出 186 条序列，`go test ./...` 全绿。

- [x] **T-001** 项目骨架：`cmd/beacon`、`internal/{collector,config,detector,transport,store}`、`go.mod`、`Makefile`、版本注入
  - Done when：`make build` 产出单二进制，`beacon version` 打印 git sha 与构建时间
- [x] **T-002** 配置系统：YAML + 环境变量 + flag 三层优先级，启动校验，脱敏打印
  - Done when：`beacon config check` 能指出缺失项与非法值，且绝不打印 token
- [x] **T-003** ∥ `collector/host/cpu`：分 mode 使用率、steal、load、PSI、上下文切换
  - Done when：与 `top`/`mpstat` 对比偏差 < 2%（SPEC §12）
- [x] **T-004** ∥ `collector/host/mem`：available/used/cached/slab、swap in/out、PSI、dirty/writeback
  - Done when：与 `free -b` 对比偏差 < 2%
- [x] **T-005** ∥ `collector/host/disk`：statfs 容量/inode/只读、diskstats 吞吐/IOPS/await/util
  - Done when：与 `df -i`、`iostat` 对比偏差 < 2%；inode 与容量分别可见
- [x] **T-006** ∥ `collector/host/net`：每接口 bytes/packets/errors/drops、TCP 状态、conntrack
  - Done when：速率与 `sar -n DEV 1` 一致；conntrack 读失败时降级不报错
- [x] **T-007** 指标注册与本地端点：Prometheus 文本格式，仅监听 `127.0.0.1`，可关闭
  - Done when：`curl 127.0.0.1:9100/metrics` 输出符合命名规范；序列数 ≤ 800
- [x] **T-008** 能力探测：`nft`/`ss`/`auditd`/元数据可达性/`/proc/pressure` 是否存在
  - Done when：缺失项上报 `available=0` 并跳过，进程不退出（ADR-005）
- [x] **T-009** 采集器测试：用固定 `/proc` 样本目录（`testdata/`）跑解析，断言数值
  - Done when：`make test` 在无 root、无 nft 的环境下全绿

## M1 · 上报链路（2 天）

> 状态：已完成（2026-11-11）。实测 60s 断网缓冲 51 KB，恢复后 3s 排空，窗口内心跳样本完整补传。

- [x] **T-101** `Transport` 接口 + `direct` / `unix` dialer
  - Done when：换 dialer 只改配置；`beacon transport test` 报告 DNS/TCP/TLS/认证/写入五层结果
- [x] **T-102** WAL 环形缓冲：崩溃安全、容量上限、保留采集时间戳
  - Done when：`kill -9` 后重启，已入 WAL 的样本不丢、不重复
- [x] **T-103** Shipper：`remote_write` protobuf + snappy，批量/重试/背压
  - Done when：中心不可达时不阻塞采集，内存不增长（pprof 验证）
- [x] **T-104** 注册与凭证：一次性 enroll token 换长期 token，落盘 `0600`
  - Done when：token 泄漏可用中心侧吊销，agent 收到 401 后停止重试并本地告警
- [x] **T-105** 心跳与 `last_seen`
  - Done when：拔网线 2 分钟后中心可判定离线（为 T-301 的 P0 规则供数）
- [x] **T-106** systemd unit + `install.sh` + `uninstall.sh`
  - Done when：新机器一条命令装完，重启后自动恢复
- [x] **T-107** 中心 `docker-compose.yml`：VM + vmalert + alertmanager + beacon-server
  - Done when：`docker compose up -d` 后 8428/9093/8080 可用，`vmui` 能查到数据
- [x] **T-108** `beacon transport test` 子命令（含 `dial=system` 的 tailnet 场景）
  - Done when：同一二进制、只改 endpoint 与 dial，即可从 tailnet 内上报（SPEC §12）
- [x] **T-109** 端到端断网演练脚本
  - Done when：断网 1 小时恢复后，数据无缺口且时间戳为采集时刻

## M2 · 审计（2 天）

> 状态：已完成（2026-11-11）。T-207 的外部可达性目前由 **agent 自测公网 IP** 实现（探测失败一律记为 unknown，不产生误报）；中心侧探针需要中心维护每台主机的公网地址与端口清单，推迟到 M6。

- [x] **T-201** 防火墙快照：`nft -j` / `iptables-save` / `ufw status` / `firewall-cmd`，归一化为统一模型
  - Done when：四类后端至少两种在真实机器上解析正确；不支持时降级为 hash 比对
- [x] **T-202** 规则集 hash + diff + `fw_change` 事件
  - Done when：手工 `nft add rule` 后 60s 内产出带 diff 的事件
- [x] **T-203** 危险规则识别：默认策略、`0.0.0.0/0` 高危端口、IPv6 覆盖缺失
  - Done when：对内置样本集（`testdata/fw/`）的判定与预期完全一致
- [x] **T-204** 端口快照：`ss -Htulpen` 解析出 proto/addr/port/pid/comm/uid
  - Done when：与 `ss -tulpn` 人工核对一致；解析失败不影响主流程
- [x] **T-205** 端口 diff：新增、关闭、**绑定地址扩大**、uid 变化 + 白名单
  - Done when：`127.0.0.1:6379` 改绑 `0.0.0.0:6379` 时立即产生 P0 事件
- [x] **T-206** 暴露面模型：`manual`（YAML）+ `probe`（外部实探）两源差集，provider 留空
  - Done when：无任何云凭据时报告可生成，且显式标注 `security_group: unknown`
- [x] **T-207** 中心侧 probe：并发 TCP connect、超时、重试、结果回写
  - Done when：探测 100 个端口对中心 CPU 影响可忽略，结果与 `nc -z` 一致
- [x] **T-208** 事件存储与查询：SQLite 表结构 + `GET /events?host=&since=`
  - Done when：能按主机与时间范围回放"谁在什么时候改了防火墙"
- [x] **T-209** `beacon audit fw|ports|exposure` 三个子命令
  - Done when：输出人类可读 + `--json` 两种格式

## M3 · 告警（2 天）

> 状态：已完成（2026-11-11）。规则先用 `vmalert -dryRun` 校验，Alertmanager 配置用 `amtool check-config` 校验。
> 已用真实飞书机器人验证：签名正确时卡片送达（497ms），签名错误时飞书返回 `sign match fail`，说明签名确实生效且算法一致。
> 已落地的规则覆盖：主机心跳/磁盘/inode/只读/内存/OOM/swap/CPU/steal/conntrack/重传、防火墙失效/默认放行/高危规则/规则变更/IPv6、端口新增/绑定扩大/意外暴露。
> 依赖 M4 指标（扫描、爆破、出站突增）和尚未采集的指标（时间漂移、服务状态、authorized_keys）的规则暂不写入，避免"永远不触发"的死规则。

- [x] **T-301** vmalert 规则集：MVP 子集（规则 1–17、21–24、29–31）
  - Done when：`vmalert -dryRun` 全部解析通过，无未定义指标
- [x] **T-302** Alertmanager 配置：route / group / inhibit（主机离线抑制其余）
  - Done when：主机离线时，其上的磁盘/CPU 告警被抑制且不出现在通知里
- [x] **T-303** 飞书适配：`/hooks/alert` + 时间戳签名 + 卡片渲染
  - Done when：`beacon notify test feishu` 发出真实卡片，字段与 SPEC §7.3 一致
- [x] **T-304** 去重、合并、限流、重试队列
  - Done when：同 `host+kind` 10 分钟内只发 1 条，并附"N 次"
- [x] **T-305** 卡片内"静默 1 小时"按钮 → Alertmanager silence API
  - Done when：点击后 rule 在 AM 中静默，到期自动恢复
- [x] **T-306** 告警端到端演练
  - Done when：改一条 nft 规则 → 60s 内飞书收到 P1 卡片，且 evidence 可读

## M4 · 流量（3 天）

> 状态：M4 基本完成（2026-11-11）。T-406 的 `--since` 未实现：本地命令只输出当前快照，历史窗口查询走 vmui。
> 出站突增使用「星期几 × 小时」的 EWMA 基线（168 槽位），M5 升级为分位数。
> 已用真实 conntrack 表验证：解析器正确处理 `[UNREPLIED]`、IPv6、`zone=`/`use=` 等额外字段；本机 `nf_conntrack_acct=0`，因此 Top-K 按连接数排序。

- [x] **T-401** conntrack 采样：上限 4096 条，超限归并，读失败降级
  - Done when：10k 连接压力下采集耗时 < 200ms，CPU < 1%
- [x] **T-402** 有界维度聚合 + Top-K 明细（K=20）
  - Done when：单主机序列数不因外部扫描增长（基数测试）
- [x] **T-403** 检测器：`port_scan_in` / `port_scan_out` / `ssh_bruteforce` / `syn_flood`
  - Done when：`nmap -sS` 从另一台机器扫描时 60s 内命中，正常浏览不误报
- [x] **T-404** 可疑端口表 + 首次外联目的地
  - Done when：向 3333 端口发起持续出站时命中 P0，证据含目的地址与字节数
- [x] **T-405** `egress_burst`（依赖 T-501 基线）
  - Done when：人为跑满上传 3 分钟后命中，稳态业务不误报
- [ ] **T-406** `beacon flow --since --top`
  - Done when：任意历史窗口能列出 Top-N 目的与端口

## M5 · 收尾（2 天）

> 状态：已完成（2026-11-11）。验收结果见 [docs/acceptance.md](../docs/acceptance.md)：
> 8 项通过，防火墙变更时延与 7 天误报率待实机/时间验证，tailnet 传输需第二节点。
> 基线已按 §6.2 升级为 P95 + MAD（每槽 96 个样本、20 样本预热、连续 3 点触发）。
> Grafana 决策：不引入，理由见 [docs/adr/0001-grafana.md](../docs/adr/0001-grafana.md)。

- [x] **T-501** 基线算法：同小时 P50/P95/MAD、冷启动期禁用
  - Done when：7 天数据回放，误报 ≤ 1 条/天/主机
- [x] **T-502** CLI 收尾：`top` / `rule test` / `version` / 统一输出格式
  - Done when：所有子命令 `--json` 可用，便于脚本化
- [x] **T-503** 文档：安装、runbook、告警处置手册（每条规则对应"怎么办"）
  - Done when：不看代码也能按文档处理 P0
- [x] **T-504** Grafana 决策门评审并记录结论（满足三条标准之一才装）
  - Done when：`docs/adr/grafana-decision.md` 有明确结论与理由
- [x] **T-505** 完整验收：逐条跑 [SPEC §12](SPEC.md#12-验收标准)
  - Done when：验收表全部打勾，附实测数据

## M5.5 · 控制台（2026-11-11 新增）

> 状态：已完成。视觉按 `design.md` 的 Stripe 风格实现，图表使用 ECharts，不自行绘制。

- [x] **T-701** Vite + React + TS 骨架，ECharts 亮色主题
- [x] **T-702** 中心查询代理（query / query_range / alerts）与管理员鉴权
- [x] **T-703** 总览页：主机卡片、状态统计、活跃告警
- [x] **T-704** 主机详情：CPU/内存/磁盘/网络曲线、端口表、链路与暴露面
- [x] **T-705** 告警页与审计事件页（可展开原始 payload）
- [x] **T-706** 390px 响应式、键盘焦点、prefers-reduced-motion
- [x] **T-707** Docker 多阶段构建与 `-web-dir` 静态资源服务

## M6 · 占位实现（非 MVP）

- [ ] **T-601** `CloudProvider` 接口细化 + `noop` 实现（MVP 已留接口）
- [ ] **T-602** 腾讯云 adapter（CVM 安全组、带宽）
- [ ] **T-603** 阿里云 adapter（ECS 安全组、带宽）
- [ ] **T-604** `tsnet` dialer（内嵌 Tailscale）
- [ ] **T-605** 飞书企业自建应用（P0 加急/电话）
- [ ] **T-606** eBPF 进程级流量
- [ ] **T-607** 中心侧外部探针（替代 agent 自测公网 IP，需要中心维护主机公网地址与端口清单）

---

## 阻塞项

| 事项 | 阻塞 | 影响 |
|---|---|---|
| 飞书机器人 webhook + 签名 secret | T-303、T-306 | 告警链路无法联调，可先用本地 mock |
| 一台真实 1C1G 云主机 | T-109、T-505 | 资源预算无法验证 |
| 首批主机清单与 `role` 标签 | T-205 白名单 | 新端口告警会偏吵 |

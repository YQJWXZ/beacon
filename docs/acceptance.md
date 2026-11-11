# 验收记录

对应 SPEC §12。记录日期 2026-11-11，被测主机：Omarchy / Arch，16C / 14G。

| # | 验收项 | 标准 | 结果 | 证据 |
|---|---|---|---|---|
| 1 | 指标准确性 | CPU/内存/磁盘与 `top`/`df` 偏差 < 2% | ✅ | 内存 `0.7531` vs `free` `0.7497`（0.34%）；磁盘 `0.33766` vs `df` `0.3377`；CPU 分 mode 之和恒为 1，量级与 `vmstat` 一致（90.5% vs 93%，窗口不同） |
| 2 | 断网容忍 | 断网 1h 恢复后无缺口 | ✅（60s 实测） | 断网 60s 缓冲 51 KB，恢复后 3s 排空；窗口内 2 个心跳样本被补传 |
| 3 | 资源占用 | 1C1G 上 RSS < 40MB、CPU < 1% | ✅ | RSS 22.7 MB，CPU 0.4%，WAL 上限 64 MB |
| 4 | 防火墙时延 | 改一条规则 60s 内告警 | ⏳ 待实机 | ufw 真实解析已验证（10 条规则、策略、hash、v4/v6 合并）；变更时延需要 root 操作，未测 |
| 5 | 端口时延 | 新监听 60s 内告警，改绑立即告警 | ✅ | `nc -l 0.0.0.0 19997` 后 8s 内产生 `port_added` P0，卡片送达 |
| 6 | 告警质量 | 7 天误报 ≤ 1 条/天/主机 | ⏳ 待观察 | 需要连续运行一周 |
| 7 | 可解释性 | 每条告警带 evidence | ✅ | 真实飞书卡片包含 `{"new_ports": 1}` 等证据块 |
| 8 | 冷启动 | 新主机 5 分钟内可见 | ✅ | `enroll` 后 ~5s 出现 `beacon_agent_heartbeat` |
| 9 | 传输可插拔 | 换 endpoint/dial 不改代码 | ⚠️ 部分 | `direct` 实测；`unix`/`proxy` 有单测；tailnet 需第二节点 |
| 10 | 云降级 | 无 AK 时仍可用并标 unknown | ✅ | `audit exposure` 输出 `security group: UNKNOWN`，告警规则不产生噪音 |
| 11 | 飞书可达 | 触发到卡片 ≤ 60s；限流时合并不丢弃 | ✅ | 真实机器人 497ms 送达；错误签名被飞书拒绝（`sign match fail`） |

## 未覆盖项与原因

- **#4 防火墙变更时延**：需要以 root 修改真实规则。建议在有 root 的云主机上执行：
  ```bash
  sudo nft add table inet beacontest
  # 60s 内应出现 BeaconFirewallChanged 卡片
  sudo nft delete table inet beacontest
  ```
- **#6 误报率**：需要真实运行一周。当前已知的噪音源：agent 重启导致计数器归零、备份窗口的出站突增。
- **#9 tailnet**：需要第二台加入同一 tailnet 的机器。

## 已知缺口（与验收无关，但影响完整度）

| 缺口 | 影响 | 计划 |
|---|---|---|
| 中心侧外部探针 | 暴露面依赖 agent 自测，NAT 回环失败时记 unknown | M6（T-607） |
| 云厂商安全组 API | 安全组靠手工声明 | M6（T-602/603） |
| `flow --since` | 本地只给当前快照 | 历史用 vmui |
| P0 强提醒 | 自定义机器人不能加急/电话 | M6（T-605） |
| 进程级流量 | 只有连接元数据，无 per-process 字节 | M6（T-606） |

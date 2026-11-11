# Runbook

告警处置手册。每条规则给出：含义、先看什么、common 处理方式。
所有命令在中心或目标主机上执行，`<host>` 用告警卡片里的主机名。

## 通用排障入口

```bash
# 主机当前状态（需要 root）
sudo beacon agent check
sudo beacon audit fw
sudo beacon audit ports
sudo beacon audit exposure
sudo beacon flow
sudo beacon top -by mem

# 中心侧
curl -s localhost:8428/api/v1/query --data-urlencode 'query=up{host="<host>"}'
curl -s -H "Authorization: Bearer $BEACON_ENROLL_TOKEN" \
  'localhost:8080/api/v1/events?host=<host>&limit=20'
```

## P0

### BeaconAgentDown
**含义**：心跳中断超过 2 分钟。可能是主机宕机、agent 崩溃、网络不通。

1. `ping <host>` / 云控制台看实例状态
2. 能 SSH 就 `systemctl status beacon-agent`、`journalctl -u beacon-agent -n 100`
3. 起来了但没数据 → `beacon transport test`
4. 主机正常、agent 正常、仍无数据 → 检查中心 `docker compose ps`

### BeaconDiskFull / BeaconInodeFull
**含义**：空间或 inode ≥ 95%。

```bash
df -h; df -i
du -xh /var 2>/dev/null | sort -rh | head
journalctl --disk-usage
```

优先处理：日志轮转、docker 镜像/容器、`/tmp`。inode 满通常是海量小文件（session、缓存）。

### BeaconFilesystemReadOnly
**含义**：文件系统因错误转只读，写入已失败。

```bash
dmesg -T | tail -50        # 找 I/O error / EXT4-fs error
mount | grep ' ro,'
```

不要急着重启：先确认是否有数据可抢救。云盘故障通常需要工单。

### BeaconFirewallInactive
**含义**：agent 读到了规则表，但没有任何生效的后端（服务停了/规则被清空）。

```bash
systemctl status nftables ufw firewalld
sudo nft list ruleset | head
```

### BeaconFirewallPolicyOpen
**含义**：input 链默认 accept，规则表形同虚设。

```bash
sudo nft list chain inet filter input   # 或 ufw status verbose
```

### BeaconNewPublicPort / BeaconPortScopeWidened
**含义**：出现了绑定 `0.0.0.0` 的新监听，或服务从 `127.0.0.1` 改绑到全网。

```bash
sudo beacon audit ports      # 看 added / widened
sudo ss -tulpn | grep <port>
```

确认是否本人操作。不是 → 按入侵处理：断网、取证、重建。

### BeaconUnexpectedExposure
**含义**：端口实际可达、且不在 `audit.port_allow` 白名单。

先确认探测可信（`audit.probe.public_ip` 是否配置），再决定是加白名单还是关端口。

### BeaconOOMKill
**含义**：内核杀过进程。

```bash
dmesg -T | grep -i 'killed process'
journalctl -k | grep -i oom
```

找内存增长源；临时缓解是加 swap 或限内存，根因通常是泄漏。

### BeaconPortScanOut / BeaconSSHBruteforce / BeaconSuspiciousEgress
**含义**：主机可能已被控制，正在扫描别人 / 被爆破 / 外联矿池。

```bash
sudo beacon flow            # 看 top destinations
sudo ss -tupn | head -30
sudo lastb | head
```

处置顺序：隔离网络 → 保留现场（`ps`、`ss`、`/proc/<pid>/exe`）→ 排查入口（`authorized_keys`、cron、容器）→ 重建而不是清理。

## P1

| 告警 | 先看 | 常见原因 |
|---|---|---|
| BeaconCPUHigh | `beacon top -by cpu` | 业务高峰、死循环、挖矿 |
| BeaconStealHigh | 云控制台 CPU 指标 | 宿主机争抢，本机无法优化，考虑换规格 |
| BeaconMemoryPressure | `free -m`、`beacon top -by mem` | 缓存正常增长 / 泄漏 |
| BeaconSwapThrash | `vmstat 1` 的 si/so | 内存不足，swap 在救命也在拖慢 |
| BeaconConntrackNearFull | `conntrack -C`、`sysctl nf_conntrack_max` | 连接泄漏、扫描、P2P |
| BeaconTCPRetransHigh | `ss -s`、`mtr <peer>` | 链路质量、对端限速 |
| BeaconRiskyFirewallRule | `beacon audit fw` | 22/3306/6379 等对全网开放 |
| BeaconFirewallChanged | `beacon audit fw` 的 diff | 有人改了规则（确认是否本人） |
| BeaconIPv6Unfiltered | `nft list ruleset` 是否有 ip6 表 | 只配了 IPv4 |
| BeaconEgressBurst | `beacon flow` | 备份/同步窗口、被入侵外传 |
| BeaconPortScanIn | `beacon flow` | 互联网背景噪音，一般只需确认未被突破 |

## 静默

卡片上的「静默 1 小时」会创建 Alertmanager silence，到期自动恢复。长期规则调整请改规则文件，不要长期静默。

## 已知误报场景

- **非 root 运行 agent**：防火墙与进程归属不可读，`beacon_fw_readable=0`，相关规则已自动禁用
- **NAT 回环失败**：`audit.probe.public_ip` 探测失败记为 unknown，不触发暴露告警
- **首次采集**：不产生端口/防火墙变更事件（建立基线）
- **agent 重启**：计数器归零，`increase()` 可能短暂出现尖峰，通常一个周期内恢复

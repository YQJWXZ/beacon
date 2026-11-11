# 安装与升级

## 0. 前提

| 项 | 要求 |
|---|---|
| 中心 | Linux + Docker + Compose v2；端口 8428/9093/8080 仅监听 127.0.0.1 |
| 被监控主机 | Linux 4.20+（PSI）；systemd；root |
| 网络 | agent 只需出站访问中心 8080；不需要公网 IP，不需要开入站端口 |
| 远程可达 | 中心在家用 NAT 后时，用 Tailscale（`transport.dial: system` + MagicDNS 域名） |

## 1. 中心

```bash
git clone <repo> beacon && cd beacon

export BEACON_ENROLL_TOKEN=$(openssl rand -hex 16)
export BEACON_FEISHU_WEBHOOK='https://open.feishu.cn/open-apis/bot/v2/hook/xxx'
export BEACON_FEISHU_SECRET='xxx'                 # 可选
export BEACON_PUBLIC_URL='http://<center>:8080'   # 卡片按钮要能打开

docker compose -f deploy/docker-compose.yml up -d
curl -s localhost:8428/health      # OK
```

把 `BEACON_ENROLL_TOKEN`、飞书凭证存到 `deploy/.env` 或密码管理器。**不要提交到仓库。**

### 打开控制台

浏览器访问 `http://<center>:8080`，用同一个 `BEACON_ENROLL_TOKEN` 登录。
如果中心与浏览器不在同一台机器，默认只监听回环，用 SSH 隧道：

```bash
ssh -L 8080:127.0.0.1:8080 <center>
```

控制台的前端资源由 `beacon-server -web-dir` 指定，默认 `web/dist`；Docker 镜像已内置。
本地从源码运行时需要先 `make ui`。

### 验证告警链路

```bash
BEACON_FEISHU_WEBHOOK='...' BEACON_FEISHU_SECRET='...' \
  ./bin/beacon notify test feishu
```

群里出现一张 P0 测试卡片即成功。失败时命令会打印飞书返回的原始错误（例如 `sign match fail`）。

## 2. 被监控主机

```bash
# 在源码目录构建（交叉编译时 GOOS/GOARCH 自行指定）
make build
sudo ./scripts/install.sh ./bin/beacon

# 注册（一次性 token）
sudo beacon agent enroll -server http://<center>:8080 -token $BEACON_ENROLL_TOKEN

# 配置中心地址
sudo sed -i 's|^  endpoint: ""|  endpoint: "http://<center>:8080/api/v1/write"|' /etc/beacon/agent.yaml
sudo systemctl restart beacon-agent

# 自检
sudo beacon agent check
sudo beacon transport test -config /etc/beacon/agent.yaml
```

5 分钟内应能在中心看到该主机：

```bash
curl -s localhost:8428/api/v1/query --data-urlencode 'query=beacon_agent_heartbeat'
```

### 云主机（腾讯云 / 阿里云）

安全组**不需要新增入站规则**。agent 主动出站到中心的 8080；如果中心没有公网地址，把两边加入同一个 Tailscale 网络，配置：

```yaml
transport:
  endpoint: "http://<center-magicdns>:8080/api/v1/write"
  dial: system
```

### 没有云 API 凭据

默认就是这样，无需配置。暴露面分析会标记 `security_group: unknown`，其余功能不受影响。
拿到只读 AK 之前，可以手工声明期望放行规则：

```yaml
audit:
  security_group:
    known: true
    entries:
      - {proto: tcp, port: 22, cidr: "0.0.0.0/0"}
      - {proto: tcp, port: 443, cidr: "0.0.0.0/0"}
```

## 3. 验证安装

```bash
sudo beacon audit fw        # 应显示真实后端与规则数
sudo beacon audit ports     # 应显示监听端口与进程
sudo beacon flow            # 应显示连接方向统计
sudo beacon top             # 应显示进程排行
```

四个命令都正常，说明权限、procfs、conntrack、ss 全部就绪。

## 4. 升级

```bash
git pull && make build
sudo ./scripts/install.sh ./bin/beacon   # 覆盖二进制，保留配置与状态
```

状态目录 `/var/lib/beacon` 不会被动。WAL 中未发送的数据会在重启后继续补传。

## 5. 卸载

```bash
sudo systemctl disable --now beacon-agent
sudo rm /etc/systemd/system/beacon-agent.service /usr/local/bin/beacon
sudo rm -rf /etc/beacon /var/lib/beacon
sudo systemctl daemon-reload
```

中心侧吊销：从 `hosts.json` 删除该主机，或在 `POST /api/v1/enroll` 之外重置 enroll token（旧主机 token 仍有效，需要手工删）。

## 6. 权限说明

agent 以 root 运行，因为：

| 数据 | 需要 |
|---|---|
| `/proc/net/nf_conntrack` | root（文件 0400） |
| `nft list ruleset` | `CAP_NET_ADMIN` |
| `ss -p` 进程归属 | root / `CAP_SYS_PTRACE` |
| `dmesg`（OOM、I/O 错误） | `CAP_SYSLOG` |

agent 不监听网络端口、不执行 shell、不接受中心指令。想进一步收权，可在 unit 里改用
`User=beacon` + `AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_SYSLOG`，
但排障会变复杂，属于可选的 M6 加固项。

## 7. 资源占用

| 组件 | 内存 | CPU | 磁盘 |
|---|---|---|---|
| agent | 20–40 MB | <1% | WAL ≤ 64MB |
| VictoriaMetrics | 150–300 MB | <5% | 2–5 GB / 10 台 / 30 天 |
| beacon-server | 20–40 MB | 低 | SQLite 事件库（很小） |

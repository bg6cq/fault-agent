# Fault Agent

Linux 主机故障监控 Agent，定期检查系统故障状态并上报到集中服务器。支持 JSON 和 YAML 两种配置文件格式。

如果数据送到 https://noc.ustc.edu.cn/api/v1/reports，并设置了GID(注意要设置为工号、学号，即登录时右上角显示的)，可以登录到 https://noc.ustc.edu.cn/linux 查看


## USTC 校内使用

每台服务器上，/usr/src 目录下，
```
cd /usr/src
git clone https://git.ustc.edu.cn/ustcnic/fault-agent
```

支持 JSON 和 YAML 两种配置格式，选择其一即可：

**JSON 格式：**
```
cp config.json.sample config.json
vi config.json # 修改 hostname、sysinfo、url 
python /usr/src/fault-agent/fault-agent.py --config /usr/src/fault-agent/config.json --oneshot
```

**YAML 格式：**
```
cp config.yaml.sample config.yaml
vi config.yaml # 修改 hostname、sysinfo、url
python /usr/src/fault-agent/fault-agent.py --config /usr/src/fault-agent/config.yaml --oneshot
```
如果正常，参考crontab.txt
```
crontab -e 改为定期运行
```



## 目录结构

```
/usr/src/fault-agent/
├── fault-agent.py      # 主脚本（单文件，零依赖）
├── config.json         # 配置文件（JSON 格式）
├── config.json.sample  # JSON 配置示例
├── config.yaml         # 配置文件（YAML 格式）
├── config.yaml.sample  # YAML 配置示例
```

## 依赖

- Python 3.7+
- 仅使用标准库，零外部依赖
- 可选：`pyyaml`（如需 YAML 格式配置文件）

## 快速开始

### 1. 配置

支持 JSON 和 YAML 两种格式，根据 `--config` 文件后缀自动识别。编辑配置文件，修改 `server.url` 指向你的收集服务器：

YAML 格式（`config.yaml`）：

```yaml
server:
  url: https://monitor.example.com/api/v1/reports
  bearer_token_path: /etc/fault-agent/auth.token
```

JSON 格式（`config.json`）：

```json
{
  "server": {
    "url": "https://monitor.example.com/api/v1/reports",
    "bearer_token_path": "/etc/fault-agent/auth.token"
  }
}
```

完整配置项请参考 `config.json.sample` 或 `config.yaml.sample`。

按需调整 `agent.sysinfo`（字符串标签）和 `agent.tags`（KV 标签字典），这些会原封不动上报到服务器。

### 2. 手动运行测试

```bash
python3 fault-agent.py --config config.yaml --oneshot
# 或
python3 fault-agent.py --config config.json --oneshot
```

`--oneshot` 模式将检查结果打印到 stdout 而非发送到服务器。

### 3. 部署到 crontab

```cron
*/2 * * * * /usr/src/fault-agent/fault-agent.py --config /usr/src/fault-agent/config.yaml
```

### 4. 查看日志

默认输出到 stderr（journald）。如需文件日志，重定向 crontab 输出。

## 检查项（共 21 项）

### 系统资源
| 检查项 | 命令/来源 | Warning | Critical |
|--------|-----------|---------|----------|
| 磁盘使用率 | `df -P` | >=85% | >=95% |
| Inode 使用率 | `df -iP` | >=80% | >=90% |
| 内存压力 | `/proc/meminfo` | >=90% | >=95% |
| Swap 颠簸 | `free -w`, `vmstat` | usage>=50% 或 pages>100/s | usage>=80% 或 pages>1000/s |
| CPU 负载 | `/proc/loadavg` | load_per_cpu>2.0 | load_per_cpu>5.0 |
| 文件描述符 | `/proc/sys/fs/file-nr` | >=60% | >=80% |
| 端口耗尽 | `/proc/net/tcp` + `ip_local_port_range` | >=60% | >=80% |
| 连接跟踪表 | `nf_conntrack_*` | >=60% | >=80% |

### 进程/服务
| 检查项 | 命令/来源 | Warning | Critical |
|--------|-----------|---------|----------|
| OOM Killer | `dmesg` / `journalctl -k` | - | 检测到 OOM |
| 僵尸进程 | `ps -eo state` | >0 | >10 |
| systemd 故障 | `systemctl` | degraded 状态 | 存在 failed unit |
| 时间同步 | `chronyc tracking` / `timedatectl` | drift>100ms | drift>5s |

### 存储/文件系统
| 检查项 | 命令/来源 | Warning | Critical |
|--------|-----------|---------|----------|
| 磁盘 I/O 错误 | `dmesg --level=err,warn` / `smartctl` | - | 检测到错误 |
| 文件系统只读 | `/proc/mounts` | - | 可写分区被 remount ro |
| NFS 卡死 | `stat -t` (timeout 5s) | - | stat 超时 |
| RAID/LVM 健康 | `/proc/mdstat`, `lvs`, `pvs` | LVM 属性异常 | RAID 降级/PV 丢失 |

### 网络
| 检查项 | 命令/来源 | Warning | Critical |
|--------|-----------|---------|----------|
| 网络连通性 | TCP connect / ping | 部分目标不可达 | 全部目标不可达 |
| DNS 解析 | `getaddrinfo` | - | 解析失败 |
| 防火墙规则 | `nft` / `iptables` | - | 命令报错 |

### 安全/内核
| 检查项 | 命令/来源 | Warning | Critical |
|--------|-----------|---------|----------|
| 证书过期 | `openssl x509` | <30 天 | <7 天或已过期 |
| 内核错误 | `dmesg --level=err` | - | 检测到新 error |

## 上报 JSON 结构

```json
{
  "agent_version": "1.0.0",
  "hostname": "web-01",
  "machine_id": "e8c4e...",
  "sysinfo": "Beijing-IDC",
  "tags": { "dc": "Beijing", "role": "web" },
  "reported_at": "2026-05-08T14:30:00Z",
  "uptime_seconds": 6134400,
  "checks": [
    {
      "check_name": "disk_usage",
      "status": "ok",
      "message": "",
      "metric_value": 63,
      "metric_unit": "percent",
      "threshold": null,
      "detail": { "mounts": [...] }
    }
  ],
  "summary": { "total": 6, "ok": 4, "warning": 1, "critical": 1, "error": 0 }
}
```

状态含义：`ok`（正常）| `warning`（阈值预警）| `critical`（故障）| `error`（检查执行失败）

## 设计要点

- **健壮性** — 每个检查独立 try/except，子进程设 timeout，命令不存在时静默跳过
- **传输可靠** — 指数退避重试（1s~300s），本地 Spool 目录缓存失败上报
- **状态追踪** — 记录每个检查项的上次状态，支持增量检测
- **安全** — Bearer Token 从文件读取（不在配置中明文存储），TLS 验证默认开启

## 许可证

MIT

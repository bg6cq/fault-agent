#!/usr/bin/env python3
"""Linux Host Fault Monitoring Agent — single-file agent.

Periodically collects system fault indicators and reports them to a central server.
Ships with zero dependencies beyond Python 3 standard library.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
DEFAULT_CONFIG_PATH = Path("/usr/src/fault-agent/config.json")
DEFAULT_SPOOL_DIR = Path("/var/spool/fault-agent")
DEFAULT_STATE_DIR = Path("/var/lib/fault-agent")
DEFAULT_TIMEOUT = 30  # per-check subprocess timeout (seconds)
REPORT_SCHEMA_VERSION = "1.0"

STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
STATUS_ERROR = "error"

log = logging.getLogger("fault-agent")

# ---------------------------------------------------------------------------
# Check result helpers
# ---------------------------------------------------------------------------

def ok_result(name: str, message: str = "", metric_value: float | None = None,
              metric_unit: str = "", threshold: float | None = None,
              detail: dict | None = None) -> dict:
    return dict(check_name=name, status=STATUS_OK, ts=_now_iso(),
                message=message, metric_value=metric_value,
                metric_unit=metric_unit, threshold=threshold, detail=detail or {})


def warning_result(name: str, message: str = "", metric_value: float | None = None,
                   metric_unit: str = "", threshold: float | None = None,
                   detail: dict | None = None) -> dict:
    return dict(check_name=name, status=STATUS_WARNING, ts=_now_iso(),
                message=message, metric_value=metric_value,
                metric_unit=metric_unit, threshold=threshold, detail=detail or {})


def critical_result(name: str, message: str = "", metric_value: float | None = None,
                    metric_unit: str = "", threshold: float | None = None,
                    detail: dict | None = None) -> dict:
    return dict(check_name=name, status=STATUS_CRITICAL, ts=_now_iso(),
                message=message, metric_value=metric_value,
                metric_unit=metric_unit, threshold=threshold, detail=detail or {})


def error_result(name: str, message: str = "") -> dict:
    return dict(check_name=name, status=STATUS_ERROR, ts=_now_iso(),
                message=message, metric_value=None, metric_unit="",
                threshold=None, detail={"error": message})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_int(path: str, default: int = 0) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except Exception:
        return default


def _run(cmd: list[str], timeout: int = DEFAULT_TIMEOUT,
         text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=text, timeout=timeout)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        log.warning("config not found at %s, using defaults", path)
        return _default_config()

    raw = path.read_text()
    # try JSON first (stdlib, zero-dep)
    try:
        cfg = json.loads(raw)
        log.info("loaded JSON config from %s", path)
        return cfg
    except json.JSONDecodeError:
        pass

    # try YAML via pyyaml if available
    try:
        import yaml  # type: ignore
        cfg = yaml.safe_load(raw)
        log.info("loaded YAML config from %s", path)
        return cfg
    except ImportError:
        pass

    log.warning("could not parse %s (not JSON, pyyaml not installed), using defaults", path)
    return _default_config()


def _default_config() -> dict:
    return {
        "agent": {
            "hostname": "",
            "sysinfo": "",
            "tags": {},
            "spool_dir": str(DEFAULT_SPOOL_DIR),
            "state_dir": str(DEFAULT_STATE_DIR),
        },
        "server": {
            "url": "http://localhost:8000/api/v1/reports",
            "timeout_seconds": 30,
            "retry_max_seconds": 300,
            "tls_verify": True,
            "bearer_token_path": "",
        },
        "checks": {
            name: {"enabled": True}
            for name in CHECK_REGISTRY
        },
        "logging": {"level": "info"},
    }


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

CHECK_REGISTRY: list[str] = []


def register_check(fn):
    CHECK_REGISTRY.append(fn.__name__)
    return fn


# ===================================================================
# CHECK MODULES
# ===================================================================

@register_check
def disk_usage(cfg: dict) -> list[dict]:
    """Check disk usage percentage per mount point."""
    conf = cfg.get("disk_usage", {})
    warn = conf.get("warning_pct", 85)
    crit = conf.get("critical_pct", 95)
    exclude_fs = set(conf.get("exclude_fstypes", ["tmpfs", "devtmpfs", "squashfs", "overlay", "efivarfs"]))
    exclude_mnt = set(conf.get("exclude_mounts", ["/boot", "/boot/efi"]))

    try:
        r = _run(["df", "-P"])
    except Exception as e:
        return [error_result("disk_usage", str(e))]

    results: list[dict] = []
    mounts_detail: list[dict] = []
    any_problem = False

    for line in r.stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        fs = parts[0]
        mount = parts[5]
        if fs in exclude_fs or mount in exclude_mnt or mount.startswith("/boot"):
            continue
        try:
            pct = int(parts[4].rstrip("%"))
        except ValueError:
            continue
        total = int(parts[1]) * 1024
        mounts_detail.append({"mount": mount, "used_pct": pct, "total_bytes": total})
        if pct >= crit:
            results.append(critical_result("disk_usage", f"{mount}: {pct}% used",
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(crit), detail={"mount": mount}))
            any_problem = True
        elif pct >= warn:
            results.append(warning_result("disk_usage", f"{mount}: {pct}% used",
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(warn), detail={"mount": mount}))
            any_problem = True

    if not any_problem:
        results.append(ok_result("disk_usage", detail={"mounts": mounts_detail}))
    return results


@register_check
def inode_usage(cfg: dict) -> list[dict]:
    """Check inode usage percentage."""
    conf = cfg.get("inode_usage", {})
    warn = conf.get("warning_pct", 80)
    crit = conf.get("critical_pct", 90)

    try:
        r = _run(["df", "-iP"])
    except Exception as e:
        return [error_result("inode_usage", str(e))]

    results: list[dict] = []
    any_problem = False

    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        mount = parts[5]
        try:
            pct = int(parts[4].rstrip("%"))
        except (ValueError, IndexError):
            continue
        if pct >= crit:
            results.append(critical_result("inode_usage", f"{mount}: inode {pct}%",
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(crit)))
            any_problem = True
        elif pct >= warn:
            results.append(warning_result("inode_usage", f"{mount}: inode {pct}%",
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(warn)))
            any_problem = True

    if not any_problem:
        results.append(ok_result("inode_usage"))
    return results


@register_check
def disk_io_errors(cfg: dict) -> list[dict]:
    """Check for disk I/O errors in kernel log."""
    conf = cfg.get("disk_io_errors", {})
    results: list[dict] = []

    patterns = r"(i/o error|buffer io|ata.*fail|disk failure|media error|read error|write error)"
    lines: list[str] = []

    # try dmesg
    try:
        r = _run(["dmesg", "--level=err,warn"], timeout=10)
        for line in r.stdout.splitlines():
            if re.search(patterns, line, re.IGNORECASE):
                lines.append(line)
    except Exception:
        pass

    # try journalctl -k as fallback
    if not lines:
        try:
            r = _run(["journalctl", "-k", "-p", "3", "-b", "--no-pager"], timeout=10)
            for line in r.stdout.splitlines():
                if re.search(patterns, line, re.IGNORECASE):
                    lines.append(line)
        except Exception:
            pass

    # try smartctl
    smart_status = "not available"
    smartctl_path = shutil.which("smartctl")
    if smartctl_path:
        try:
            r = _run([smartctl_path, "--scan"], timeout=10)
            devices = re.findall(r"/dev/\w+", r.stdout)
            for dev in devices[:4]:
                sr = _run([smartctl_path, "-H", dev], timeout=10)
                if "PASSED" in sr.stdout:
                    smart_status = f"{dev}: PASSED"
                elif "FAILED" in sr.stdout:
                    lines.append(f"SMART health FAILED on {dev}")
                    smart_status = f"{dev}: FAILED"
        except Exception:
            pass

    if lines:
        return [critical_result("disk_io_errors", f"{len(lines)} I/O error(s) detected",
                metric_value=float(len(lines)), metric_unit="count",
                detail={"lines": lines[-5:], "smart_status": smart_status})]
    return [ok_result("disk_io_errors", detail={"smart_status": smart_status})]


@register_check
def memory_usage(cfg: dict) -> list[dict]:
    """Check memory pressure from /proc/meminfo."""
    conf = cfg.get("memory_usage", {})
    warn = conf.get("warning_pct", 90)
    crit = conf.get("critical_pct", 95)

    meminfo = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val_str = parts[1].strip().split()[0]
                    try:
                        meminfo[key] = int(val_str)
                    except ValueError:
                        pass
    except Exception as e:
        return [error_result("memory_usage", str(e))]

    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)
    if total == 0:
        return [error_result("memory_usage", "cannot read MemTotal")]

    used_pct = (1 - available / total) * 100
    detail = {"total_kb": total, "available_kb": available,
              "free_kb": meminfo.get("MemFree", 0),
              "buffers_kb": meminfo.get("Buffers", 0),
              "cached_kb": meminfo.get("Cached", 0)}

    if used_pct >= crit:
        return [critical_result("memory_usage", f"{used_pct:.1f}% used",
                metric_value=round(used_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if used_pct >= warn:
        return [warning_result("memory_usage", f"{used_pct:.1f}% used",
                metric_value=round(used_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("memory_usage", metric_value=round(used_pct, 1),
            metric_unit="percent", detail=detail)]


@register_check
def oom_killer(cfg: dict) -> list[dict]:
    """Check for OOM killer invocations."""
    conf = cfg.get("oom_killer", {})
    results: list[dict] = []
    victims: list[str] = []

    patterns = [r"Killed process (\d+) \((.+)\)", r"invoked oom-killer"]

    try:
        r = _run(["dmesg", "--level=err,warn"], timeout=10)
    except Exception:
        try:
            r = _run(["journalctl", "-k", "-b", "--no-pager"], timeout=10)
        except Exception as e:
            return [error_result("oom_killer", str(e))]

    count = 0
    for line in r.stdout.splitlines():
        if "oom-killer" in line or "Out of memory" in line or "Killed process" in line:
            count += 1
            m = re.search(r"Killed process (\d+) \((.+)\)", line)
            if m:
                victims.append(m.group(2))

    if count > 0:
        detail = {"count": count, "victims": list(set(victims))}
        msg = f"OOM killer invoked {count} time(s)"
        if victims:
            msg += f"; victims: {', '.join(set(victims))}"
        results.append(critical_result("oom_killer", msg,
                       metric_value=float(count), metric_unit="count",
                       detail=detail))
    else:
        results.append(ok_result("oom_killer"))

    return results


@register_check
def swap_thrashing(cfg: dict) -> list[dict]:
    """Check swap usage and page-in/out activity."""
    conf = cfg.get("swap_thrashing", {})
    warn_usage = conf.get("warning_usage_pct", 50)
    crit_usage = conf.get("critical_usage_pct", 80)

    try:
        r = _run(["free", "-w"])
    except Exception as e:
        return [error_result("swap_thrashing", str(e))]

    swap_total = 0
    swap_used = 0
    for line in r.stdout.splitlines():
        if line.startswith("Swap:"):
            parts = line.split()
            if len(parts) >= 3:
                swap_total = int(parts[1])
                swap_used = int(parts[2])
            break

    if swap_total == 0:
        return [ok_result("swap_thrashing", message="no swap configured")]

    usage_pct = swap_used / swap_total * 100

    # Check vmstat for page-in/out rates
    try:
        r = _run(["vmstat", "1", "2"], timeout=5)
        lines = r.stdout.splitlines()
        if len(lines) >= 3:
            parts = lines[2].split()
            si = int(parts[6]) if len(parts) > 6 else 0
            so = int(parts[7]) if len(parts) > 7 else 0
        else:
            si, so = 0, 0
    except Exception:
        si, so = 0, 0

    detail = {"swap_total_kb": swap_total, "swap_used_kb": swap_used,
              "usage_pct": round(usage_pct, 1), "si_per_sec": si, "so_per_sec": so}
    pps = si + so

    if usage_pct >= crit_usage or pps > conf.get("critical_pages_per_sec", 1000):
        return [critical_result("swap_thrashing", f"swap {usage_pct:.1f}% used, {pps} pages/sec",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit_usage), detail=detail)]
    if usage_pct >= warn_usage or pps > conf.get("warning_pages_per_sec", 100):
        return [warning_result("swap_thrashing", f"swap {usage_pct:.1f}% used, {pps} pages/sec",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn_usage), detail=detail)]
    return [ok_result("swap_thrashing", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def cpu_load(cfg: dict) -> list[dict]:
    """Check CPU load averages."""
    conf = cfg.get("cpu_load", {})
    warn_per_cpu = conf.get("warning_load_per_cpu", 2.0)
    crit_per_cpu = conf.get("critical_load_per_cpu", 5.0)

    try:
        load_str = Path("/proc/loadavg").read_text().strip()
    except Exception as e:
        return [error_result("cpu_load", str(e))]

    parts = load_str.split()
    if len(parts) < 3:
        return [error_result("cpu_load", "unexpected /proc/loadavg format")]

    try:
        load_1 = float(parts[0])
        load_5 = float(parts[1])
        load_15 = float(parts[2])
    except ValueError:
        return [error_result("cpu_load", "cannot parse loadavg")]

    try:
        cpu_count = os.cpu_count() or 1
    except Exception:
        cpu_count = 1

    load_per_cpu = load_1 / cpu_count
    detail = {"load_1": load_1, "load_5": load_5, "load_15": load_15,
              "cpu_count": cpu_count, "load_per_cpu": round(load_per_cpu, 2)}

    # Capture top processes if load is high
    top_procs = []
    if load_per_cpu > warn_per_cpu:
        try:
            r = _run(["ps", "-eo", "pid,pcpu,comm", "--sort=-pcpu", "--no-headers"])
            for line in r.stdout.splitlines()[:5]:
                p = line.strip().split(None, 2)
                if len(p) >= 3:
                    top_procs.append({"pid": p[0], "cpu": p[1], "comm": p[2]})
        except Exception:
            pass
    detail["top_processes"] = top_procs

    if load_per_cpu >= crit_per_cpu:
        return [critical_result("cpu_load", f"load per cpu: {load_per_cpu:.2f}",
                metric_value=round(load_per_cpu, 2), metric_unit="load_per_cpu",
                threshold=float(crit_per_cpu), detail=detail)]
    if load_per_cpu >= warn_per_cpu:
        return [warning_result("cpu_load", f"load per cpu: {load_per_cpu:.2f}",
                metric_value=round(load_per_cpu, 2), metric_unit="load_per_cpu",
                threshold=float(warn_per_cpu), detail=detail)]
    return [ok_result("cpu_load", metric_value=round(load_per_cpu, 2), detail=detail)]


@register_check
def zombie_processes(cfg: dict) -> list[dict]:
    """Count zombie/defunct processes."""
    conf = cfg.get("zombie_processes", {})
    warn = conf.get("warning_count", 1)
    crit = conf.get("critical_count", 10)

    try:
        r = _run(["ps", "-eo", "state,pid,comm", "--no-headers"])
    except Exception as e:
        return [error_result("zombie_processes", str(e))]

    zombies = []
    for line in r.stdout.splitlines():
        if line.strip().startswith("Z"):
            parts = line.strip().split(None, 2)
            if len(parts) >= 3:
                zombies.append({"pid": parts[1], "comm": parts[2]})

    count = len(zombies)
    if count >= crit:
        return [critical_result("zombie_processes", f"{count} zombie process(es)",
                metric_value=float(count), metric_unit="count", threshold=float(crit),
                detail={"zombies": zombies, "count": count})]
    if count >= warn:
        return [warning_result("zombie_processes", f"{count} zombie process(es)",
                metric_value=float(count), metric_unit="count", threshold=float(warn),
                detail={"zombies": zombies, "count": count})]
    return [ok_result("zombie_processes", metric_value=float(count), detail={"count": count})]


@register_check
def systemd_failures(cfg: dict) -> list[dict]:
    """Check systemd unit failures and overall system state."""
    results: list[dict] = []

    # overall state
    state = "unknown"
    try:
        r = _run(["systemctl", "is-system-running"], timeout=10)
        state = r.stdout.strip()
    except Exception:
        return [error_result("systemd_failures", "systemctl not available or permission denied")]

    # failed units
    failed_units = []
    try:
        r = _run(["systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend"], timeout=10)
        for line in r.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                failed_units.append({"unit": parts[0], "load": parts[1]})
    except Exception:
        pass

    detail = {"system_state": state, "failed_units": failed_units}

    if state not in ("running", "degraded"):
        # If state is unknown/initializing/maintenance → warning
        if failed_units:
            results.append(critical_result("systemd_failures",
                           f"system state: {state}, {len(failed_units)} failed unit(s)",
                           detail=detail))
        else:
            results.append(warning_result("systemd_failures", f"system state: {state}", detail=detail))
    elif state == "degraded" or failed_units:
        results.append(critical_result("systemd_failures",
                       f"degraded: {len(failed_units)} failed unit(s)",
                       metric_value=float(len(failed_units)), metric_unit="count",
                       detail=detail))
    else:
        results.append(ok_result("systemd_failures", detail=detail))

    return results


@register_check
def network_connectivity(cfg: dict) -> list[dict]:
    """Check network connectivity to configured targets."""
    conf = cfg.get("network_connectivity", {})
    targets = conf.get("targets", [{"host": "1.1.1.1", "method": "tcp", "port": 443}])

    results: list[dict] = []
    target_results = []
    successes = 0
    failures = 0
    total = len(targets)

    for t in targets:
        host = t.get("host", "")
        method = t.get("method", "tcp")
        port = t.get("port", 443)
        tr = {"host": host, "method": method}

        if method == "ping":
            try:
                r = _run(["ping", "-c", "1", "-W", "3", host], timeout=5)
                tr["reachable"] = r.returncode == 0
            except Exception:
                tr["reachable"] = False
        else:  # tcp connect
            try:
                sock = socket.create_connection((host, port), timeout=5)
                sock.close()
                tr["reachable"] = True
            except Exception:
                tr["reachable"] = False

        if tr["reachable"]:
            successes += 1
        else:
            failures += 1
        target_results.append(tr)

    detail = {"targets": target_results, "success": successes, "failure": failures, "total": total}

    if failures == total:
        results.append(critical_result("network_connectivity", f"all {total} target(s) unreachable",
                       detail=detail))
    elif failures > 0:
        results.append(warning_result("network_connectivity", f"{failures}/{total} target(s) unreachable",
                       metric_value=float(failures), metric_unit="count", detail=detail))
    else:
        results.append(ok_result("network_connectivity", detail=detail))

    return results


@register_check
def dns_resolution(cfg: dict) -> list[dict]:
    """Check DNS resolution."""
    conf = cfg.get("dns_resolution", {})
    targets = conf.get("targets", [])

    if not targets:
        # default: try to resolve a common name
        targets = ["google.com"]

    results: list[dict] = []
    target_results = []
    any_failure = False

    for target in targets:
        tr = {"target": target}
        start = time.monotonic()
        try:
            socket.getaddrinfo(target, 80, type=socket.SOCK_STREAM)
            elapsed = time.monotonic() - start
            tr["success"] = True
            tr["time_seconds"] = round(elapsed, 3)
        except socket.gaierror as e:
            elapsed = time.monotonic() - start
            tr["success"] = False
            tr["error"] = str(e)
            tr["time_seconds"] = round(elapsed, 3)
            any_failure = True
        target_results.append(tr)

    # Also read resolvers
    resolvers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                m = re.match(r"^nameserver\s+(\S+)", line)
                if m:
                    resolvers.append(m.group(1))
    except Exception:
        pass

    detail = {"targets": target_results, "resolvers": resolvers}

    if any_failure:
        return [critical_result("dns_resolution", "DNS resolution failed for one or more targets",
                detail=detail)]
    return [ok_result("dns_resolution", detail=detail)]


@register_check
def port_exhaustion(cfg: dict) -> list[dict]:
    """Check for local port exhaustion risk."""
    conf = cfg.get("port_exhaustion", {})
    warn = conf.get("warning_pct", 60)
    crit = conf.get("critical_pct", 80)

    try:
        port_range_str = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().strip()
        parts = port_range_str.split()
        port_min = int(parts[0])
        port_max = int(parts[1])
        port_total = port_max - port_min
    except Exception as e:
        return [error_result("port_exhaustion", str(e))]

    # Count used ports from /proc/net/tcp and /proc/net/tcp6
    used = 0
    for proc_path in ["/proc/net/tcp", "/proc/net/tcp6"]:
        try:
            with open(proc_path) as f:
                for line in f:
                    if line.strip() and not line.startswith("  sl"):
                        used += 1
        except Exception:
            pass

    usage_pct = used / max(port_total, 1) * 100
    detail = {"port_min": port_min, "port_max": port_max, "port_total": port_total,
              "used": used, "usage_pct": round(usage_pct, 1)}

    if usage_pct >= crit:
        return [critical_result("port_exhaustion", f"port usage: {usage_pct:.1f}%",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if usage_pct >= warn:
        return [warning_result("port_exhaustion", f"port usage: {usage_pct:.1f}%",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("port_exhaustion", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def conntrack_saturation(cfg: dict) -> list[dict]:
    """Check conntrack table saturation."""
    conf = cfg.get("conntrack_saturation", {})
    warn = conf.get("warning_pct", 60)
    crit = conf.get("critical_pct", 80)

    conntrack_max = _read_int("/proc/sys/net/netfilter/nf_conntrack_max")
    if conntrack_max == 0:
        # try sysctl
        try:
            r = _run(["sysctl", "-n", "net.netfilter.nf_conntrack_max"], timeout=5)
            conntrack_max = int(r.stdout.strip())
        except Exception:
            return [ok_result("conntrack_saturation", "conntrack not available (not a problem)")]

    conntrack_count = _read_int("/proc/sys/net/netfilter/nf_conntrack_count", -1)
    if conntrack_count < 0:
        return [ok_result("conntrack_saturation", "cannot read conntrack count")]

    usage_pct = conntrack_count / conntrack_max * 100
    detail = {"conntrack_max": conntrack_max, "conntrack_count": conntrack_count,
              "usage_pct": round(usage_pct, 1)}

    if usage_pct >= crit:
        return [critical_result("conntrack_saturation", f"conntrack {usage_pct:.1f}% full",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if usage_pct >= warn:
        return [warning_result("conntrack_saturation", f"conntrack {usage_pct:.1f}% full",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("conntrack_saturation", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def file_descriptors(cfg: dict) -> list[dict]:
    """Check file descriptor usage."""
    conf = cfg.get("file_descriptors", {})
    warn = conf.get("warning_pct", 60)
    crit = conf.get("critical_pct", 80)

    try:
        file_nr = Path("/proc/sys/fs/file-nr").read_text().strip()
    except Exception as e:
        return [error_result("file_descriptors", str(e))]

    parts = file_nr.split()
    if len(parts) < 3:
        return [error_result("file_descriptors", "unexpected file-nr format")]

    try:
        allocated = int(parts[0])
        file_max = int(parts[2])
    except ValueError:
        return [error_result("file_descriptors", "cannot parse file-nr")]

    usage_pct = allocated / max(file_max, 1) * 100
    detail = {"allocated": allocated, "file_max": file_max, "usage_pct": round(usage_pct, 1)}

    if usage_pct >= crit:
        return [critical_result("file_descriptors", f"FD usage: {usage_pct:.1f}%",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if usage_pct >= warn:
        return [warning_result("file_descriptors", f"FD usage: {usage_pct:.1f}%",
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("file_descriptors", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def time_sync(cfg: dict) -> list[dict]:
    """Check NTP/Chrony time sync."""
    conf = cfg.get("time_sync", {})
    warn_drift = conf.get("warning_drift_seconds", 0.1)
    crit_drift = conf.get("critical_drift_seconds", 5.0)

    detail: dict[str, Any] = {}
    drift = None

    # try chronyc first
    try:
        r = _run(["chronyc", "tracking"], timeout=10)
        for line in r.stdout.splitlines():
            m = re.match(r"System time\s*:\s*(-?\d+\.?\d*)\s*(ms|us|ns|s)?", line, re.IGNORECASE)
            if m:
                val = float(m.group(1))
                unit = m.group(2) or "ms"
                if unit == "us":
                    val /= 1_000_000
                elif unit == "ms":
                    val /= 1000
                elif unit == "ns":
                    val /= 1_000_000_000
                drift = abs(val)
                detail["drift_seconds"] = val
                break
            m2 = re.match(r"Last offset\s*:\s*(-?\d+\.?\d*)\s*(ms|us|ns|s)?", line, re.IGNORECASE)
            if m2:
                detail["last_offset"] = m2.group(1)
        if not drift:
            detail["chronyc_output"] = r.stdout.strip()
    except Exception:
        pass

    # fallback to timedatectl
    if drift is None:
        try:
            r = _run(["timedatectl", "show"], timeout=5)
            for line in r.stdout.splitlines():
                if "NTPSynchronized=" in line:
                    detail["ntp_synchronized"] = line.split("=", 1)[1]
                if "FallbackNTPServers=" in line:
                    detail["ntp_servers"] = line.split("=", 1)[1]
        except Exception:
            pass

    if drift is None:
        # check if NTP is even running
        try:
            r = _run(["timedatectl", "show", "-p", "NTPSynchronized"], timeout=5)
            synced = r.stdout.strip()
            if "no" in synced.lower():
                return [warning_result("time_sync", "NTP not synchronized", detail=detail)]
        except Exception:
            pass
        return [warning_result("time_sync", "time sync status unknown", detail=detail)]

    if drift >= crit_drift:
        return [critical_result("time_sync", f"time drift: {drift:.3f}s",
                metric_value=round(drift, 3), metric_unit="seconds",
                threshold=float(crit_drift), detail=detail)]
    if drift >= warn_drift:
        return [warning_result("time_sync", f"time drift: {drift:.3f}s",
                metric_value=round(drift, 3), metric_unit="seconds",
                threshold=float(warn_drift), detail=detail)]
    return [ok_result("time_sync", metric_value=round(drift, 3), detail=detail)]


@register_check
def certificate_expiry(cfg: dict) -> list[dict]:
    """Check system certificate expiration."""
    conf = cfg.get("certificate_expiry", {})
    warn_days = conf.get("warning_days", 30)
    crit_days = conf.get("critical_days", 7)
    search_paths = conf.get("search_paths", ["/etc/ssl/certs", "/etc/pki/tls/certs"])
    max_files = conf.get("max_files", 100)
    timeout = conf.get("timeout_seconds", 10)

    openssl = shutil.which("openssl")
    if not openssl:
        return [ok_result("certificate_expiry", "openssl not available")]

    results: list[dict] = []
    expiring: list[dict] = []
    now = datetime.now(timezone.utc)
    scanned = 0

    for sp in search_paths:
        sp_path = Path(sp)
        if not sp_path.is_dir():
            continue
        for fpath in sp_path.glob("*"):
            if scanned >= max_files:
                break
            if fpath.suffix in (".pem", ".crt", ".0"):
                scanned += 1
                try:
                    r = _run([openssl, "x509", "-in", str(fpath), "-noout",
                              "-enddate", "-subject"], timeout=timeout)
                    enddate = None
                    subject = ""
                    for line in r.stdout.splitlines():
                        if line.startswith("notAfter="):
                            enddate_str = line.split("=", 1)[1].strip()
                            try:
                                enddate = datetime.strptime(enddate_str,
                                                            "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            except ValueError:
                                pass
                        if line.startswith("subject="):
                            subject = line.split("=", 1)[1].strip()
                    if enddate:
                        days_left = (enddate - now).days
                        if days_left < 0:
                            expiring.append({"file": str(fpath), "subject": subject,
                                             "days_left": days_left, "status": "expired"})
                        elif days_left < crit_days:
                            expiring.append({"file": str(fpath), "subject": subject,
                                             "days_left": days_left, "status": "critical"})
                        elif days_left < warn_days:
                            expiring.append({"file": str(fpath), "subject": subject,
                                             "days_left": days_left, "status": "warning"})
                except Exception:
                    continue
        if scanned >= max_files:
            break

    if expiring:
        expired = [e for e in expiring if e["status"] == "expired"]
        critical_certs = [e for e in expiring if e["status"] == "critical" and e["status"] != "expired"]
        warning_certs = [e for e in expiring if e["status"] == "warning"]

        msgs = []
        if expired:
            msgs.append(f"{len(expired)} expired")
        if critical_certs:
            msgs.append(f"{len(critical_certs)} expiring soon")
        if warning_certs:
            msgs.append(f"{len(warning_certs)} nearing expiry")

        if expired or critical_certs:
            results.append(critical_result("certificate_expiry",
                           "; ".join(msgs), detail={"expiring": expiring}))
        else:
            results.append(warning_result("certificate_expiry",
                           "; ".join(msgs), detail={"expiring": expiring}))
    else:
        results.append(ok_result("certificate_expiry", detail={"scanned": scanned}))

    return results


@register_check
def read_only_fs(cfg: dict) -> list[dict]:
    """Check if any writable filesystem was remounted read-only."""
    try:
        r = _run(["mount", "-l"], timeout=10)
    except Exception as e:
        return [error_result("read_only_fs", str(e))]

    read_only_mounts = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        device = parts[0]
        mount = parts[2]
        opts = parts[5].lstrip("(").rstrip(")")
        # Skip pseudo-filesystems
        if device in ("proc", "sysfs", "devtmpfs", "tmpfs") or device.startswith("systemd"):
            continue
        if mount.startswith("/sys") or mount.startswith("/proc") or mount == "/dev":
            continue
        if "ro" in opts.split(","):
            read_only_mounts.append({"device": device, "mount": mount, "options": opts})

    if read_only_mounts:
        return [critical_result("read_only_fs", f"{len(read_only_mounts)} filesystem(s) are read-only",
                detail={"mounts": read_only_mounts})]
    return [ok_result("read_only_fs")]


@register_check
def nfs_mounts(cfg: dict) -> list[dict]:
    """Check for stuck NFS mounts."""
    conf = cfg.get("nfs_mounts", {})
    timeout = conf.get("timeout_seconds", 5)

    nfs_mounts_list = []
    try:
        r = _run(["mount", "-t", "nfs,nfs4"], timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                nfs_mounts_list.append({"device": parts[0], "mount": parts[2]})
    except Exception:
        return [ok_result("nfs_mounts", "no NFS mounts or mount command not available")]

    if not nfs_mounts_list:
        return [ok_result("nfs_mounts", "no NFS mounts found")]

    results: list[dict] = []
    stuck_mounts = []
    healthy = 0

    for mnt in nfs_mounts_list:
        mount_point = mnt["mount"]
        try:
            r = subprocess.run(["stat", "-t", mount_point], capture_output=True,
                               timeout=timeout)
            if r.returncode == 0:
                healthy += 1
            else:
                stuck_mounts.append(mount_point)
        except subprocess.TimeoutExpired:
            stuck_mounts.append(mount_point)
        except Exception as e:
            stuck_mounts.append(mount_point)

    if stuck_mounts:
        return [critical_result("nfs_mounts", f"{len(stuck_mounts)} NFS mount(s) stuck/unreachable",
                detail={"stuck_mounts": stuck_mounts, "healthy": healthy})]
    return [ok_result("nfs_mounts", detail={"healthy": healthy, "total": len(nfs_mounts_list)})]


@register_check
def firewall_errors(cfg: dict) -> list[dict]:
    """Check iptables/nftables for errors."""
    results: list[dict] = []
    errors: list[str] = []

    # try nft first
    nft_path = shutil.which("nft")
    if nft_path:
        try:
            r = _run([nft_path, "list", "ruleset"], timeout=10)
            if r.returncode != 0:
                errors.append(f"nft: {r.stderr.strip()}")
        except Exception as e:
            errors.append(f"nft: {e}")

    # try iptables
    ipt_path = shutil.which("iptables")
    if ipt_path:
        try:
            r = _run([ipt_path, "-L", "-n"], timeout=10)
            if r.returncode != 0:
                errors.append(f"iptables: {r.stderr.strip()}")
            # Check for 0 rules
            rule_count = len(r.stdout.splitlines()) - 2  # approximate
            if rule_count == 0:
                errors.append("iptables: empty ruleset")
        except Exception as e:
            errors.append(f"iptables: {e}")

    if not nft_path and not ipt_path:
        return [ok_result("firewall_errors", "no firewall tools available")]

    if errors:
        return [critical_result("firewall_errors", "; ".join(errors), detail={"errors": errors})]
    return [ok_result("firewall_errors", "firewall rules loaded OK")]


@register_check
def kernel_messages(cfg: dict) -> list[dict]:
    """Check kernel error/warning message counts (incremental)."""
    conf = cfg.get("kernel_messages", {})
    max_lines = conf.get("max_lines", 5)

    # Get current counts
    err_count = 0
    warn_count = 0
    err_lines: list[str] = []

    try:
        r = _run(["dmesg", "--level=err", "--since", "5 minutes ago"], timeout=10)
        err_lines = [l for l in r.stdout.splitlines() if l.strip()]
        err_count = len(err_lines)
    except Exception:
        pass

    try:
        r = _run(["dmesg", "--level=warn", "--since", "5 minutes ago"], timeout=10)
        warn_lines = [l for l in r.stdout.splitlines() if l.strip()]
        warn_count = len(warn_lines)
    except Exception:
        warn_lines = []

    # If --since is not supported (older dmesg), try reading full log
    if err_count == 0 and warn_count == 0:
        try:
            r = _run(["dmesg", "--level=err"], timeout=10)
            err_count = len([l for l in r.stdout.splitlines() if l.strip()])
        except Exception:
            pass

    detail = {
        "err_count": err_count,
        "warn_count": warn_count,
        "recent_errs": err_lines[-max_lines:] if err_lines else [],
    }

    if err_count > 0:
        return [critical_result("kernel_messages", f"{err_count} kernel error(s) in recent log",
                metric_value=float(err_count), metric_unit="count",
                detail=detail)]
    if warn_count > 0:
        return [warning_result("kernel_messages", f"{warn_count} kernel warning(s) in recent log",
                metric_value=float(warn_count), metric_unit="count", detail=detail)]
    return [ok_result("kernel_messages", detail=detail)]


@register_check
def raid_lvm(cfg: dict) -> list[dict]:
    """Check RAID and LVM health."""
    results: list[dict] = []
    detail: dict[str, Any] = {}

    # mdadm RAID check
    mdstat = Path("/proc/mdstat")
    if mdstat.exists():
        try:
            content = mdstat.read_text()
            detail["mdstat"] = content.strip()
            # look for degraded arrays: [UU_] or [U_] patterns
            degraded = re.findall(r"(\w+)\s*:\s*active\s+\S+\s+(\S+\[[^U])", content)
            failed = re.findall(r"(\w+)\s*:\s*active\s+\S+\s+\S+\[_", content)
            if failed:
                results.append(critical_result("raid_lvm",
                               f"RAID failed/degraded: {', '.join(f[0] for f in failed)}",
                               detail=dict(detail)))
            elif degraded:
                results.append(critical_result("raid_lvm",
                               f"RAID degraded: {', '.join(d[0] for d in degraded)}",
                               detail=dict(detail)))
        except Exception:
            pass

    # LVM check
    for cmd in (["lvs", "--noheadings", "-o", "lv_name,vg_name,attr"],
                ["pvs", "--noheadings", "-o", "pv_name,vg_name,attr"]):
        tool = shutil.which(cmd[0])
        if not tool:
            continue
        try:
            r = _run(cmd, timeout=10)
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    attr = parts[2]
                    if "a" not in attr:
                        name = f"{parts[1]}/{parts[0]}" if cmd[0] == "lvs" else parts[0]
                        if "pvs" in cmd[0]:
                            results.append(critical_result("raid_lvm",
                                           f"LVM PV {name} is not active ({attr})"))
                        else:
                            results.append(warning_result("raid_lvm",
                                              f"LVM LV {name} has unexpected attr: {attr}"))
        except Exception:
            pass

    if not results:
        results.append(ok_result("raid_lvm", detail=detail))
    return results


# ---------------------------------------------------------------------------
# Check runner
# ---------------------------------------------------------------------------

# Map check names (from config) to implementation functions
CHECK_MAP: dict[str, callable] = {
    "disk_usage": disk_usage,
    "inode_usage": inode_usage,
    "disk_io_errors": disk_io_errors,
    "memory_usage": memory_usage,
    "oom_killer": oom_killer,
    "swap_thrashing": swap_thrashing,
    "cpu_load": cpu_load,
    "zombie_processes": zombie_processes,
    "systemd_failures": systemd_failures,
    "network_connectivity": network_connectivity,
    "dns_resolution": dns_resolution,
    "port_exhaustion": port_exhaustion,
    "conntrack_saturation": conntrack_saturation,
    "file_descriptors": file_descriptors,
    "time_sync": time_sync,
    "certificate_expiry": certificate_expiry,
    "read_only_fs": read_only_fs,
    "nfs_mounts": nfs_mounts,
    "firewall_errors": firewall_errors,
    "kernel_messages": kernel_messages,
    "raid_lvm": raid_lvm,
}


def run_checks(config: dict) -> list[dict]:
    """Run all enabled checks and return list of check results."""
    check_configs = config.get("checks", {})
    all_results: list[dict] = []

    for check_name, check_fn in CHECK_MAP.items():
        check_conf = check_configs.get(check_name, {"enabled": True})
        if not check_conf.get("enabled", True):
            continue

        try:
            result = check_fn(check_configs)
            if isinstance(result, list):
                all_results.extend(result)
            else:
                all_results.append(result)
            log.debug("check %s completed", check_name)
        except Exception as e:
            log.error("check %s failed with exception: %s", check_name, e)
            all_results.append(error_result(check_name, f"internal error: {e}"))

    return all_results


# ---------------------------------------------------------------------------
# State tracking
# ---------------------------------------------------------------------------

def load_state(state_dir: str | Path) -> dict:
    state_path = Path(state_dir) / "check_states.json"
    if state_path.exists():
        try:
            return json.loads(state_path.read_text())
        except Exception:
            return {}
    return {}


def save_state(state_dir: str | Path, state: dict) -> None:
    state_path = Path(state_dir) / "check_states.json"
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.error("failed to save state: %s", e)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_report(config: dict, results: list[dict]) -> dict:
    agent_cfg = config.get("agent", {})

    # hostname
    hostname = agent_cfg.get("hostname", "") or socket.gethostname()

    # machine_id
    machine_id = ""
    try:
        machine_id = Path("/etc/machine-id").read_text().strip()
    except Exception:
        try:
            machine_id = str(uuid.getnode())
        except Exception:
            machine_id = hostname

    # uptime
    uptime = 0.0
    try:
        uptime_str = Path("/proc/uptime").read_text().strip().split()[0]
        uptime = float(uptime_str)
    except Exception:
        pass

    summary = {"total": len(results), "ok": 0, "warning": 0, "critical": 0, "error": 0}
    for r in results:
        s = r.get("status", STATUS_OK)
        if s in summary:
            summary[s] += 1

    return OrderedDict([
        ("agent_version", VERSION),
        ("schema_version", REPORT_SCHEMA_VERSION),
        ("hostname", hostname),
        ("machine_id", machine_id),
        ("sysinfo", agent_cfg.get("sysinfo", "")),
        ("tags", agent_cfg.get("tags", {})),
        ("reported_at", _now_iso()),
        ("uptime_seconds", uptime),
        ("check_interval_seconds", config.get("check_interval_seconds", 120)),
        ("checks", results),
        ("summary", summary),
    ])


# ---------------------------------------------------------------------------
# HTTP Reporter
# ---------------------------------------------------------------------------

def send_report(report: dict, config: dict) -> bool:
    """Send report to central server. Returns True on success."""
    server_cfg = config.get("server", {})
    url = server_cfg.get("url", "")
    timeout = server_cfg.get("timeout_seconds", 30)
    token_path = server_cfg.get("bearer_token_path", "")
    tls_verify = server_cfg.get("tls_verify", True)

    if not url:
        log.warning("no server url configured")
        return False

    # Parse URL
    if not url.startswith("http://") and not url.startswith("https://"):
        log.error("invalid server url: %s", url)
        return False

    is_https = url.startswith("https://")
    rest = url[len("https://" if is_https else "http://"):]
    host_port, _, path = rest.partition("/")
    path = "/" + path

    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        port = int(port_str)
    else:
        host = host_port
        port = 443 if is_https else 80

    payload = json.dumps(report, indent=2).encode("utf-8")

    for attempt in range(6):  # 5 retries max
        try:
            ctx = ssl.create_default_context()
            if not tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            if is_https:
                sock = socket.create_connection((host, port), timeout=timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                sock = ssock  # type: ignore
            else:
                sock = socket.create_connection((host, port), timeout=timeout)

            try:
                req_headers = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n"
                )
                if token_path:
                    try:
                        token = Path(token_path).read_text().strip()
                        req_headers += f"Authorization: Bearer {token}\r\n"
                    except Exception as e:
                        log.warning("cannot read token from %s: %s", token_path, e)

                sock.sendall(req_headers.encode("utf-8") + b"\r\n" + payload)
                response = sock.recv(4096).decode("utf-8", errors="replace")
                status_line = response.split("\r\n")[0] if response else ""
                code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0

                if 200 <= code < 300:
                    log.info("report sent successfully (HTTP %d)", code)
                    return True
                elif code == 400:
                    log.error("server rejected report (HTTP 400): %s", response[:200])
                    return False  # don't retry bad request
                else:
                    log.warning("server returned HTTP %d (attempt %d)", code, attempt + 1)
            finally:
                sock.close()

        except (socket.timeout, ConnectionRefusedError, ConnectionError, OSError) as e:
            log.warning("connection failed (attempt %d): %s", attempt + 1, e)
        except Exception as e:
            log.error("unexpected send error (attempt %d): %s", attempt + 1, e)

        # Backoff
        if attempt < 5:
            delay = min(2 ** attempt, server_cfg.get("retry_max_seconds", 300))
            log.info("retrying in %ds...", delay)
            time.sleep(delay)

    log.error("failed to send report after all retries")
    return False


# ---------------------------------------------------------------------------
# Spool
# ---------------------------------------------------------------------------

def spool_report(report: dict, spool_dir: str | Path) -> None:
    """Save report to local spool directory for later replay."""
    spool_path = Path(spool_dir)
    try:
        spool_path.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        fname = f"report_{ts}_{os.urandom(4).hex()}.json"
        (spool_path / fname).write_text(json.dumps(report, indent=2))
        log.info("report spooled to %s/%s", spool_dir, fname)
    except Exception as e:
        log.error("failed to spool report: %s", e)


def replay_spool(config: dict) -> int:
    """Send all spooled reports, oldest first. Returns number replayed."""
    spool_dir = Path(config.get("agent", {}).get("spool_dir", str(DEFAULT_SPOOL_DIR)))
    if not spool_dir.is_dir():
        return 0

    files = sorted(spool_dir.glob("report_*.json"))
    replayed = 0
    for f in files:
        if replayed >= 10:  # cap per cycle
            log.info("spool replay cap (10) reached, %d remain", len(files) - replayed)
            break
        try:
            report = json.loads(f.read_text())
            if send_report(report, config):
                f.unlink()
                replayed += 1
                log.debug("replayed spooled report %s", f.name)
            else:
                break  # stop if server is down
        except Exception as e:
            log.error("failed to replay %s: %s", f.name, e)
            # remove corrupt files
            try:
                size = f.stat().st_size
                if size == 0 or size > 10 * 1024 * 1024:
                    f.unlink()
            except Exception:
                pass
            break

    return replayed


# ---------------------------------------------------------------------------
# Oneshot mode (print report to stdout for debugging)
# ---------------------------------------------------------------------------

def print_report(report: dict) -> None:
    print(json.dumps(report, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def setup_logging(config: dict) -> None:
    level_str = config.get("logging", {}).get("level", "info").upper()
    level = getattr(logging, level_str, logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S")


def main():
    parser = argparse.ArgumentParser(description="Linux Host Fault Monitoring Agent")
    parser.add_argument("--config", "-c", default=str(DEFAULT_CONFIG_PATH),
                        help="Path to config file (JSON or YAML)")
    parser.add_argument("--oneshot", action="store_true",
                        help="Run checks once and print report to stdout (no server send)")
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config)

    log.info("fault-agent v%s starting", VERSION)
    log.debug("config loaded from %s", args.config)

    # Phase 1: Replay spooled reports
    if not args.oneshot:
        replayed = replay_spool(config)
        if replayed:
            log.info("replayed %d spooled report(s)", replayed)

    # Phase 2: Run checks
    log.info("running %d check(s)...", len(CHECK_MAP))
    results = run_checks(config)
    log.info("checks complete: %d total", len(results))

    # Phase 3: Build report
    report = build_report(config, results)
    summary = report["summary"]
    log.info("summary: %d ok, %d warning, %d critical, %d error",
             summary["ok"], summary["warning"], summary["critical"], summary["error"])

    # Phase 4: Output / send
    if args.oneshot:
        print_report(report)
    else:
        success = send_report(report, config)
        if not success:
            spool_report(report, config.get("agent", {}).get("spool_dir", str(DEFAULT_SPOOL_DIR)))
            sys.exit(1)

    log.info("fault-agent finished")


if __name__ == "__main__":
    main()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Linux Host Fault Monitoring Agent — single-file agent.

Periodically collects system fault indicators and reports them to a central server.
Compatible with Python 2.7+ and Python 3.4+. Zero dependencies beyond stdlib.
"""
from __future__ import print_function

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
import multiprocessing
from collections import OrderedDict

try:
    from datetime import timezone as _timezone
    _utc = _timezone.utc
except ImportError:
    # Python 2 compatibility
    class _UtcZone(object):
        def utcoffset(self, dt):
            from datetime import timedelta
            return timedelta(0)
        def tzname(self, dt):
            return "UTC"
        def dst(self, dt):
            from datetime import timedelta
            return timedelta(0)
    _utc = _UtcZone()

# ---------------------------------------------------------------------------
# Python 2 / 3 compatibility helpers
# ---------------------------------------------------------------------------

try:
    basestring
except NameError:
    basestring = str

try:
    TimeoutExpired = subprocess.TimeoutExpired
except AttributeError:
    TimeoutExpired = None

try:
    JSONDecodeError = json.JSONDecodeError
except AttributeError:
    JSONDecodeError = ValueError


def _read_file(path):
    """Read file content as string, works on Py2 and Py3."""
    with open(path) as f:
        return f.read()


def _write_file(path, content):
    """Write string content to file."""
    with open(path, 'w') as f:
        f.write(content)


def _path_exists(path):
    return os.path.exists(path)


def _path_isdir(path):
    return os.path.isdir(path)


def _path_splitext(path):
    return os.path.splitext(path)


def _path_getsize(path):
    return os.path.getsize(path)


def _listdir(path):
    try:
        return os.listdir(path)
    except OSError:
        return []


def _makedirs(path):
    try:
        os.makedirs(path)
    except OSError:
        pass


def _cpu_count():
    try:
        return multiprocessing.cpu_count()
    except NotImplementedError:
        return 1


def _monotonic():
    try:
        return time.monotonic()
    except AttributeError:
        return time.time()


def _urandom_hex(n):
    raw = os.urandom(n)
    try:
        return raw.hex()
    except AttributeError:
        return raw.encode('hex')


def _which(cmd):
    try:
        return shutil.which(cmd)
    except AttributeError:
        # Python 2 fallback
        path = os.environ.get('PATH', os.defpath)
        extensions = ['']
        if sys.platform == 'win32':
            extensions += os.environ.get('PATHEXT', '').split(os.pathsep)
        for d in path.split(os.pathsep):
            for ext in extensions:
                f = os.path.join(d, cmd + ext)
                if os.path.isfile(f) and os.access(f, os.X_OK):
                    return f
        return None


def _now_iso():
    from datetime import datetime
    try:
        dt = datetime.now(_utc)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.') + '%03d' % (dt.microsecond // 1000) + '+00:00'
    except TypeError:
        dt = datetime.utcnow()
        return dt.strftime('%Y-%m-%dT%H:%M:%S.') + '%03d' % (dt.microsecond // 1000) + '+00:00'


def _strptime_utc(date_str, fmt):
    """Parse date string, assume UTC. Works on Py2 and Py3."""
    from datetime import datetime
    # Remove %Z handling since Py2 strptime has issues with it
    dt = datetime.strptime(date_str, fmt)
    try:
        return dt.replace(tzinfo=_utc)
    except TypeError:
        return dt


# ---------------------------------------------------------------------------
# Subprocess runner (compatible Py2/Py3)
# ---------------------------------------------------------------------------

class _RunResult(object):
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _run(cmd, timeout=30):
    """Run subprocess and return _RunResult. Compatible with Py2 and Py3."""
    try:
        return _run_py3(cmd, timeout)
    except AttributeError:
        return _run_py2(cmd, timeout)


def _run_py3(cmd, timeout):
    """Python 3.5+ path using subprocess.run."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return _RunResult(r.stdout or '', r.stderr or '', r.returncode)
    except TypeError:
        # Fallback if capture_output/text not supported (Python < 3.7)
        return _run_universal(cmd, timeout)


def _run_py2(cmd, timeout):
    """Python 2 path using Popen."""
    return _run_universal(cmd, timeout)


def _run_universal(cmd, timeout):
    """Universal subprocess runner using Popen."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
        stdout, stderr = p.communicate(timeout=timeout)
        return _RunResult(stdout or '', stderr or '', p.returncode)
    except TypeError:
        # Python 2.7: communicate doesn't support timeout kwarg
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
        # Use poll() loop with timeout
        import threading
        result = {'stdout': '', 'stderr': '', 'returncode': None}

        def _reader():
            try:
                out, err = p.communicate()
                result['stdout'] = out or ''
                result['stderr'] = err or ''
                result['returncode'] = p.returncode
            except Exception:
                pass

        t = threading.Thread(target=_reader)
        t.daemon = True
        t.start()
        t.join(timeout)
        if t.is_alive():
            p.kill()
            t.join()
            raise subprocess.TimeoutExpired(cmd, timeout)
        return _RunResult(result['stdout'], result['stderr'], result['returncode'])


def _run_simple(cmd, timeout=30):
    """Run command, ignore output, return CompletedProcess-like object."""
    return _run(cmd, timeout)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.1"
DEFAULT_CONFIG_PATH = "/usr/src/fault-agent/config.json"
DEFAULT_SPOOL_DIR = "/var/spool/fault-agent"
DEFAULT_STATE_DIR = "/var/lib/fault-agent"
DEFAULT_TIMEOUT = 30
REPORT_SCHEMA_VERSION = "1.0"

STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
STATUS_ERROR = "error"

log = logging.getLogger("fault-agent")

# ---------------------------------------------------------------------------
# Check result helpers
# ---------------------------------------------------------------------------

def _make_result(name, status, message="", metric_value=None,
                 metric_unit="", threshold=None, detail=None):
    return dict(check_name=name, status=status, ts=_now_iso(),
                message=message, metric_value=metric_value,
                metric_unit=metric_unit, threshold=threshold,
                detail=detail if detail is not None else {})


def ok_result(name, message="", metric_value=None, metric_unit="",
              threshold=None, detail=None):
    return _make_result(name, STATUS_OK, message, metric_value,
                        metric_unit, threshold, detail)


def warning_result(name, message="", metric_value=None, metric_unit="",
                   threshold=None, detail=None):
    return _make_result(name, STATUS_WARNING, message, metric_value,
                        metric_unit, threshold, detail)


def critical_result(name, message="", metric_value=None, metric_unit="",
                    threshold=None, detail=None):
    return _make_result(name, STATUS_CRITICAL, message, metric_value,
                        metric_unit, threshold, detail)


def error_result(name, message=""):
    return _make_result(name, STATUS_ERROR, message,
                        detail={"error": message})


def _read_int(path, default=0):
    try:
        return int(_read_file(path).strip())
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path):
    path = str(path)
    if not _path_exists(path):
        log.warning("config not found at %s, using defaults", path)
        return _default_config()

    raw = _read_file(path)
    # try JSON first (stdlib, zero-dep)
    try:
        cfg = json.loads(raw)
        log.info("loaded JSON config from %s", path)
        return cfg
    except JSONDecodeError:
        pass

    # try YAML via pyyaml if available
    try:
        import yaml
        cfg = yaml.safe_load(raw)
        log.info("loaded YAML config from %s", path)
        return cfg
    except ImportError:
        pass

    log.warning("could not parse %s (not JSON, pyyaml not installed), using defaults", path)
    return _default_config()


def _default_config():
    return {
        "agent": {
            "hostname": "",
            "sysinfo": "",
            "tags": {},
            "spool_dir": DEFAULT_SPOOL_DIR,
            "state_dir": DEFAULT_STATE_DIR,
        },
        "server": {
            "url": "https://noc.ustc.edu.cn/api/v1/reports",
            "timeout_seconds": 30,
            "retry_max_seconds": 300,
            "tls_verify": True,
            "bearer_token_path": "",
        },
        "checks": {},
        "logging": {"level": "info"},
    }


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

CHECK_REGISTRY = []


def register_check(fn):
    CHECK_REGISTRY.append(fn.__name__)
    return fn


# ===================================================================
# CHECK MODULES
# ===================================================================

@register_check
def disk_usage(cfg):
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

    results = []
    mounts_detail = []
    any_problem = False

    for line in r.stdout.splitlines()[1:]:
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
            results.append(critical_result("disk_usage", "%s: %d%% used" % (mount, pct),
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(crit), detail={"mount": mount}))
            any_problem = True
        elif pct >= warn:
            results.append(warning_result("disk_usage", "%s: %d%% used" % (mount, pct),
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(warn), detail={"mount": mount}))
            any_problem = True

    if not any_problem:
        results.append(ok_result("disk_usage", detail={"mounts": mounts_detail}))
    return results


@register_check
def inode_usage(cfg):
    """Check inode usage percentage."""
    conf = cfg.get("inode_usage", {})
    warn = conf.get("warning_pct", 80)
    crit = conf.get("critical_pct", 90)

    try:
        r = _run(["df", "-iP"])
    except Exception as e:
        return [error_result("inode_usage", str(e))]

    results = []
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
            results.append(critical_result("inode_usage", "%s: inode %d%%" % (mount, pct),
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(crit)))
            any_problem = True
        elif pct >= warn:
            results.append(warning_result("inode_usage", "%s: inode %d%%" % (mount, pct),
                           metric_value=float(pct), metric_unit="percent",
                           threshold=float(warn)))
            any_problem = True

    if not any_problem:
        results.append(ok_result("inode_usage"))
    return results


@register_check
def disk_io_errors(cfg):
    """Check for disk I/O errors in kernel log."""
    results = []

    patterns = r"(i/o error|buffer io|ata.*fail|disk failure|media error|read error|write error)"
    lines = []

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
    smartctl_path = _which("smartctl")
    if smartctl_path:
        try:
            r = _run([smartctl_path, "--scan"], timeout=10)
            devices = re.findall(r"/dev/\w+", r.stdout)
            for dev in devices[:4]:
                sr = _run([smartctl_path, "-H", dev], timeout=10)
                if "PASSED" in sr.stdout:
                    smart_status = "%s: PASSED" % dev
                elif "FAILED" in sr.stdout:
                    lines.append("SMART health FAILED on %s" % dev)
                    smart_status = "%s: FAILED" % dev
        except Exception:
            pass

    if lines:
        return [critical_result("disk_io_errors", "%d I/O error(s) detected" % len(lines),
                metric_value=float(len(lines)), metric_unit="count",
                detail={"lines": lines[-5:], "smart_status": smart_status})]
    return [ok_result("disk_io_errors", detail={"smart_status": smart_status})]


@register_check
def memory_usage(cfg):
    """Check memory pressure from /proc/meminfo."""
    conf = cfg.get("memory_usage", {})
    warn = conf.get("warning_pct", 90)
    crit = conf.get("critical_pct", 95)

    meminfo = {}
    try:
        for line in _read_file("/proc/meminfo").splitlines():
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
    available = meminfo.get("MemAvailable")
    if available is None:
        available = (meminfo.get("MemFree", 0)
                     + meminfo.get("Buffers", 0)
                     + meminfo.get("Cached", 0))
    if total == 0:
        return [error_result("memory_usage", "cannot read MemTotal")]

    used_pct = (1 - float(available) / total) * 100
    detail = {"total_kb": total, "available_kb": available,
              "free_kb": meminfo.get("MemFree", 0),
              "buffers_kb": meminfo.get("Buffers", 0),
              "cached_kb": meminfo.get("Cached", 0)}

    if used_pct >= crit:
        return [critical_result("memory_usage", "%.1f%% used" % used_pct,
                metric_value=round(used_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if used_pct >= warn:
        return [warning_result("memory_usage", "%.1f%% used" % used_pct,
                metric_value=round(used_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("memory_usage", metric_value=round(used_pct, 1),
            metric_unit="percent", detail=detail)]


@register_check
def oom_killer(cfg):
    """Check for OOM killer invocations."""
    results = []
    victims = []

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
        msg = "OOM killer invoked %d time(s)" % count
        if victims:
            msg += "; victims: %s" % ", ".join(set(victims))
        results.append(critical_result("oom_killer", msg,
                       metric_value=float(count), metric_unit="count",
                       detail=detail))
    else:
        results.append(ok_result("oom_killer"))

    return results


@register_check
def swap_thrashing(cfg):
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

    usage_pct = float(swap_used) / swap_total * 100

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
        return [critical_result("swap_thrashing", "swap %.1f%% used, %d pages/sec" % (usage_pct, pps),
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit_usage), detail=detail)]
    if usage_pct >= warn_usage or pps > conf.get("warning_pages_per_sec", 100):
        return [warning_result("swap_thrashing", "swap %.1f%% used, %d pages/sec" % (usage_pct, pps),
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn_usage), detail=detail)]
    return [ok_result("swap_thrashing", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def cpu_load(cfg):
    """Check CPU load averages."""
    conf = cfg.get("cpu_load", {})
    warn_per_cpu = conf.get("warning_load_per_cpu", 2.0)
    crit_per_cpu = conf.get("critical_load_per_cpu", 5.0)

    try:
        load_str = _read_file("/proc/loadavg").strip()
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
        cpu_count = _cpu_count()
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
        return [critical_result("cpu_load", "load per cpu: %.2f" % load_per_cpu,
                metric_value=round(load_per_cpu, 2), metric_unit="load_per_cpu",
                threshold=float(crit_per_cpu), detail=detail)]
    if load_per_cpu >= warn_per_cpu:
        return [warning_result("cpu_load", "load per cpu: %.2f" % load_per_cpu,
                metric_value=round(load_per_cpu, 2), metric_unit="load_per_cpu",
                threshold=float(warn_per_cpu), detail=detail)]
    return [ok_result("cpu_load", metric_value=round(load_per_cpu, 2), detail=detail)]


@register_check
def zombie_processes(cfg):
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
        return [critical_result("zombie_processes", "%d zombie process(es)" % count,
                metric_value=float(count), metric_unit="count", threshold=float(crit),
                detail={"zombies": zombies, "count": count})]
    if count >= warn:
        return [warning_result("zombie_processes", "%d zombie process(es)" % count,
                metric_value=float(count), metric_unit="count", threshold=float(warn),
                detail={"zombies": zombies, "count": count})]
    return [ok_result("zombie_processes", metric_value=float(count), detail={"count": count})]


@register_check
def systemd_failures(cfg):
    """Check systemd unit failures and overall system state."""
    results = []

    state = "unknown"
    try:
        r = _run(["systemctl", "is-system-running"], timeout=10)
        state = r.stdout.strip()
    except Exception:
        return [error_result("systemd_failures", "systemctl not available or permission denied")]

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
        if failed_units:
            results.append(critical_result("systemd_failures",
                           "system state: %s, %d failed unit(s)" % (state, len(failed_units)),
                           detail=detail))
        else:
            results.append(warning_result("systemd_failures", "system state: %s" % state, detail=detail))
    elif state == "degraded" or failed_units:
        results.append(critical_result("systemd_failures",
                       "degraded: %d failed unit(s)" % len(failed_units),
                       metric_value=float(len(failed_units)), metric_unit="count",
                       detail=detail))
    else:
        results.append(ok_result("systemd_failures", detail=detail))

    return results


@register_check
def network_connectivity(cfg):
    """Check network connectivity to configured targets."""
    conf = cfg.get("network_connectivity", {})
    targets = conf.get("targets", [{"host": "1.1.1.1", "method": "tcp", "port": 443}])

    results = []
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
        results.append(critical_result("network_connectivity", "all %d target(s) unreachable" % total,
                       detail=detail))
    elif failures > 0:
        results.append(warning_result("network_connectivity", "%d/%d target(s) unreachable" % (failures, total),
                       metric_value=float(failures), metric_unit="count", detail=detail))
    else:
        results.append(ok_result("network_connectivity", detail=detail))

    return results


@register_check
def dns_resolution(cfg):
    """Check DNS resolution."""
    conf = cfg.get("dns_resolution", {})
    targets = conf.get("targets", [])

    if not targets:
        targets = ["google.com"]

    results = []
    target_results = []
    any_failure = False

    for target in targets:
        tr = {"target": target}
        start = _monotonic()
        try:
            socket.getaddrinfo(target, 80)
            elapsed = _monotonic() - start
            tr["success"] = True
            tr["time_seconds"] = round(elapsed, 3)
        except socket.gaierror as e:
            elapsed = _monotonic() - start
            tr["success"] = False
            tr["error"] = str(e)
            tr["time_seconds"] = round(elapsed, 3)
            any_failure = True
        target_results.append(tr)

    # Also read resolvers
    resolvers = []
    try:
        for line in _read_file("/etc/resolv.conf").splitlines():
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
def port_exhaustion(cfg):
    """Check for local port exhaustion risk."""
    conf = cfg.get("port_exhaustion", {})
    warn = conf.get("warning_pct", 60)
    crit = conf.get("critical_pct", 80)

    try:
        port_range_str = _read_file("/proc/sys/net/ipv4/ip_local_port_range").strip()
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
            for line in _read_file(proc_path).splitlines():
                if line.strip() and not line.startswith("  sl"):
                    used += 1
        except Exception:
            pass

    usage_pct = float(used) / max(port_total, 1) * 100
    detail = {"port_min": port_min, "port_max": port_max, "port_total": port_total,
              "used": used, "usage_pct": round(usage_pct, 1)}

    if usage_pct >= crit:
        return [critical_result("port_exhaustion", "port usage: %.1f%%" % usage_pct,
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if usage_pct >= warn:
        return [warning_result("port_exhaustion", "port usage: %.1f%%" % usage_pct,
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("port_exhaustion", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def conntrack_saturation(cfg):
    """Check conntrack table saturation."""
    conf = cfg.get("conntrack_saturation", {})
    warn = conf.get("warning_pct", 60)
    crit = conf.get("critical_pct", 80)

    conntrack_max = _read_int("/proc/sys/net/netfilter/nf_conntrack_max")
    if conntrack_max == 0:
        try:
            r = _run(["sysctl", "-n", "net.netfilter.nf_conntrack_max"], timeout=5)
            conntrack_max = int(r.stdout.strip())
        except Exception:
            return [ok_result("conntrack_saturation", "conntrack not available (not a problem)")]

    conntrack_count = _read_int("/proc/sys/net/netfilter/nf_conntrack_count", -1)
    if conntrack_count < 0:
        return [ok_result("conntrack_saturation", "cannot read conntrack count")]

    usage_pct = float(conntrack_count) / conntrack_max * 100
    detail = {"conntrack_max": conntrack_max, "conntrack_count": conntrack_count,
              "usage_pct": round(usage_pct, 1)}

    if usage_pct >= crit:
        return [critical_result("conntrack_saturation", "conntrack %.1f%% full" % usage_pct,
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if usage_pct >= warn:
        return [warning_result("conntrack_saturation", "conntrack %.1f%% full" % usage_pct,
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("conntrack_saturation", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def file_descriptors(cfg):
    """Check file descriptor usage."""
    conf = cfg.get("file_descriptors", {})
    warn = conf.get("warning_pct", 60)
    crit = conf.get("critical_pct", 80)

    try:
        file_nr = _read_file("/proc/sys/fs/file-nr").strip()
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

    usage_pct = float(allocated) / max(file_max, 1) * 100
    detail = {"allocated": allocated, "file_max": file_max, "usage_pct": round(usage_pct, 1)}

    if usage_pct >= crit:
        return [critical_result("file_descriptors", "FD usage: %.1f%%" % usage_pct,
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(crit), detail=detail)]
    if usage_pct >= warn:
        return [warning_result("file_descriptors", "FD usage: %.1f%%" % usage_pct,
                metric_value=round(usage_pct, 1), metric_unit="percent",
                threshold=float(warn), detail=detail)]
    return [ok_result("file_descriptors", metric_value=round(usage_pct, 1), detail=detail)]


@register_check
def time_sync(cfg):
    """Check NTP/Chrony time sync."""
    conf = cfg.get("time_sync", {})
    warn_drift = conf.get("warning_drift_seconds", 0.1)
    crit_drift = conf.get("critical_drift_seconds", 5.0)

    detail = {}
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
                    val /= 1000000
                elif unit == "ms":
                    val /= 1000
                elif unit == "ns":
                    val /= 1000000000
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
        try:
            r = _run(["timedatectl", "show", "-p", "NTPSynchronized"], timeout=5)
            synced = r.stdout.strip()
            if "no" in synced.lower():
                return [warning_result("time_sync", "NTP not synchronized", detail=detail)]
        except Exception:
            pass
        return [warning_result("time_sync", "time sync status unknown", detail=detail)]

    if drift >= crit_drift:
        return [critical_result("time_sync", "time drift: %.3fs" % drift,
                metric_value=round(drift, 3), metric_unit="seconds",
                threshold=float(crit_drift), detail=detail)]
    if drift >= warn_drift:
        return [warning_result("time_sync", "time drift: %.3fs" % drift,
                metric_value=round(drift, 3), metric_unit="seconds",
                threshold=float(warn_drift), detail=detail)]
    return [ok_result("time_sync", metric_value=round(drift, 3), detail=detail)]


@register_check
def certificate_expiry(cfg):
    """Check system certificate expiration."""
    conf = cfg.get("certificate_expiry", {})
    warn_days = conf.get("warning_days", 30)
    crit_days = conf.get("critical_days", 7)
    search_paths = conf.get("search_paths", ["/etc/ssl/certs", "/etc/pki/tls/certs"])
    max_files = conf.get("max_files", 100)
    timeout = conf.get("timeout_seconds", 10)

    openssl = _which("openssl")
    if not openssl:
        return [ok_result("certificate_expiry", "openssl not available")]

    from datetime import datetime
    now = datetime.now(_utc) if hasattr(_utc, 'utcoffset') else datetime.utcnow()
    results = []
    expiring = []
    scanned = 0

    for sp in search_paths:
        if not _path_isdir(sp):
            continue
        for fname in _listdir(sp):
            if scanned >= max_files:
                break
            fpath = os.path.join(sp, fname)
            if not os.path.isfile(fpath):
                continue
            ext = _path_splitext(fname)[1]
            if ext in (".pem", ".crt") or fname.endswith(".0"):
                scanned += 1
                try:
                    r = _run([openssl, "x509", "-in", fpath, "-noout",
                              "-enddate", "-subject"], timeout=timeout)
                    enddate = None
                    subject = ""
                    for line in r.stdout.splitlines():
                        if line.startswith("notAfter="):
                            enddate_str = line.split("=", 1)[1].strip()
                            try:
                                enddate = _strptime_utc(enddate_str,
                                                        "%b %d %H:%M:%S %Y")
                            except ValueError:
                                pass
                        if line.startswith("subject="):
                            subject = line.split("=", 1)[1].strip()
                    if enddate:
                        delta = enddate - now
                        if hasattr(delta, 'days'):
                            days_left = delta.days
                        else:
                            days_left = delta.days
                        if days_left < 0:
                            expiring.append({"file": fpath, "subject": subject,
                                             "days_left": days_left, "status": "expired"})
                        elif days_left < crit_days:
                            expiring.append({"file": fpath, "subject": subject,
                                             "days_left": days_left, "status": "critical"})
                        elif days_left < warn_days:
                            expiring.append({"file": fpath, "subject": subject,
                                             "days_left": days_left, "status": "warning"})
                except Exception:
                    continue
        if scanned >= max_files:
            break

    if expiring:
        expired = [e for e in expiring if e["status"] == "expired"]
        critical_certs = [e for e in expiring if e["status"] == "critical"]
        warning_certs = [e for e in expiring if e["status"] == "warning"]

        msgs = []
        if expired:
            msgs.append("%d expired" % len(expired))
        if critical_certs:
            msgs.append("%d expiring soon" % len(critical_certs))
        if warning_certs:
            msgs.append("%d nearing expiry" % len(warning_certs))

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
def read_only_fs(cfg):
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
        # Skip pseudo-filesystems and inherently read-only mounts
        if device in ("proc", "sysfs", "devtmpfs", "tmpfs") or device.startswith("systemd"):
            continue
        if mount.startswith("/sys") or mount.startswith("/proc") or mount == "/dev":
            continue
        if mount.startswith("/snap/") or mount.startswith("/run/credentials/"):
            continue
        if "ro" in opts.split(","):
            read_only_mounts.append({"device": device, "mount": mount, "options": opts})

    if read_only_mounts:
        return [critical_result("read_only_fs", "%d filesystem(s) are read-only" % len(read_only_mounts),
                detail={"mounts": read_only_mounts})]
    return [ok_result("read_only_fs")]


@register_check
def nfs_mounts(cfg):
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

    results = []
    stuck_mounts = []
    healthy = 0

    for mnt in nfs_mounts_list:
        mount_point = mnt["mount"]
        try:
            r = _run(["stat", "-t", mount_point], timeout=timeout)
            if r.returncode == 0:
                healthy += 1
            else:
                stuck_mounts.append(mount_point)
        except TimeoutExpired:
            stuck_mounts.append(mount_point)
        except Exception:
            stuck_mounts.append(mount_point)

    if stuck_mounts:
        return [critical_result("nfs_mounts", "%d NFS mount(s) stuck/unreachable" % len(stuck_mounts),
                detail={"stuck_mounts": stuck_mounts, "healthy": healthy})]
    return [ok_result("nfs_mounts", detail={"healthy": healthy, "total": len(nfs_mounts_list)})]


@register_check
def firewall_errors(cfg):
    """Check iptables/nftables for errors."""
    results = []
    errors = []

    nft_path = _which("nft")
    if nft_path:
        try:
            r = _run([nft_path, "list", "ruleset"], timeout=10)
            if r.returncode != 0:
                errors.append("nft: %s" % r.stderr.strip())
        except Exception as e:
            errors.append("nft: %s" % str(e))

    ipt_path = _which("iptables")
    if ipt_path:
        try:
            r = _run([ipt_path, "-L", "-n"], timeout=10)
            if r.returncode != 0:
                errors.append("iptables: %s" % r.stderr.strip())
            rule_count = len(r.stdout.splitlines()) - 2
            if rule_count == 0:
                errors.append("iptables: empty ruleset")
        except Exception as e:
            errors.append("iptables: %s" % str(e))

    if not nft_path and not ipt_path:
        return [ok_result("firewall_errors", "no firewall tools available")]

    if errors:
        return [critical_result("firewall_errors", "; ".join(errors), detail={"errors": errors})]
    return [ok_result("firewall_errors", "firewall rules loaded OK")]


@register_check
def kernel_messages(cfg):
    """Check kernel error/warning message counts (incremental)."""
    conf = cfg.get("kernel_messages", {})
    max_lines = conf.get("max_lines", 5)

    err_count = 0
    warn_count = 0
    err_lines = []

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
        return [critical_result("kernel_messages", "%d kernel error(s) in recent log" % err_count,
                metric_value=float(err_count), metric_unit="count",
                detail=detail)]
    if warn_count > 0:
        return [warning_result("kernel_messages", "%d kernel warning(s) in recent log" % warn_count,
                metric_value=float(warn_count), metric_unit="count", detail=detail)]
    return [ok_result("kernel_messages", detail=detail)]


@register_check
def raid_lvm(cfg):
    """Check RAID and LVM health."""
    results = []
    detail = {}

    # mdadm RAID check — parse /proc/mdstat properly
    mdstat_path = "/proc/mdstat"
    if _path_exists(mdstat_path):
        try:
            content = _read_file(mdstat_path)
            detail["mdstat"] = content.strip()
            degraded_devs = []
            failed_devs = []
            # Parse md device lines, each followed by indented continuation lines
            lines = content.splitlines()
            i = 0
            while i < len(lines):
                # Skip Personalities, unused devices, empty lines
                if not lines[i] or lines[i].startswith('Personalities') or lines[i].startswith('unused'):
                    i += 1
                    continue
                m = re.match(r'^(\w+)\s*:\s*active\s+raid\S+\s+', lines[i])
                if m:
                    md_name = m.group(1)
                    # Collect all indented continuation lines
                    block = lines[i]
                    i += 1
                    while i < len(lines) and lines[i].startswith(' '):
                        block += '\n' + lines[i]
                        i += 1
                    if '(F)' in block:
                        failed_devs.append(md_name)
                        continue
                    # Status brackets: [N/M] [UUU...]
                    # Degraded if N < M or status contains _
                    status_m = re.search(r'\[(\d+)/(\d+)\]\s+\[([^\]]+)\]', block)
                    if status_m:
                        present = int(status_m.group(1))
                        total = int(status_m.group(2))
                        status_chars = status_m.group(3)
                        if '_' in status_chars or present != total:
                            degraded_devs.append(md_name)
                else:
                    i += 1
            if failed_devs:
                results.append(critical_result("raid_lvm",
                               "RAID failed: %s" % ", ".join(failed_devs),
                               detail=dict(detail)))
            elif degraded_devs:
                results.append(critical_result("raid_lvm",
                               "RAID degraded: %s" % ", ".join(degraded_devs),
                               detail=dict(detail)))
        except Exception:
            pass

    # LVM check
    for cmd in (["lvs", "--noheadings", "-o", "lv_name,vg_name,attr"],
                ["pvs", "--noheadings", "-o", "pv_name,vg_name,attr"]):
        tool = _which(cmd[0])
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
                        name = "%s/%s" % (parts[1], parts[0]) if cmd[0] == "lvs" else parts[0]
                        if "pvs" in cmd[0]:
                            results.append(critical_result("raid_lvm",
                                           "LVM PV %s is not active (%s)" % (name, attr)))
                        else:
                            results.append(warning_result("raid_lvm",
                                              "LVM LV %s has unexpected attr: %s" % (name, attr)))
        except Exception:
            pass

    if not results:
        results.append(ok_result("raid_lvm", detail=detail))
    return results


@register_check
def suspicious_files(cfg):
    """Check for files that indicate a potential intrusion."""
    conf = cfg.get("suspicious_files", {})
    paths = conf.get("paths", ["/usr/bin/clean"])

    results = []
    found = []

    for path in paths:
        if _path_exists(path):
            try:
                info = {"path": path, "size": _path_getsize(path)}
            except Exception:
                info = {"path": path, "size": -1}
            found.append(info)

    if found:
        names = ", ".join(f["path"] for f in found)
        return [critical_result("suspicious_files",
                "suspicious file(s) found: %s" % names,
                metric_value=float(len(found)), metric_unit="count",
                detail={"files": found})]
    return [ok_result("suspicious_files", message="no suspicious files found")]


# ---------------------------------------------------------------------------
# Check runner
# ---------------------------------------------------------------------------

CHECK_MAP = OrderedDict([
    ("disk_usage", disk_usage),
    ("inode_usage", inode_usage),
    ("disk_io_errors", disk_io_errors),
    ("memory_usage", memory_usage),
    ("oom_killer", oom_killer),
    ("swap_thrashing", swap_thrashing),
    ("cpu_load", cpu_load),
    ("zombie_processes", zombie_processes),
    ("systemd_failures", systemd_failures),
    ("network_connectivity", network_connectivity),
    ("dns_resolution", dns_resolution),
    ("port_exhaustion", port_exhaustion),
    ("conntrack_saturation", conntrack_saturation),
    ("file_descriptors", file_descriptors),
    ("time_sync", time_sync),
    ("certificate_expiry", certificate_expiry),
    ("read_only_fs", read_only_fs),
    ("nfs_mounts", nfs_mounts),
    ("firewall_errors", firewall_errors),
    ("kernel_messages", kernel_messages),
    ("raid_lvm", raid_lvm),
    ("suspicious_files", suspicious_files),
])


def run_checks(config):
    """Run all enabled checks and return list of check results."""
    check_configs = config.get("checks", {})
    all_results = []

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
            all_results.append(error_result(check_name, "internal error: %s" % str(e)))

    return all_results


# ---------------------------------------------------------------------------
# State tracking
# ---------------------------------------------------------------------------

def load_state(state_dir):
    state_path = os.path.join(state_dir, "check_states.json")
    if _path_exists(state_path):
        try:
            return json.loads(_read_file(state_path))
        except Exception:
            return {}
    return {}


def save_state(state_dir, state):
    state_path = os.path.join(state_dir, "check_states.json")
    try:
        _makedirs(state_dir)
        _write_file(state_path, json.dumps(state, indent=2))
    except Exception as e:
        log.error("failed to save state: %s", e)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_report(config, results):
    agent_cfg = config.get("agent", {})

    # hostname
    hostname = agent_cfg.get("hostname", "") or socket.gethostname()

    # machine_id
    machine_id = ""
    try:
        machine_id = _read_file("/etc/machine-id").strip()
    except Exception:
        try:
            machine_id = str(uuid.getnode())
        except Exception:
            machine_id = hostname

    # uptime
    uptime = 0.0
    try:
        uptime_str = _read_file("/proc/uptime").strip().split()[0]
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

def _create_ssl_context(tls_verify=True):
    """Create SSL context. Compatible with older Python 2.7 (< 2.7.9)."""
    try:
        ctx = ssl.create_default_context()
        if not tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx, True
    except AttributeError:
        return None, False


def _wrap_socket(sock, host, ctx, ctx_ok):
    """Wrap socket with SSL. Compatible with older Python 2.7."""
    if ctx_ok:
        return ctx.wrap_socket(sock, server_hostname=host)
    else:
        return ssl.wrap_socket(sock)


def send_report(report, config):
    """Send report to central server. Returns True on success."""
    server_cfg = config.get("server", {})
    url = server_cfg.get("url", "")
    timeout = server_cfg.get("timeout_seconds", 30)
    token_path = server_cfg.get("bearer_token_path", "")
    tls_verify = server_cfg.get("tls_verify", True)

    if not url:
        log.warning("no server url configured")
        return False

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
    log.info("posting report to %s", url)

    for attempt in range(6):
        try:
            ctx, ctx_ok = _create_ssl_context(tls_verify)

            if is_https:
                sock = socket.create_connection((host, port), timeout=timeout)
                sock = _wrap_socket(sock, host, ctx, ctx_ok)
            else:
                sock = socket.create_connection((host, port), timeout=timeout)

            try:
                req_headers = (
                    "POST %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n"
                ) % (path, host, len(payload))
                if token_path:
                    try:
                        token = _read_file(token_path).strip()
                        req_headers += "Authorization: Bearer %s\r\n" % token
                    except Exception as e:
                        log.warning("cannot read token from %s: %s", token_path, e)

                sock.sendall(req_headers.encode("utf-8") + b"\r\n" + payload)
                response = sock.recv(4096).decode("utf-8", "replace")
                status_line = response.split("\r\n")[0] if response else ""
                parts = status_line.split()
                code = int(parts[1]) if len(parts) > 1 else 0

                if 200 <= code < 300:
                    log.info("report sent successfully (HTTP %d)", code)
                    return True
                elif code == 400:
                    log.error("server rejected report (HTTP 400): %s", response[:200])
                    return False
                else:
                    log.warning("server returned HTTP %d (attempt %d)", code, attempt + 1)
            finally:
                sock.close()

        except (socket.timeout, socket.error, OSError) as e:
            log.warning("connection failed (attempt %d): %s", attempt + 1, e)
        except Exception as e:
            log.error("unexpected send error (attempt %d): %s", attempt + 1, e)

        if attempt < 5:
            delay = min(2 ** attempt, server_cfg.get("retry_max_seconds", 300))
            log.info("retrying in %ds...", delay)
            time.sleep(delay)

    log.error("failed to send report after all retries")
    return False


# ---------------------------------------------------------------------------
# Spool
# ---------------------------------------------------------------------------

def spool_report(report, spool_dir):
    """Save report to local spool directory for later replay."""
    try:
        _makedirs(spool_dir)
        ts = time.strftime("%Y%m%dT%H%M%S")
        fname = "report_%s_%s.json" % (ts, _urandom_hex(4))
        _write_file(os.path.join(spool_dir, fname), json.dumps(report, indent=2))
        log.info("report spooled to %s/%s", spool_dir, fname)
    except Exception as e:
        log.error("failed to spool report: %s", e)


def replay_spool(config):
    """Send all spooled reports, oldest first. Returns number replayed."""
    spool_dir = config.get("agent", {}).get("spool_dir", DEFAULT_SPOOL_DIR)
    if not _path_isdir(spool_dir):
        return 0

    files = sorted([f for f in _listdir(spool_dir) if f.startswith("report_") and f.endswith(".json")])
    replayed = 0
    for fname in files:
        if replayed >= 10:
            log.info("spool replay cap (10) reached")
            break
        fpath = os.path.join(spool_dir, fname)
        try:
            report = json.loads(_read_file(fpath))
            if send_report(report, config):
                os.unlink(fpath)
                replayed += 1
                log.debug("replayed spooled report %s", fname)
            else:
                break
        except Exception as e:
            log.error("failed to replay %s: %s", fname, e)
            try:
                size = _path_getsize(fpath)
                if size == 0 or size > 10 * 1024 * 1024:
                    os.unlink(fpath)
            except Exception:
                pass
            break

    return replayed


# ---------------------------------------------------------------------------
# Oneshot mode (print report to stdout for debugging)
# ---------------------------------------------------------------------------

def print_report(report):
    print(json.dumps(report, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def setup_logging(config):
    level_str = config.get("logging", {}).get("level", "info").upper()
    level = getattr(logging, level_str, logging.INFO)
    logging.getLogger().setLevel(level)


def main():
    parser = argparse.ArgumentParser(description="Linux Host Fault Monitoring Agent")
    parser.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH,
                        help="Path to config file (JSON or YAML)")
    parser.add_argument("--oneshot", action="store_true",
                        help="Run checks once and print report to stdout (no server send)")
    args = parser.parse_args()

    # Set up basic logging before config loading (load_config may log warnings)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S")

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
            spool_report(report, config.get("agent", {}).get("spool_dir", DEFAULT_SPOOL_DIR))
            sys.exit(1)

    log.info("fault-agent finished")


if __name__ == "__main__":
    main()

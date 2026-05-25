#!/usr/bin/env python3
"""Tail /var/log/audit/audit.log and emit one JSON line per event to stdout.

Falls back to synthetic audit events when auditd cannot attach to the kernel
(e.g., during CI or Docker Desktop on Mac without full audit capabilities).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any


# ── Audit line parser ──────────────────────────────────────────────────────

_TS_RE = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _parse_audit_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    # Extract type
    type_match = re.match(r"^type=(\S+)", line)
    event_type = type_match.group(1) if type_match else "UNKNOWN"

    # Extract timestamp and serial
    ts_match = _TS_RE.search(line)
    if ts_match:
        ts = float(ts_match.group(1))
        serial = int(ts_match.group(2))
        timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    else:
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        serial = 0

    # Parse key=value pairs (skip the type= and msg= leading fields)
    body = re.sub(r"^type=\S+\s+msg=audit\([^)]+\):\s*", "", line)
    fields: dict[str, Any] = {}
    for m in _KV_RE.finditer(body):
        key, val = m.group(1), m.group(2)
        fields[key] = val.strip('"')

    # Decode hex-encoded strings (audit uses hex for strings with spaces)
    for key in ("exe", "comm", "name", "cwd", "proctitle"):
        if key in fields:
            val = fields[key]
            if re.fullmatch(r"[0-9A-F]{2,}", val, re.IGNORECASE):
                try:
                    fields[key] = bytes.fromhex(val).decode("utf-8", errors="replace")
                except Exception:
                    pass

    # Map syscall numbers to names for the most common ones
    _SYSCALL_NAMES = {
        "59": "execve", "56": "clone", "257": "openat", "42": "connect",
        "43": "accept", "105": "setuid", "106": "setgid", "90": "chmod",
        "175": "init_module", "313": "finit_module",
        # ARM64 equivalents
        "221": "execve", "26": "ptrace",
    }
    if "syscall" in fields:
        fields["syscall_name"] = _SYSCALL_NAMES.get(fields["syscall"], fields["syscall"])

    return {
        "source": "auditd",
        "host": os.environ.get("HOSTNAME", "linux-victim"),
        "container": "dv-linux-victim",
        "timestamp": timestamp,
        "serial": serial,
        "type": event_type,
        **fields,
    }


# ── Synthetic event generator ──────────────────────────────────────────────

_SYNTHETIC_EVENTS = [
    # Normal activity
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/ls",
     "comm": "ls", "uid": "1001", "pid": "1234", "key": "exec"},
    {"type": "SYSCALL", "syscall_name": "connect", "exe": "/usr/bin/curl",
     "comm": "curl", "uid": "1001", "pid": "1235", "key": "network_connect"},
    # Suspicious: shell spawned
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/bin/bash",
     "comm": "bash", "uid": "33", "pid": "1236", "key": "shell_exec",
     "proctitle": "/bin/bash -c id"},
    # Suspicious: credential file read
    {"type": "PATH", "name": "/etc/shadow", "nametype": "READ",
     "uid": "0", "pid": "1237", "key": "sensitive_file"},
    # Suspicious: setuid call
    {"type": "SYSCALL", "syscall_name": "setuid", "exe": "/tmp/exploit",
     "comm": "exploit", "uid": "1001", "pid": "1238", "key": "priv_change"},
    # Normal: python interpreter
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/python3",
     "comm": "python3", "uid": "1001", "pid": "1239", "key": "interpreter_exec"},
    # Suspicious: nmap scan
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/nmap",
     "comm": "nmap", "uid": "0", "pid": "1240", "key": "network_scan"},
    # Sudo use
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/sudo",
     "comm": "sudo", "uid": "1001", "pid": "1241", "key": "sudo_exec"},
]


def _synthetic_event(index: int) -> dict[str, Any]:
    template = _SYNTHETIC_EVENTS[index % len(_SYNTHETIC_EVENTS)]
    return {
        "source": "auditd-synthetic",
        "host": os.environ.get("HOSTNAME", "linux-victim"),
        "container": "dv-linux-victim",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "serial": index,
        **template,
    }


# ── Tail-follow log file ───────────────────────────────────────────────────

def _tail_follow(path: str):
    """Yield lines from a file, blocking until new lines appear."""
    while not os.path.exists(path):
        time.sleep(1)

    with open(path, encoding="utf-8", errors="replace") as fh:
        # Seek to end on first open so we don't replay old events
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(0.2)


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    audit_log = sys.argv[1] if len(sys.argv) > 1 else "/var/log/audit/audit.log"
    auditd_ok = (sys.argv[2].lower() == "true") if len(sys.argv) > 2 else False

    if auditd_ok:
        # Real mode: tail and parse actual audit events
        for raw_line in _tail_follow(audit_log):
            event = _parse_audit_line(raw_line)
            if event:
                print(json.dumps(event), flush=True)
    else:
        # Synthetic mode: emit realistic-looking events on a 10-second cycle
        idx = 0
        while True:
            event = _synthetic_event(idx)
            print(json.dumps(event), flush=True)
            idx += 1
            time.sleep(10)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Victim telemetry agent.

Three modes running in parallel:
  1. Tail /var/log/audit/audit.log and emit JSON (when auditd is available)
  2. Emit periodic synthetic events (fallback on Mac M1 / no kernel audit)
  3. HTTP server on :9099 — atomic-runner POSTs attack commands here;
     the victim executes them and emits a real JSON event to stdout.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


_HOST = os.environ.get("HOSTNAME", "linux-victim")
_AGENT_PORT = int(os.environ.get("AGENT_PORT", "9099"))
_stdout_lock = threading.Lock()


def _emit(event: dict[str, Any]) -> None:
    with _stdout_lock:
        print(json.dumps(event), flush=True)


# ── Audit line parser ──────────────────────────────────────────────────────

_TS_RE = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_SYSCALL_NAMES = {
    "59": "execve", "56": "clone", "257": "openat", "42": "connect",
    "43": "accept", "105": "setuid", "106": "setgid", "90": "chmod",
    "175": "init_module", "313": "finit_module",
    "221": "execve", "26": "ptrace",
}


def _parse_audit_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    type_match = re.match(r"^type=(\S+)", line)
    event_type = type_match.group(1) if type_match else "UNKNOWN"
    ts_match = _TS_RE.search(line)
    if ts_match:
        ts = float(ts_match.group(1))
        serial = int(ts_match.group(2))
        timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    else:
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        serial = 0
    body = re.sub(r"^type=\S+\s+msg=audit\([^)]+\):\s*", "", line)
    fields: dict[str, Any] = {}
    for m in _KV_RE.finditer(body):
        key, val = m.group(1), m.group(2)
        fields[key] = val.strip('"')
    for key in ("exe", "comm", "name", "cwd", "proctitle"):
        if key in fields:
            val = fields[key]
            if re.fullmatch(r"[0-9A-F]{2,}", val, re.IGNORECASE):
                try:
                    fields[key] = bytes.fromhex(val).decode("utf-8", errors="replace")
                except Exception:
                    pass
    if "syscall" in fields:
        fields["syscall_name"] = _SYSCALL_NAMES.get(fields["syscall"], fields["syscall"])
    return {
        "source": "auditd",
        "host": _HOST,
        "container": "dv-linux-victim",
        "timestamp": timestamp,
        "serial": serial,
        "type": event_type,
        **fields,
    }


# ── Synthetic background events ────────────────────────────────────────────

_SYNTHETIC_EVENTS = [
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/ls",
     "comm": "ls", "uid": "1001", "pid": "1234", "key": "exec"},
    {"type": "SYSCALL", "syscall_name": "connect", "exe": "/usr/bin/curl",
     "comm": "curl", "uid": "1001", "pid": "1235", "key": "network_connect"},
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/bin/bash",
     "comm": "bash", "uid": "33", "pid": "1236", "key": "shell_exec",
     "proctitle": "/bin/bash -c id"},
    {"type": "PATH", "name": "/etc/shadow", "nametype": "READ",
     "uid": "0", "pid": "1237", "key": "sensitive_file"},
    {"type": "SYSCALL", "syscall_name": "setuid", "exe": "/tmp/exploit",
     "comm": "exploit", "uid": "1001", "pid": "1238", "key": "priv_change"},
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/python3",
     "comm": "python3", "uid": "1001", "pid": "1239", "key": "interpreter_exec"},
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/nmap",
     "comm": "nmap", "uid": "0", "pid": "1240", "key": "network_scan"},
    {"type": "SYSCALL", "syscall_name": "execve", "exe": "/usr/bin/sudo",
     "comm": "sudo", "uid": "1001", "pid": "1241", "key": "sudo_exec"},
]


def _synthetic_loop() -> None:
    idx = 0
    while True:
        tmpl = _SYNTHETIC_EVENTS[idx % len(_SYNTHETIC_EVENTS)]
        _emit({
            "source": "auditd-synthetic",
            "host": _HOST,
            "container": "dv-linux-victim",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "serial": idx,
            **tmpl,
        })
        idx += 1
        time.sleep(10)


def _tail_loop(audit_log: str) -> None:
    while not os.path.exists(audit_log):
        time.sleep(1)
    with open(audit_log, encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                ev = _parse_audit_line(line)
                if ev:
                    _emit(ev)
            else:
                time.sleep(0.2)


# ── HTTP agent API (port 9099) ─────────────────────────────────────────────

def _run_command(cmd: str, timeout: int = 10) -> tuple[int, str]:
    """Execute a shell command and return (returncode, combined output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, executable="/bin/bash",
        )
        out = (result.stdout + result.stderr).strip()
        return result.returncode, out
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as exc:
        return 1, str(exc)


class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # suppress default access log

    def do_GET(self) -> None:
        if self.path == "/health":
            self._respond(200, {"status": "ok", "host": _HOST})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/simulate":
            self._respond(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid json"})
            return

        technique = req.get("technique", "unknown")
        command = req.get("command", "")
        key = req.get("key", "exec")
        exe = req.get("exe", "/bin/bash")
        uid = req.get("uid", "1001")
        event_type = req.get("event_type", "SYSCALL")
        extra = req.get("extra", {})

        # Execute the command for real
        rc, output = _run_command(command) if command else (0, "")

        # Build and emit the audit event
        pid = str(os.getpid() + hash(command) % 1000)
        event: dict[str, Any] = {
            "source": "auditd-agent",
            "host": _HOST,
            "container": "dv-linux-victim",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "type": event_type,
            "technique": technique,
            "exe": exe,
            "comm": os.path.basename(exe),
            "uid": uid,
            "pid": pid,
            "key": key,
            "cmd_output": output[:500] if output else "",
            "returncode": rc,
            **extra,
        }
        _emit(event)

        self._respond(200, {"ok": True, "event": event, "returncode": rc, "output": output[:500]})

    def _respond(self, code: int, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _agent_server() -> None:
    server = HTTPServer(("0.0.0.0", _AGENT_PORT), AgentHandler)
    print(f"[victim-agent] HTTP API on :{_AGENT_PORT}", file=sys.stderr, flush=True)
    server.serve_forever()


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    audit_log = sys.argv[1] if len(sys.argv) > 1 else "/var/log/audit/audit.log"
    auditd_ok = (sys.argv[2].lower() == "true") if len(sys.argv) > 2 else False

    # Always start the HTTP agent API
    t_agent = threading.Thread(target=_agent_server, daemon=True)
    t_agent.start()

    if auditd_ok:
        _tail_loop(audit_log)
    else:
        _synthetic_loop()


if __name__ == "__main__":
    main()

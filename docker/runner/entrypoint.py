#!/usr/bin/env python3
"""
detection-validator runner entrypoint

Orchestrates one Atomic Red Team atomic under Sysmon for Linux and emits the
captured events as JSONL on stdout.  The host LiveLocalSource reads that JSONL.

Exit codes:
  0  – events written (may be zero if the atomic generated no observable events)
  1  – fatal: ART YAML not found, executor unsupported, or Sysmon failed to start

Environment variables
---------------------
TECHNIQUE_ID  (required) e.g. T1059.004
ATOMIC_NAME   GUID of the specific atomic to run; default: first Linux atomic
PLATFORM      linux (default)

The container must be started with --privileged so eBPF probes load.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required inside the container")

# ── Environment ───────────────────────────────────────────────────────────────

TECHNIQUE_ID = os.environ.get("TECHNIQUE_ID", "")
ATOMIC_NAME = os.environ.get("ATOMIC_NAME", "")
PLATFORM = os.environ.get("PLATFORM", "linux")

SYSMON_LOG = Path("/var/log/sysmon.log")
ART_RAW_BASE = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"

# Event type → EventID mapping for key-value format
_KV_EVENT_ID: dict[str, int] = {
    "Process created": 1,
    "ProcessCreate": 1,
    "Network connection detected": 3,
    "NetworkConnect": 3,
    "Process terminated": 5,
    "ProcessTerminate": 5,
    "File created": 11,
    "FileCreate": 11,
    "File deleted": 23,
    "FileDelete": 23,
}

# Sysmon XML namespace
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


# ── Infrastructure ────────────────────────────────────────────────────────────


def _start_rsyslog() -> None:
    subprocess.Popen(
        ["rsyslogd", "-n"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)


def _start_sysmon() -> bool:
    """Load Sysmon config and start the daemon.  Returns False if it fails."""
    r = subprocess.run(
        ["sysmon", "-accepteula", "-c", "/etc/sysmon/config.xml"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(f"[runner] sysmon failed to start: {r.stderr.strip()}", file=sys.stderr)
        return False
    time.sleep(3)  # Allow eBPF probes to attach
    return True


def _log_size() -> int:
    try:
        return SYSMON_LOG.stat().st_size
    except FileNotFoundError:
        return 0


# ── ART YAML ─────────────────────────────────────────────────────────────────


def _fetch_art(technique_id: str) -> list[dict]:
    url = f"{ART_RAW_BASE}/{technique_id}/{technique_id}.yaml"
    req = urllib.request.Request(url, headers={"User-Agent": "detection-validator-runner/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = yaml.safe_load(resp.read())
    return data.get("atomic_tests", []) if isinstance(data, dict) else []


def _pick_atomic(tests: list[dict], guid: str) -> dict | None:
    """Return the first Linux atomic matching *guid* (or any Linux atomic if guid is empty)."""
    for t in tests:
        platforms = [p.lower() for p in t.get("supported_platforms", [])]
        if "linux" not in platforms:
            continue
        if not guid or t.get("auto_generated_guid", "") == guid:
            return t
    return None


def _substitute_args(command: str, input_arguments: dict) -> str:
    for name, info in input_arguments.items():
        default = str(info.get("default", ""))
        command = command.replace(f"#{{{name}}}", default)
    return command


def _run_atomic(atomic: dict) -> None:
    executor = atomic.get("executor", {})
    exec_name = executor.get("name", "sh").lower()
    if exec_name == "manual":
        print("[runner] manual atomic — skipping execution", file=sys.stderr)
        return

    raw_cmd = executor.get("command", "")
    input_args = atomic.get("input_arguments", {})
    command = _substitute_args(raw_cmd, input_args)

    shell = "bash" if exec_name in ("bash", "shell") else "sh"
    print(f"[runner] executing: {command[:120]!r}", file=sys.stderr)
    subprocess.run([shell, "-c", command], timeout=60, check=False)
    time.sleep(2)  # Let events propagate to syslog


# ── Sysmon event parsing ──────────────────────────────────────────────────────


def _parse_xml_event(xml_str: str) -> dict | None:
    """Parse a Sysmon XML event string into a flat dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    def _find(parent: ET.Element, tag: str) -> ET.Element | None:
        el = parent.find(tag)
        if el is None:
            el = parent.find(f"{{{_NS}}}{tag}")
        return el

    event: dict = {}

    system = _find(root, "System")
    if system is not None:
        eid_el = _find(system, "EventID")
        if eid_el is not None and eid_el.text:
            try:
                event["EventID"] = int(eid_el.text)
            except ValueError:
                pass
        tc_el = _find(system, "TimeCreated")
        if tc_el is not None:
            event["UtcTime"] = tc_el.get("SystemTime", "")
        cmp_el = _find(system, "Computer")
        if cmp_el is not None:
            event["Computer"] = cmp_el.text or ""

    event_data = _find(root, "EventData")
    if event_data is not None:
        for data in event_data:
            name = data.get("Name", "")
            if name:
                event[name] = data.text or ""

    return event if event else None


_KV_RE = re.compile(r"(\w[\w ]*?)=([^,\n]+)")


def _parse_kv_event(msg: str) -> dict | None:
    """Parse Sysmon Linux key=value syslog message format.

    Messages look like:
      Process created: UtcTime=2024-06-05 12:00:00, ProcessId=1234, Image=/usr/bin/bash, ...
    """
    event: dict = {}

    # Derive EventID from prefix
    colon = msg.find(":")
    if colon > 0:
        event_type = msg[:colon].strip()
        eid = _KV_EVENT_ID.get(event_type)
        if eid:
            event["EventID"] = eid
        msg = msg[colon + 1:]

    for m in _KV_RE.finditer(msg):
        event[m.group(1).strip()] = m.group(2).strip()

    return event if len(event) > 1 else None


def _parse_sysmon_line(line: str) -> dict | None:
    """Try JSON, then XML block, then key-value."""
    line = line.strip()
    if not line:
        return None

    # JSON
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass

    # Embedded XML (line may be prefixed by syslog header on some rsyslog configs)
    xml_start = line.find("<Event")
    if xml_start >= 0:
        xml_end = line.rfind("</Event>")
        if xml_end > xml_start:
            return _parse_xml_event(line[xml_start: xml_end + 8])

    # Key=Value (default Sysmon for Linux syslog format)
    return _parse_kv_event(line)


def _collect_events(baseline_size: int) -> list[dict]:
    """Read events appended to the log after *baseline_size* bytes."""
    events: list[dict] = []
    try:
        content = SYSMON_LOG.read_text(errors="replace")
    except FileNotFoundError:
        return events

    new_content = content[baseline_size:]
    for line in new_content.splitlines():
        ev = _parse_sysmon_line(line)
        if ev:
            events.append(ev)
    return events


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    if not TECHNIQUE_ID:
        print("[runner] TECHNIQUE_ID is required", file=sys.stderr)
        return 1

    # Start infrastructure
    _start_rsyslog()
    if not _start_sysmon():
        print("[runner] Sysmon failed to start — is the container --privileged?", file=sys.stderr)
        return 1

    # Baseline
    baseline = _log_size()

    # Fetch and run atomic
    try:
        tests = _fetch_art(TECHNIQUE_ID)
    except urllib.error.HTTPError as exc:
        print(f"[runner] ART YAML not found for {TECHNIQUE_ID}: HTTP {exc.code}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[runner] failed to fetch ART YAML: {exc}", file=sys.stderr)
        return 1

    atomic = _pick_atomic(tests, ATOMIC_NAME)
    if atomic is None:
        print(
            f"[runner] no Linux atomic found for {TECHNIQUE_ID} (guid={ATOMIC_NAME!r})",
            file=sys.stderr,
        )
        return 1

    try:
        _run_atomic(atomic)
    except subprocess.TimeoutExpired:
        print(f"[runner] atomic timed out for {TECHNIQUE_ID}", file=sys.stderr)

    # Collect new events
    events = _collect_events(baseline)
    for ev in events:
        print(json.dumps(ev), flush=True)

    print(f"[runner] {len(events)} event(s) captured for {TECHNIQUE_ID}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

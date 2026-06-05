"""LiveLocalSource: real telemetry via Atomic Red Team + Sysmon for Linux.

Architecture
============
A Docker container (docker/runner/) installs Sysmon for Linux and Atomic Red
Team, then runs one Linux atomic for the requested technique.  Sysmon for
Linux uses eBPF to intercept process, network, and file events — the SAME
field names as Windows Sysmon — so existing Sigma rules and the query_gen
ECS-Windows pipeline map directly with no translator.

The runner emits JSONL on stdout; LiveLocalSource.ensure() reads that output,
normalises it to TelemetryEvent (source_fidelity="live"), and indexes into
``telemetry-live-{technique}``.

Prerequisites (Linux / WSL2 only)
==================================
- Linux host with kernel ≥ 5.8 (BTF-backed eBPF)
- Docker with --privileged support
- Runner image: docker buildx build -t detection-validator-runner:latest docker/runner/

Mac users
=========
Docker Desktop's VM kernel does not expose eBPF to containers.  LiveLocalSource
detects this and raises NotAvailable with a clear pointer to ``--source replay``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Literal

from detection_validator.telemetry.base import (
    NotAvailable,
    SourceDescription,
    TelemetryBatch,
    TelemetrySource,
)

_RUNNER_IMAGE = "detection-validator-runner:latest"
_ART_RAW_BASE = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"
_RUNNER_TIMEOUT = 120  # seconds — generous for image pull + sysmon init + atomic


# ── Host capability probe ─────────────────────────────────────────────────────


def _probe_host() -> None:
    """Raise NotAvailable with a clear message if eBPF or Docker is unavailable."""
    if sys.platform == "darwin":
        raise NotAvailable(
            "live capture unavailable on this host (no eBPF)\n"
            "  Docker Desktop's VM kernel does not expose eBPF to containers.\n"
            "  Mac users: use  dv telemetry capture --source replay"
        )

    # Linux: eBPF BTF requires kernel ≥ 5.8
    try:
        r = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True, timeout=5
        )
        kver = r.stdout.strip()
        parts = kver.split(".")
        major = int(parts[0])
        minor = int(parts[1].split("-")[0]) if len(parts) > 1 else 0
        if major < 5 or (major == 5 and minor < 8):
            raise NotAvailable(
                f"live capture requires Linux kernel ≥5.8 (have {kver!r})\n"
                "  Upgrade the host kernel or use: dv telemetry capture --source replay"
            )
    except NotAvailable:
        raise
    except Exception:
        pass  # Cannot determine version; let Docker fail fast with a clear error

    # Docker must be available and the daemon must be running
    try:
        subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10, check=True,
        )
    except FileNotFoundError:
        raise NotAvailable(
            "live capture requires Docker — install Docker and retry\n"
            "  Or use: dv telemetry capture --source replay"
        )
    except subprocess.CalledProcessError:
        raise NotAvailable(
            "Docker daemon is not running — start Docker and retry\n"
            "  Or use: dv telemetry capture --source replay"
        )
    except subprocess.TimeoutExpired:
        raise NotAvailable(
            "Docker did not respond within 10 s — check Docker status\n"
            "  Or use: dv telemetry capture --source replay"
        )


# ── Atomic Red Team helpers ───────────────────────────────────────────────────


def _fetch_art_atomics(technique_id: str) -> list[dict]:
    """Download and parse the ART YAML for *technique_id*.

    Returns the list of atomic_tests dicts.
    Raises NotAvailable for 404 (no ART definition) or network failures.
    """
    try:
        import yaml
    except ImportError as exc:
        raise NotAvailable("pyyaml is required for live capture: pip install pyyaml") from exc

    url = f"{_ART_RAW_BASE}/{technique_id}/{technique_id}.yaml"
    req = urllib.request.Request(url, headers={"User-Agent": "detection-validator/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = yaml.safe_load(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotAvailable(
                f"No Atomic Red Team definition found for {technique_id}\n"
                "  Check the technique ID or use: dv telemetry capture --source replay"
            )
        raise NotAvailable(
            f"Failed to download ART atomics for {technique_id}: HTTP {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:
        raise NotAvailable(
            f"Cannot reach GitHub to fetch ART atomics: {exc}\n"
            "  Check network connectivity or use --source replay"
        ) from exc
    except Exception as exc:
        raise NotAvailable(
            f"Failed to parse ART YAML for {technique_id}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise NotAvailable(f"Unexpected ART YAML format for {technique_id}")

    return data.get("atomic_tests", [])


def _is_linux_atomic(atomic: dict) -> bool:
    platforms = [p.lower() for p in atomic.get("supported_platforms", [])]
    return "linux" in platforms


def _is_destructive(atomic: dict) -> bool:
    """Return True if the atomic requires elevation or modifies protected system state."""
    executor = atomic.get("executor", {})
    if executor.get("elevation_required", False):
        return True
    cmd = executor.get("command", "")
    _DANGEROUS = ("rm -rf /", "dd if=", "mkfs", "fdisk", "> /etc/", "chmod 000 /")
    return any(pat in cmd for pat in _DANGEROUS)


# ── Runner container ──────────────────────────────────────────────────────────


def _run_runner(
    technique_id: str,
    atomic: dict,
    runner_image: str = _RUNNER_IMAGE,
    timeout: int = _RUNNER_TIMEOUT,
) -> list[dict]:
    """Run the runner container; parse and return the JSONL events from stdout."""
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "-e", f"TECHNIQUE_ID={technique_id}",
        "-e", f"ATOMIC_NAME={atomic.get('auto_generated_guid', '')}",
        runner_image,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise NotAvailable(
            f"Runner container timed out after {timeout}s for {technique_id}\n"
            "  The atomic may hang — try a different test or use --source replay"
        ) from exc
    except FileNotFoundError:
        raise NotAvailable(
            "docker not found — install Docker to use live capture\n"
            "  Or use: dv telemetry capture --source replay"
        )

    events: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except json.JSONDecodeError:
            pass

    return events


# ── LiveLocalSource ───────────────────────────────────────────────────────────


class LiveLocalSource(TelemetrySource):
    """Run Atomic Red Team Linux atomics under Sysmon for Linux in a Docker container.

    Captures real kernel-level telemetry tagged ``source_fidelity="live"`` and
    indexed into ``dv-telemetry-live-{technique}`` so it does not collide with
    replay data.

    Quick start (Linux/WSL2 only)::

        # Build the runner image once
        docker buildx build -t detection-validator-runner:latest docker/runner/

        # Capture live telemetry
        dv telemetry capture --technique T1059.004 --source live-local

    Args:
        i_understand: Set True to allow atomics that require elevation or
            modify protected system paths.  Required for techniques like
            credential dumping (T1003.001) on Linux.
        runner_image: Docker image to run.  Defaults to the local build tag.
    """

    def __init__(
        self,
        i_understand: bool = False,
        runner_image: str = _RUNNER_IMAGE,
    ) -> None:
        self.i_understand = i_understand
        self.runner_image = runner_image

    def describe(self) -> SourceDescription:
        return SourceDescription(
            name="live-local",
            fidelity="live",
            supported_platforms=["linux"],
        )

    def ensure(self, technique_id: str, platform: str) -> TelemetryBatch:
        """Execute a Linux ART atomic and return the captured Sysmon events.

        Raises:
            NotAvailable: for any condition that prevents live capture, always
                with a specific human-readable reason and a pointer to
                ``--source replay`` where applicable.
        """
        # ── Platform guard ────────────────────────────────────────────────────
        if platform.lower() == "windows":
            raise NotAvailable(
                "live Windows capture needs a Windows host — use --source replay"
            )

        # ── Host capability: eBPF + Docker ────────────────────────────────────
        _probe_host()

        # ── Fetch ART definition ──────────────────────────────────────────────
        atomics = _fetch_art_atomics(technique_id)
        linux_atomics = [a for a in atomics if _is_linux_atomic(a)]

        if not linux_atomics:
            raise NotAvailable(
                f"No Linux atomic found for {technique_id} in Atomic Red Team\n"
                "  This technique may be Windows-only — use: dv telemetry capture --source replay"
            )

        atomic = linux_atomics[0]

        # ── Destructive gate ──────────────────────────────────────────────────
        if _is_destructive(atomic) and not self.i_understand:
            name = atomic.get("name", technique_id)
            raise NotAvailable(
                f"Atomic '{name}' requires elevation or modifies protected system state.\n"
                f"  Re-run with --i-understand to proceed.\n"
                f"  Or use: dv telemetry capture --source replay"
            )

        # ── Run container ─────────────────────────────────────────────────────
        raw_events = _run_runner(technique_id, atomic, self.runner_image)

        if not raw_events:
            raise NotAvailable(
                f"Runner produced no Sysmon events for {technique_id}\n"
                "  The atomic may not generate process/network/file events visible to Sysmon.\n"
                "  Try --i-understand for elevated variants, or use --source replay."
            )

        # ── Normalise ─────────────────────────────────────────────────────────
        from detection_validator.telemetry.normalizer import normalize_events

        events = normalize_events(raw_events, technique_id, fidelity="live")

        return TelemetryBatch(
            technique_id=technique_id,
            source_name="live-local",
            fidelity="live",
            events=events,
        )

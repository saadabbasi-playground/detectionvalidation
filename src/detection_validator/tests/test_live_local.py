"""Tests for LiveLocalSource — all offline, Docker and subprocess fully mocked."""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from detection_validator.telemetry.base import NotAvailable, SourceDescription
from detection_validator.telemetry.live_local import (
    LiveLocalSource,
    _fetch_art_atomics,
    _is_destructive,
    _is_linux_atomic,
    _probe_host,
    _run_runner,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_BASH_ATOMIC: dict = {
    "name": "Create a Bash script and execute it",
    "auto_generated_guid": "aaa-111",
    "supported_platforms": ["linux", "macos"],
    "executor": {
        "name": "sh",
        "elevation_required": False,
        "command": "echo hello > /tmp/art_test.txt",
        "cleanup_command": "rm -f /tmp/art_test.txt",
    },
    "input_arguments": {},
}

_DESTRUCTIVE_ATOMIC: dict = {
    "name": "Dump credentials",
    "auto_generated_guid": "bbb-222",
    "supported_platforms": ["linux"],
    "executor": {
        "name": "sh",
        "elevation_required": True,
        "command": "cat /etc/shadow",
    },
    "input_arguments": {},
}

_WINDOWS_ATOMIC: dict = {
    "name": "Windows-only",
    "auto_generated_guid": "ccc-333",
    "supported_platforms": ["windows"],
    "executor": {"name": "powershell", "command": "Get-Process"},
    "input_arguments": {},
}

_SAMPLE_ART_YAML: dict = {
    "attack_technique": "T1059.004",
    "display_name": "Unix Shell",
    "atomic_tests": [_BASH_ATOMIC],
}

_SAMPLE_EVENTS: list[dict] = [
    {
        "EventID": 1,
        "UtcTime": "2024-06-05T12:00:00.000Z",
        "Image": "/usr/bin/bash",
        "CommandLine": "bash -c echo hello",
        "ProcessId": 12345,
        "User": "runner",
    },
    {
        "EventID": 11,
        "UtcTime": "2024-06-05T12:00:00.100Z",
        "Image": "/usr/bin/bash",
        "TargetFilename": "/tmp/art_test.txt",
    },
]

_SAMPLE_JSONL = "\n".join(json.dumps(e) for e in _SAMPLE_EVENTS)


def _make_urlopen(data: bytes, code: int = 200):
    """Return a context-manager mock that yields an HTTP response-like object."""
    resp = MagicMock()
    resp.read.return_value = data
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    if code != 200:
        raise urllib.error.HTTPError(url="", code=code, msg="", hdrs=None, fp=None)
    return resp


# ── _is_linux_atomic / _is_destructive ───────────────────────────────────────


class TestAtomicHelpers:
    def test_is_linux_atomic_true(self):
        assert _is_linux_atomic(_BASH_ATOMIC)

    def test_is_linux_atomic_false_windows_only(self):
        assert not _is_linux_atomic(_WINDOWS_ATOMIC)

    def test_is_linux_atomic_mixed(self):
        a = {"supported_platforms": ["linux", "windows"]}
        assert _is_linux_atomic(a)

    def test_is_destructive_elevation(self):
        assert _is_destructive(_DESTRUCTIVE_ATOMIC)

    def test_is_destructive_safe(self):
        assert not _is_destructive(_BASH_ATOMIC)

    def test_is_destructive_rm_rf_root(self):
        a = {"executor": {"elevation_required": False, "command": "rm -rf /tmp && rm -rf /"}}
        assert _is_destructive(a)

    def test_is_destructive_mkfs(self):
        a = {"executor": {"command": "mkfs.ext4 /dev/sdb"}}
        assert _is_destructive(a)

    def test_is_destructive_missing_executor(self):
        assert not _is_destructive({})


# ── _probe_host ───────────────────────────────────────────────────────────────


class TestProbeHost:
    def test_macos_raises(self):
        with patch.object(sys, "platform", "darwin"):
            with pytest.raises(NotAvailable) as exc_info:
                _probe_host()
        assert "no eBPF" in exc_info.value.reason
        assert "replay" in exc_info.value.reason

    def test_linux_old_kernel_raises(self):
        uname_result = MagicMock()
        uname_result.stdout = "5.4.0-150-generic\n"
        uname_result.returncode = 0
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.run", return_value=uname_result) as mock_run:
                with pytest.raises(NotAvailable) as exc_info:
                    _probe_host()
        assert "5.4" in exc_info.value.reason
        assert "5.8" in exc_info.value.reason

    def test_linux_new_kernel_docker_missing(self):
        uname_result = MagicMock()
        uname_result.stdout = "6.1.0-21-amd64\n"
        uname_result.returncode = 0
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    uname_result,  # uname -r
                    FileNotFoundError,  # docker info
                ]
                with pytest.raises(NotAvailable) as exc_info:
                    _probe_host()
        assert "Docker" in exc_info.value.reason

    def test_linux_docker_not_running(self):
        uname_result = MagicMock(stdout="6.1.0-21-amd64\n")
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    uname_result,
                    subprocess.CalledProcessError(1, "docker"),
                ]
                with pytest.raises(NotAvailable) as exc_info:
                    _probe_host()
        assert "not running" in exc_info.value.reason

    def test_linux_docker_timeout(self):
        uname_result = MagicMock(stdout="6.1.0-21-amd64\n")
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    uname_result,
                    subprocess.TimeoutExpired(cmd="docker", timeout=10),
                ]
                with pytest.raises(NotAvailable) as exc_info:
                    _probe_host()
        assert "10 s" in exc_info.value.reason

    def test_linux_ready(self):
        uname_result = MagicMock(stdout="6.1.0-21-amd64\n")
        docker_result = MagicMock(returncode=0)
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.run", side_effect=[uname_result, docker_result]):
                _probe_host()  # must not raise

    def test_linux_kernel_major_5_minor_8_ok(self):
        uname_result = MagicMock(stdout="5.8.0-63-generic\n")
        docker_result = MagicMock(returncode=0)
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.run", side_effect=[uname_result, docker_result]):
                _probe_host()

    def test_linux_kernel_major_5_minor_7_fails(self):
        uname_result = MagicMock(stdout="5.7.19-generic\n")
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.run", return_value=uname_result):
                with pytest.raises(NotAvailable) as exc_info:
                    _probe_host()
        assert "5.8" in exc_info.value.reason


# ── _fetch_art_atomics ────────────────────────────────────────────────────────


class TestFetchArtAtomics:
    def _mock_urlopen(self, data: dict | bytes):
        import yaml as _yaml

        if isinstance(data, dict):
            raw = _yaml.dump(data).encode()
        else:
            raw = data

        resp = MagicMock()
        resp.read.return_value = raw
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_success(self):
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(_SAMPLE_ART_YAML)):
            tests = _fetch_art_atomics("T1059.004")
        assert len(tests) == 1
        assert tests[0]["name"] == _BASH_ATOMIC["name"]

    def test_404_raises_not_available(self):
        exc = urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=exc):
            with pytest.raises(NotAvailable) as exc_info:
                _fetch_art_atomics("T9999.999")
        assert "T9999.999" in exc_info.value.reason
        assert "replay" in exc_info.value.reason

    def test_http_error_non_404(self):
        exc = urllib.error.HTTPError(url="", code=500, msg="Server Error", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=exc):
            with pytest.raises(NotAvailable) as exc_info:
                _fetch_art_atomics("T1059.004")
        assert "HTTP 500" in exc_info.value.reason

    def test_network_error(self):
        exc = urllib.error.URLError("connection refused")
        with patch("urllib.request.urlopen", side_effect=exc):
            with pytest.raises(NotAvailable) as exc_info:
                _fetch_art_atomics("T1059.004")
        assert "GitHub" in exc_info.value.reason

    def test_empty_atomic_tests(self):
        data = {"attack_technique": "T1059.004", "atomic_tests": []}
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(data)):
            tests = _fetch_art_atomics("T1059.004")
        assert tests == []

    def test_bad_yaml_raises_not_available(self):
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(b"!!invalid: [yaml")):
            with pytest.raises(NotAvailable) as exc_info:
                _fetch_art_atomics("T1059.004")
        assert "parse" in exc_info.value.reason.lower()


# ── _run_runner ───────────────────────────────────────────────────────────────


class TestRunRunner:
    def test_success_parses_jsonl(self):
        result = MagicMock()
        result.stdout = _SAMPLE_JSONL
        result.returncode = 0
        with patch("subprocess.run", return_value=result):
            events = _run_runner("T1059.004", _BASH_ATOMIC, "test-image:latest")
        assert len(events) == 2
        assert events[0]["Image"] == "/usr/bin/bash"

    def test_skips_non_json_lines(self):
        result = MagicMock()
        result.stdout = '[runner] info line\n{"EventID": 1}\nnot json\n{"EventID": 5}'
        with patch("subprocess.run", return_value=result):
            events = _run_runner("T1059.004", _BASH_ATOMIC)
        assert len(events) == 2

    def test_empty_stdout(self):
        result = MagicMock()
        result.stdout = ""
        with patch("subprocess.run", return_value=result):
            events = _run_runner("T1059.004", _BASH_ATOMIC)
        assert events == []

    def test_timeout_raises_not_available(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=120),
        ):
            with pytest.raises(NotAvailable) as exc_info:
                _run_runner("T1059.004", _BASH_ATOMIC)
        assert "120s" in exc_info.value.reason
        assert "replay" in exc_info.value.reason

    def test_docker_not_found_raises_not_available(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(NotAvailable) as exc_info:
                _run_runner("T1059.004", _BASH_ATOMIC)
        assert "docker" in exc_info.value.reason.lower()

    def test_passes_correct_docker_args(self):
        result = MagicMock(stdout="", returncode=0)
        with patch("subprocess.run", return_value=result) as mock_run:
            _run_runner("T1059.004", _BASH_ATOMIC, "myimage:v1")
        cmd = mock_run.call_args[0][0]
        assert "--privileged" in cmd
        assert "TECHNIQUE_ID=T1059.004" in " ".join(cmd)
        assert "myimage:v1" in cmd


# ── LiveLocalSource ───────────────────────────────────────────────────────────


class TestLiveLocalSourceDescribe:
    def test_describe_name(self):
        assert LiveLocalSource().describe().name == "live-local"

    def test_describe_fidelity(self):
        assert LiveLocalSource().describe().fidelity == "live"

    def test_describe_platforms(self):
        assert "linux" in LiveLocalSource().describe().supported_platforms

    def test_default_not_destructive(self):
        src = LiveLocalSource()
        assert src.i_understand is False

    def test_i_understand_flag(self):
        src = LiveLocalSource(i_understand=True)
        assert src.i_understand is True


class TestLiveLocalSourceEnsure:
    """All tests patch _probe_host, _fetch_art_atomics, and _run_runner so no
    real Docker or network calls are made."""

    def _make_source(self, i_understand: bool = False) -> LiveLocalSource:
        return LiveLocalSource(i_understand=i_understand, runner_image="test:latest")

    def test_windows_platform_raises(self):
        src = self._make_source()
        with pytest.raises(NotAvailable) as exc_info:
            src.ensure("T1059.004", "windows")
        assert "Windows" in exc_info.value.reason
        assert "replay" in exc_info.value.reason

    def test_macos_no_ebpf(self):
        src = self._make_source()
        with patch(
            "detection_validator.telemetry.live_local._probe_host",
            side_effect=NotAvailable("live capture unavailable on this host (no eBPF)\n  Mac users: use  dv telemetry capture --source replay"),
        ):
            with pytest.raises(NotAvailable) as exc_info:
                src.ensure("T1059.004", "linux")
        assert "no eBPF" in exc_info.value.reason

    def test_no_linux_atomics(self):
        src = self._make_source()
        with patch("detection_validator.telemetry.live_local._probe_host"):
            with patch(
                "detection_validator.telemetry.live_local._fetch_art_atomics",
                return_value=[_WINDOWS_ATOMIC],
            ):
                with pytest.raises(NotAvailable) as exc_info:
                    src.ensure("T1003.001", "linux")
        assert "No Linux atomic" in exc_info.value.reason
        assert "replay" in exc_info.value.reason

    def test_destructive_without_flag(self):
        src = self._make_source(i_understand=False)
        with patch("detection_validator.telemetry.live_local._probe_host"):
            with patch(
                "detection_validator.telemetry.live_local._fetch_art_atomics",
                return_value=[_DESTRUCTIVE_ATOMIC],
            ):
                with pytest.raises(NotAvailable) as exc_info:
                    src.ensure("T1003.001", "linux")
        assert "destructive" in exc_info.value.reason.lower() or "elevation" in exc_info.value.reason.lower()
        assert "--i-understand" in exc_info.value.reason

    def test_destructive_with_flag_proceeds(self):
        src = self._make_source(i_understand=True)
        with patch("detection_validator.telemetry.live_local._probe_host"):
            with patch(
                "detection_validator.telemetry.live_local._fetch_art_atomics",
                return_value=[_DESTRUCTIVE_ATOMIC],
            ):
                with patch(
                    "detection_validator.telemetry.live_local._run_runner",
                    return_value=_SAMPLE_EVENTS,
                ):
                    batch = src.ensure("T1003.001", "linux")
        assert len(batch) == 2
        assert batch.fidelity == "live"

    def test_successful_capture(self):
        src = self._make_source()
        with patch("detection_validator.telemetry.live_local._probe_host"):
            with patch(
                "detection_validator.telemetry.live_local._fetch_art_atomics",
                return_value=[_BASH_ATOMIC],
            ):
                with patch(
                    "detection_validator.telemetry.live_local._run_runner",
                    return_value=_SAMPLE_EVENTS,
                ):
                    batch = src.ensure("T1059.004", "linux")

        assert batch.technique_id == "T1059.004"
        assert batch.source_name == "live-local"
        assert batch.fidelity == "live"
        assert len(batch) == 2
        assert batch.events[0].source_fidelity == "live"
        assert batch.events[0].Image == "/usr/bin/bash"

    def test_empty_events_raises(self):
        src = self._make_source()
        with patch("detection_validator.telemetry.live_local._probe_host"):
            with patch(
                "detection_validator.telemetry.live_local._fetch_art_atomics",
                return_value=[_BASH_ATOMIC],
            ):
                with patch(
                    "detection_validator.telemetry.live_local._run_runner",
                    return_value=[],
                ):
                    with pytest.raises(NotAvailable) as exc_info:
                        src.ensure("T1059.004", "linux")
        assert "no Sysmon events" in exc_info.value.reason.lower() or "no" in exc_info.value.reason.lower()

    def test_art_fetch_failure_propagates(self):
        src = self._make_source()
        with patch("detection_validator.telemetry.live_local._probe_host"):
            with patch(
                "detection_validator.telemetry.live_local._fetch_art_atomics",
                side_effect=NotAvailable("No ART definition"),
            ):
                with pytest.raises(NotAvailable) as exc_info:
                    src.ensure("T9999.999", "linux")
        assert "No ART definition" in exc_info.value.reason

    def test_runner_timeout_propagates(self):
        src = self._make_source()
        with patch("detection_validator.telemetry.live_local._probe_host"):
            with patch(
                "detection_validator.telemetry.live_local._fetch_art_atomics",
                return_value=[_BASH_ATOMIC],
            ):
                with patch(
                    "detection_validator.telemetry.live_local._run_runner",
                    side_effect=NotAvailable("Runner timed out after 120s"),
                ):
                    with pytest.raises(NotAvailable) as exc_info:
                        src.ensure("T1059.004", "linux")
        assert "120s" in exc_info.value.reason


# ── Normalizer fidelity integration ──────────────────────────────────────────


class TestNormalizerFidelity:
    """Ensure fidelity param is threaded through normalizer correctly."""

    def test_live_fidelity_preserved(self):
        from detection_validator.telemetry.normalizer import normalize_events

        raw = [{"EventID": 1, "Image": "/usr/bin/bash"}]
        events = normalize_events(raw, "T1059.004", fidelity="live")
        assert events[0].source_fidelity == "live"

    def test_replay_fidelity_default(self):
        from detection_validator.telemetry.normalizer import normalize_events

        raw = [{"EventID": 1, "Image": "/usr/bin/bash"}]
        events = normalize_events(raw, "T1059.004")
        assert events[0].source_fidelity == "replay"


# ── Indexer fidelity integration ──────────────────────────────────────────────


class TestIndexerFidelity:
    def test_replay_index_name(self):
        from detection_validator.telemetry.indexer import index_name_for

        assert index_name_for("T1059.004") == "dv-telemetry-replay-t1059-004"
        assert index_name_for("T1059.004", "replay") == "dv-telemetry-replay-t1059-004"

    def test_live_index_name(self):
        from detection_validator.telemetry.indexer import index_name_for

        assert index_name_for("T1059.004", "live") == "dv-telemetry-live-t1059-004"

    def test_dots_replaced(self):
        from detection_validator.telemetry.indexer import index_name_for

        assert index_name_for("T1003.001", "live") == "dv-telemetry-live-t1003-001"


# ── Registry integration ──────────────────────────────────────────────────────


class TestRegistry:
    def test_live_local_registered(self):
        from detection_validator.telemetry.base import registry

        assert "live-local" in registry.list_sources()

    def test_registry_returns_live_local_source(self):
        from detection_validator.telemetry.base import registry

        src = registry.get("live-local")
        assert isinstance(src, LiveLocalSource)

    def test_registry_live_local_describe(self):
        from detection_validator.telemetry.base import registry

        desc = registry.get("live-local").describe()
        assert desc.name == "live-local"
        assert desc.fidelity == "live"

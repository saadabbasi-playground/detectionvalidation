"""Tests for the full ReplaySource implementation.

All network I/O and OpenSearch calls are mocked — these tests run fully offline.
The fixture dataset mimics real OTRF Security-Datasets T1003.001 (LSASS) events.
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from detection_validator.telemetry.base import NotAvailable, TelemetryBatch, TelemetryEvent
from detection_validator.telemetry.indexer import _event_to_doc, _parse_url, index_name_for
from detection_validator.telemetry.normalizer import (
    _flatten,
    _parse_ts,
    _to_int,
    normalize_events,
    normalize_otrf_event,
)
from detection_validator.telemetry.replay import (
    ReplaySource,
    _OTRFCatalog,
    _parse_raw_bytes,
    _technique_variants,
)


# ── Fixture dataset (T1003.001 — LSASS Memory) ────────────────────────────────

_T1003_EVENTS: list[dict] = [
    {
        "Hostname": "WORKSTATION01",
        "TimeCreated": "2021-09-12 14:23:01.123",
        "EventID": 10,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell -c \"Invoke-Mimikatz -DumpCreds\"",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": "cmd.exe /c powershell ...",
        "ProcessId": "0x9f4",
        "User": "WORKSTATION01\\Administrator",
        "GrantedAccess": "0x1010",
        "TargetImage": r"C:\Windows\system32\lsass.exe",
    },
    {
        "Hostname": "WORKSTATION01",
        "TimeCreated": "2021-09-12 14:23:02.456",
        "EventID": 4688,
        "Channel": "Security",
        "NewProcessName": r"C:\Windows\System32\procdump.exe",
        "NewProcessCommandLine": "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
        "ParentProcessName": r"C:\Windows\System32\cmd.exe",
        "SubjectUserName": "DOMAIN\\user",
        "NewProcessId": "0x1234",
    },
    {
        "Hostname": "WORKSTATION01",
        "TimeCreated": "2021-09-12T14:23:03.789Z",
        "EventID": 10,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": r"C:\Windows\System32\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\temp\\inject.dll,Main",
        "ParentImage": r"C:\Windows\System32\svchost.exe",
        "ProcessId": 5678,
        "User": "NT AUTHORITY\\SYSTEM",
    },
    # Nested WEL format
    {
        "System": {
            "EventID": 4656,
            "TimeCreated": {"SystemTime": "2021-09-12T14:23:04.000Z"},
            "Computer": "WORKSTATION01",
            "Channel": "Security",
        },
        "EventData": {
            "ObjectName": r"C:\Windows\system32\lsass.exe",
            "SubjectUserName": "Administrator",
            "AccessMask": "0x1010",
        },
    },
    # Minimal event — only required fields
    {
        "EventID": 4663,
        "Hostname": "WORKSTATION02",
        "TimeCreated": "2021-09-12 14:24:00.000",
    },
]

_TECHNIQUE = "T1003.001"
_PLATFORM = "windows"


# ── normalizer tests ──────────────────────────────────────────────────────────

class TestFlatten:
    def test_flat_dict_unchanged(self):
        raw = {"EventID": 10, "Image": "foo.exe"}
        assert _flatten(raw) == raw

    def test_system_sub_dict_flattened(self):
        raw = {"System": {"EventID": 10, "Computer": "HOST"}, "Channel": "Sysmon"}
        flat = _flatten(raw)
        assert flat["EventID"] == 10
        assert flat["Computer"] == "HOST"
        assert flat["Channel"] == "Sysmon"

    def test_eventdata_sub_dict_flattened(self):
        raw = {"EventData": {"CommandLine": "cmd.exe", "Image": "foo.exe"}, "EventID": 1}
        flat = _flatten(raw)
        assert flat["CommandLine"] == "cmd.exe"
        assert flat["Image"] == "foo.exe"

    def test_top_level_wins_over_system(self):
        raw = {"EventID": 99, "System": {"EventID": 1}}
        flat = _flatten(raw)
        assert flat["EventID"] == 99


class TestParseTs:
    def test_iso_string(self):
        ts = _parse_ts("2021-09-12T14:23:01.123Z")
        assert ts.year == 2021
        assert ts.month == 9
        assert ts.tzinfo is not None

    def test_space_separated(self):
        ts = _parse_ts("2021-09-12 14:23:01.123")
        assert ts.year == 2021

    def test_nested_dict(self):
        ts = _parse_ts({"SystemTime": "2021-09-12T14:23:04.000Z"})
        assert ts.year == 2021

    def test_unix_float(self):
        ts = _parse_ts(1631456581.0)
        assert isinstance(ts, datetime)
        assert ts.tzinfo is not None

    def test_invalid_returns_now(self):
        ts = _parse_ts("not-a-date")
        assert isinstance(ts, datetime)

    def test_aware_datetime_passthrough(self):
        dt = datetime(2021, 9, 12, tzinfo=timezone.utc)
        assert _parse_ts(dt) is dt


class TestToInt:
    def test_plain_int(self):
        assert _to_int(1234) == 1234

    def test_hex_string(self):
        assert _to_int("0x9f4") == 2548

    def test_decimal_string(self):
        assert _to_int("5678") == 5678

    def test_none(self):
        assert _to_int(None) is None

    def test_invalid_string(self):
        assert _to_int("notanint") is None


class TestNormalizeOtRFEvent:
    def test_flat_sysmon_event(self):
        ev = normalize_otrf_event(_T1003_EVENTS[0], _TECHNIQUE)
        assert ev.technique_id == _TECHNIQUE
        assert ev.source_fidelity == "replay"
        assert ev.EventID == 10
        assert ev.Channel == "Microsoft-Windows-Sysmon/Operational"
        assert ev.Computer == "WORKSTATION01"
        assert "powershell" in ev.CommandLine.lower()
        assert "powershell" in ev.Image.lower()
        assert ev.User == "WORKSTATION01\\Administrator"

    def test_hex_pid_parsed(self):
        ev = normalize_otrf_event(_T1003_EVENTS[0], _TECHNIQUE)
        assert ev.ProcessId == 0x9F4  # 2548

    def test_wel_process_creation(self):
        ev = normalize_otrf_event(_T1003_EVENTS[1], _TECHNIQUE)
        assert "procdump" in ev.Image.lower()
        assert "lsass" in ev.CommandLine.lower()
        assert ev.User == "DOMAIN\\user"

    def test_iso_z_timestamp(self):
        ev = normalize_otrf_event(_T1003_EVENTS[2], _TECHNIQUE)
        assert ev.timestamp.tzinfo is not None
        assert ev.timestamp.year == 2021

    def test_nested_wel_format(self):
        ev = normalize_otrf_event(_T1003_EVENTS[3], _TECHNIQUE)
        assert ev.EventID == 4656
        assert ev.Computer == "WORKSTATION01"
        assert ev.User == "Administrator"

    def test_extra_fields_preserved(self):
        ev = normalize_otrf_event(_T1003_EVENTS[0], _TECHNIQUE)
        assert "GrantedAccess" in ev.extra
        assert "TargetImage" in ev.extra

    def test_minimal_event(self):
        ev = normalize_otrf_event(_T1003_EVENTS[4], _TECHNIQUE)
        assert ev.EventID == 4663
        assert ev.Computer == "WORKSTATION02"
        assert ev.Image is None
        assert ev.CommandLine is None


class TestNormalizeEvents:
    def test_returns_list_of_events(self):
        events = normalize_events(_T1003_EVENTS, _TECHNIQUE)
        assert len(events) == 5
        assert all(isinstance(e, TelemetryEvent) for e in events)

    def test_skips_non_dicts(self):
        mixed = [*_T1003_EVENTS, "not-a-dict", 42, None]
        events = normalize_events(mixed, _TECHNIQUE)  # type: ignore[arg-type]
        assert len(events) == 5

    def test_all_tagged_with_technique(self):
        events = normalize_events(_T1003_EVENTS, _TECHNIQUE)
        assert all(e.technique_id == _TECHNIQUE for e in events)

    def test_all_tagged_replay(self):
        events = normalize_events(_T1003_EVENTS, _TECHNIQUE)
        assert all(e.source_fidelity == "replay" for e in events)


# ── replay.py helpers ─────────────────────────────────────────────────────────

class TestTechniqueVariants:
    def test_t1003_001(self):
        variants = _technique_variants("T1003.001")
        assert "t1003.001" in variants
        assert "t1003_001" in variants
        assert "t1003-001" in variants
        assert "t1003001" in variants

    def test_t1059(self):
        variants = _technique_variants("T1059")
        assert "t1059" in variants


class TestParseRawBytes:
    def test_json_array(self):
        data = json.dumps(_T1003_EVENTS).encode()
        parsed = _parse_raw_bytes(data, "test.json")
        assert len(parsed) == 5

    def test_jsonl(self):
        lines = "\n".join(json.dumps(e) for e in _T1003_EVENTS)
        parsed = _parse_raw_bytes(lines.encode(), "test.jsonl")
        assert len(parsed) == 5

    def test_single_object_wrapped(self):
        data = json.dumps({"events": _T1003_EVENTS}).encode()
        parsed = _parse_raw_bytes(data, "test.json")
        assert len(parsed) == 5

    def test_zip_with_json(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("events.json", json.dumps(_T1003_EVENTS))
        parsed = _parse_raw_bytes(buf.getvalue(), "test.zip")
        assert len(parsed) == 5

    def test_empty_bytes(self):
        parsed = _parse_raw_bytes(b"", "test.json")
        assert parsed == []

    def test_garbage_bytes(self):
        parsed = _parse_raw_bytes(b"not json at all !!!", "test.json")
        assert parsed == []


# ── _OTRFCatalog ──────────────────────────────────────────────────────────────

class TestOTRFCatalog:
    def test_find_filters_by_technique(self, tmp_path):
        catalog = _OTRFCatalog(tmp_path)
        fake_entries = [
            {"path": "datasets/atomic/windows/credential-access/T1003.001/lsass.json"},
            {"path": "datasets/atomic/windows/execution/T1059.001/powershell.json"},
            {"path": "datasets/atomic/linux/execution/T1059.004/bash.json"},
        ]
        catalog._catalog_path.write_text(json.dumps(fake_entries))
        matches = catalog.find("T1003.001", "windows")
        assert len(matches) == 1
        assert "T1003.001" in matches[0]["path"]

    def test_find_filters_by_platform(self, tmp_path):
        catalog = _OTRFCatalog(tmp_path)
        fake_entries = [
            {"path": "datasets/atomic/windows/credential-access/T1003.001/lsass.json"},
            {"path": "datasets/atomic/linux/credential-access/T1003.001/linux-lsass.json"},
        ]
        catalog._catalog_path.write_text(json.dumps(fake_entries))
        matches = catalog.find("T1003.001", "windows")
        assert all("windows" in m["path"] for m in matches)

    def test_find_skips_yaml_files(self, tmp_path):
        catalog = _OTRFCatalog(tmp_path)
        fake_entries = [
            {"path": "datasets/atomic/windows/credential-access/T1003.001/metadata.yaml"},
            {"path": "datasets/atomic/windows/credential-access/T1003.001/lsass.json"},
        ]
        catalog._catalog_path.write_text(json.dumps(fake_entries))
        matches = catalog.find("T1003.001", "windows")
        assert all(m["path"].endswith(".json") for m in matches)

    def test_uses_cache_when_fresh(self, tmp_path):
        catalog = _OTRFCatalog(tmp_path)
        fake_entries = [{"path": "datasets/atomic/windows/T1003.001/test.json"}]
        catalog._catalog_path.write_text(json.dumps(fake_entries))
        # Should not call _fetch at all
        with patch.object(catalog, "_fetch") as mock_fetch:
            entries = catalog.entries()
        mock_fetch.assert_not_called()
        assert entries == fake_entries

    def test_refreshes_stale_cache(self, tmp_path):
        catalog = _OTRFCatalog(tmp_path)
        fake_entries = [{"path": "datasets/atomic/windows/T1003.001/test.json"}]
        catalog._catalog_path.write_text(json.dumps(fake_entries))
        # Make it look old
        import os
        old_time = 0  # epoch — always stale
        os.utime(catalog._catalog_path, (old_time, old_time))

        new_entries = [{"path": "datasets/atomic/windows/T1003.001/new.json"}]
        with patch.object(catalog, "_fetch", return_value=new_entries):
            entries = catalog.entries()
        assert entries == new_entries


# ── ReplaySource full integration (mocked network) ────────────────────────────

class TestReplaySourceFromFile:
    def test_loads_json_array(self, tmp_path):
        f = tmp_path / "events.json"
        f.write_text(json.dumps(_T1003_EVENTS))
        src = ReplaySource(file_path=f)
        batch = src.ensure(_TECHNIQUE, _PLATFORM)
        assert isinstance(batch, TelemetryBatch)
        assert len(batch) == 5

    def test_loads_jsonl(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text("\n".join(json.dumps(e) for e in _T1003_EVENTS))
        src = ReplaySource(file_path=f)
        batch = src.ensure(_TECHNIQUE, _PLATFORM)
        assert len(batch) == 5

    def test_batch_metadata(self, tmp_path):
        f = tmp_path / "test_events.json"
        f.write_text(json.dumps(_T1003_EVENTS))
        src = ReplaySource(file_path=f)
        batch = src.ensure(_TECHNIQUE, _PLATFORM)
        assert batch.technique_id == _TECHNIQUE
        assert batch.fidelity == "replay"
        assert "test_events.json" in batch.source_name

    def test_missing_file_raises(self, tmp_path):
        src = ReplaySource(file_path=tmp_path / "nonexistent.json")
        with pytest.raises(NotAvailable) as exc_info:
            src.ensure(_TECHNIQUE, _PLATFORM)
        assert "not found" in exc_info.value.reason.lower()

    def test_empty_file_raises(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("[]")
        src = ReplaySource(file_path=f)
        with pytest.raises(NotAvailable) as exc_info:
            src.ensure(_TECHNIQUE, _PLATFORM)
        assert _TECHNIQUE in exc_info.value.reason or "no events" in exc_info.value.reason.lower()


class TestReplaySourceFromOTRF:
    def _make_catalog(self, tmp_path: Path, entries: list[dict]) -> _OTRFCatalog:
        cat = _OTRFCatalog(tmp_path)
        cat._catalog_path.write_text(json.dumps(entries))
        return cat

    def test_no_catalog_match_raises(self, tmp_path):
        cat = self._make_catalog(tmp_path, [
            {"path": "datasets/atomic/windows/T1059.001/powershell.json"},
        ])
        src = ReplaySource(cache_dir=tmp_path, catalog=cat)
        with pytest.raises(NotAvailable) as exc_info:
            src.ensure("T1003.001", "windows")
        assert "T1003.001" in exc_info.value.reason

    def test_downloads_and_normalises(self, tmp_path):
        entry_path = "datasets/atomic/windows/credential-access/T1003.001/lsass.json"
        cat = self._make_catalog(tmp_path, [{"path": entry_path}])

        raw_data = json.dumps(_T1003_EVENTS).encode()
        with patch("detection_validator.telemetry.replay._download_raw", return_value=raw_data):
            src = ReplaySource(cache_dir=tmp_path, catalog=cat)
            batch = src.ensure("T1003.001", "windows")

        assert len(batch) == 5
        assert batch.technique_id == "T1003.001"

    def test_uses_local_cache_on_second_call(self, tmp_path):
        entry_path = "datasets/atomic/windows/credential-access/T1003.001/lsass.json"
        cat = self._make_catalog(tmp_path, [{"path": entry_path}])

        # Pre-populate the local cache
        cache_file = tmp_path / "T1003.001" / "lsass.json"
        cache_file.parent.mkdir(parents=True)
        cache_file.write_bytes(json.dumps(_T1003_EVENTS).encode())

        with patch("detection_validator.telemetry.replay._download_raw") as mock_dl:
            src = ReplaySource(cache_dir=tmp_path, catalog=cat)
            batch = src.ensure("T1003.001", "windows")
        # Should NOT have called download
        mock_dl.assert_not_called()
        assert len(batch) == 5

    def test_platform_mismatch_raises(self, tmp_path):
        entry_path = "datasets/atomic/linux/credential-access/T1003.001/linux.json"
        cat = self._make_catalog(tmp_path, [{"path": entry_path}])
        src = ReplaySource(cache_dir=tmp_path, catalog=cat)
        with pytest.raises(NotAvailable):
            src.ensure("T1003.001", "windows")  # catalog has linux only

    def test_describe_fidelity(self):
        src = ReplaySource()
        desc = src.describe()
        assert desc.fidelity == "replay"
        assert "windows" in desc.supported_platforms

    def test_batch_events_are_telemetry_events(self, tmp_path):
        entry_path = "datasets/atomic/windows/credential-access/T1003.001/lsass.json"
        cat = self._make_catalog(tmp_path, [{"path": entry_path}])
        raw_data = json.dumps(_T1003_EVENTS).encode()
        with patch("detection_validator.telemetry.replay._download_raw", return_value=raw_data):
            src = ReplaySource(cache_dir=tmp_path, catalog=cat)
            batch = src.ensure("T1003.001", "windows")
        assert all(isinstance(e, TelemetryEvent) for e in batch)
        assert all(e.source_fidelity == "replay" for e in batch)


# ── indexer helpers ───────────────────────────────────────────────────────────

class TestIndexNameFor:
    def test_t1003_001(self):
        assert index_name_for("T1003.001") == "dv-telemetry-replay-t1003-001"

    def test_t1059(self):
        assert index_name_for("T1059") == "dv-telemetry-replay-t1059"


class TestParseUrl:
    def test_full_url(self):
        host, port = _parse_url("http://localhost:9200")
        assert host == "localhost"
        assert port == 9200

    def test_no_scheme(self):
        host, port = _parse_url("myhost:9201")
        assert host == "myhost"
        assert port == 9201

    def test_default_port(self):
        host, port = _parse_url("http://opensearch.local")
        assert port == 9200


class TestEventToDoc:
    def test_fields_present(self):
        ev = normalize_otrf_event(_T1003_EVENTS[0], _TECHNIQUE)
        doc = _event_to_doc(ev)
        assert doc["technique_id"] == _TECHNIQUE
        assert doc["source_fidelity"] == "replay"
        assert "@timestamp" in doc
        assert "Image" in doc
        assert "CommandLine" in doc

    def test_none_values_dropped(self):
        ev = normalize_otrf_event(_T1003_EVENTS[4], _TECHNIQUE)  # minimal event
        doc = _event_to_doc(ev)
        assert "Image" not in doc
        assert "CommandLine" not in doc

    def test_extra_fields_merged(self):
        ev = normalize_otrf_event(_T1003_EVENTS[0], _TECHNIQUE)
        doc = _event_to_doc(ev)
        assert "GrantedAccess" in doc
        assert "TargetImage" in doc


# ── CLI smoke tests ───────────────────────────────────────────────────────────

class TestCLITelemetryCapture:
    def test_capture_no_index_from_file(self, tmp_path):
        from click.testing import CliRunner
        from detection_validator.cli import main

        events_file = tmp_path / "events.json"
        events_file.write_text(json.dumps(_T1003_EVENTS))

        runner = CliRunner()
        result = runner.invoke(main, [
            "telemetry", "capture",
            "--technique", _TECHNIQUE,
            "--file", str(events_file),
            "--no-index",
        ])
        assert result.exit_code == 0, result.output
        assert "T1003.001" in result.output
        assert "5" in result.output  # event count

    def test_capture_unknown_source_exits_1(self, tmp_path):
        from click.testing import CliRunner
        from detection_validator.cli import main

        runner = CliRunner()
        result = runner.invoke(main, [
            "telemetry", "capture",
            "--technique", _TECHNIQUE,
            "--source", "nonexistent-source",
        ])
        assert result.exit_code == 1

    def test_sources_command(self):
        from click.testing import CliRunner
        from detection_validator.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["telemetry", "sources"])
        assert result.exit_code == 0
        assert "replay" in result.output
        assert "live-local" in result.output

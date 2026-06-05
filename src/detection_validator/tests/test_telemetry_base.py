"""Tests for telemetry/base.py — TelemetrySource interface and registry."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from detection_validator.telemetry.base import (
    LiveLocalSource,
    NotAvailable,
    ReplaySource,
    SourceDescription,
    SourceRegistry,
    TelemetryBatch,
    TelemetryEvent,
    TelemetrySource,
    registry,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _event(technique_id: str = "T1059", fidelity: str = "replay") -> TelemetryEvent:
    return TelemetryEvent(
        technique_id=technique_id,
        source_fidelity=fidelity,
        timestamp=_now(),
    )


# ── NotAvailable ──────────────────────────────────────────────────────────────

class TestNotAvailable:
    def test_is_exception(self):
        exc = NotAvailable("no replay file")
        assert isinstance(exc, Exception)

    def test_reason_stored(self):
        exc = NotAvailable("agent not running")
        assert exc.reason == "agent not running"

    def test_str_is_reason(self):
        exc = NotAvailable("missing platform")
        assert str(exc) == "missing platform"

    def test_raise_and_catch(self):
        with pytest.raises(NotAvailable) as exc_info:
            raise NotAvailable("test reason")
        assert exc_info.value.reason == "test reason"

    def test_catch_as_exception(self):
        with pytest.raises(Exception):
            raise NotAvailable("still an Exception")


# ── TelemetryEvent ────────────────────────────────────────────────────────────

class TestTelemetryEvent:
    def test_required_fields(self):
        ts = _now()
        ev = TelemetryEvent(
            technique_id="T1059.001",
            source_fidelity="replay",
            timestamp=ts,
        )
        assert ev.technique_id == "T1059.001"
        assert ev.source_fidelity == "replay"
        assert ev.timestamp is ts

    def test_optional_sysmon_fields_default_none(self):
        ev = _event()
        assert ev.Image is None
        assert ev.CommandLine is None
        assert ev.ParentImage is None
        assert ev.ParentCommandLine is None
        assert ev.ProcessId is None
        assert ev.User is None

    def test_optional_windows_log_fields_default_none(self):
        ev = _event()
        assert ev.EventID is None
        assert ev.Channel is None
        assert ev.Computer is None

    def test_extra_defaults_empty_dict(self):
        ev = _event()
        assert ev.extra == {}

    def test_extra_dicts_are_independent(self):
        ev1 = _event()
        ev2 = _event()
        ev1.extra["key"] = "value"
        assert "key" not in ev2.extra

    def test_sysmon_fields_set(self):
        ev = TelemetryEvent(
            technique_id="T1059",
            source_fidelity="live",
            timestamp=_now(),
            Image=r"C:\Windows\System32\cmd.exe",
            CommandLine="cmd.exe /c whoami",
            ParentImage=r"C:\Windows\explorer.exe",
            ParentCommandLine="explorer.exe",
            ProcessId=1234,
            User="DOMAIN\\user",
        )
        assert ev.Image == r"C:\Windows\System32\cmd.exe"
        assert ev.CommandLine == "cmd.exe /c whoami"
        assert ev.ProcessId == 1234
        assert ev.User == "DOMAIN\\user"

    def test_windows_log_fields_set(self):
        ev = TelemetryEvent(
            technique_id="T1059",
            source_fidelity="replay",
            timestamp=_now(),
            EventID=4688,
            Channel="Security",
            Computer="WINHOST01",
        )
        assert ev.EventID == 4688
        assert ev.Channel == "Security"
        assert ev.Computer == "WINHOST01"

    def test_fidelity_replay(self):
        ev = TelemetryEvent(
            technique_id="T1059",
            source_fidelity="replay",
            timestamp=_now(),
        )
        assert ev.source_fidelity == "replay"

    def test_fidelity_live(self):
        ev = TelemetryEvent(
            technique_id="T1059",
            source_fidelity="live",
            timestamp=_now(),
        )
        assert ev.source_fidelity == "live"


# ── TelemetryBatch ────────────────────────────────────────────────────────────

class TestTelemetryBatch:
    def test_empty_batch(self):
        batch = TelemetryBatch(
            technique_id="T1059",
            source_name="replay",
            fidelity="replay",
        )
        assert len(batch) == 0
        assert list(batch) == []

    def test_len(self):
        events = [_event(), _event()]
        batch = TelemetryBatch(
            technique_id="T1059",
            source_name="replay",
            fidelity="replay",
            events=events,
        )
        assert len(batch) == 2

    def test_iter(self):
        ev1, ev2 = _event("T1059"), _event("T1059")
        batch = TelemetryBatch(
            technique_id="T1059",
            source_name="replay",
            fidelity="replay",
            events=[ev1, ev2],
        )
        assert list(batch) == [ev1, ev2]

    def test_metadata_fields(self):
        batch = TelemetryBatch(
            technique_id="T1190",
            source_name="live-local",
            fidelity="live",
        )
        assert batch.technique_id == "T1190"
        assert batch.source_name == "live-local"
        assert batch.fidelity == "live"

    def test_events_list_default_independent(self):
        b1 = TelemetryBatch(technique_id="T1059", source_name="r", fidelity="replay")
        b2 = TelemetryBatch(technique_id="T1059", source_name="r", fidelity="replay")
        b1.events.append(_event())
        assert len(b2) == 0


# ── SourceDescription ─────────────────────────────────────────────────────────

class TestSourceDescription:
    def test_fields(self):
        desc = SourceDescription(
            name="test-source",
            fidelity="replay",
            supported_platforms=["windows", "linux"],
        )
        assert desc.name == "test-source"
        assert desc.fidelity == "replay"
        assert desc.supported_platforms == ["windows", "linux"]

    def test_live_fidelity(self):
        desc = SourceDescription(name="live", fidelity="live", supported_platforms=["linux"])
        assert desc.fidelity == "live"


# ── TelemetrySource (ABC) ─────────────────────────────────────────────────────

class TestTelemetrySourceABC:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            TelemetrySource()  # type: ignore[abstract]

    def test_concrete_must_implement_describe(self):
        class BadSource(TelemetrySource):
            def ensure(self, technique_id, platform):
                raise NotAvailable("x")

        with pytest.raises(TypeError):
            BadSource()

    def test_concrete_must_implement_ensure(self):
        class BadSource(TelemetrySource):
            def describe(self):
                return SourceDescription("bad", "replay", [])

        with pytest.raises(TypeError):
            BadSource()

    def test_concrete_with_both_methods_ok(self):
        class GoodSource(TelemetrySource):
            def describe(self):
                return SourceDescription("good", "replay", ["linux"])

            def ensure(self, technique_id, platform):
                raise NotAvailable("stub")

        src = GoodSource()
        assert isinstance(src, TelemetrySource)


# ── SourceRegistry ────────────────────────────────────────────────────────────

class TestSourceRegistry:
    def _fresh_registry(self) -> SourceRegistry:
        return SourceRegistry()

    def test_list_empty(self):
        reg = self._fresh_registry()
        assert reg.list_sources() == []

    def test_register_and_get(self):
        reg = self._fresh_registry()
        src = ReplaySource()
        reg.register("replay", src)
        assert reg.get("replay") is src

    def test_list_sources_sorted(self):
        reg = self._fresh_registry()
        reg.register("zebra", ReplaySource())
        reg.register("alpha", ReplaySource())
        assert reg.list_sources() == ["alpha", "zebra"]

    def test_get_unknown_raises_key_error(self):
        reg = self._fresh_registry()
        reg.register("replay", ReplaySource())
        with pytest.raises(KeyError) as exc_info:
            reg.get("nonexistent")
        assert "nonexistent" in str(exc_info.value)
        assert "replay" in str(exc_info.value)

    def test_get_unknown_empty_registry(self):
        reg = self._fresh_registry()
        with pytest.raises(KeyError) as exc_info:
            reg.get("anything")
        assert "<none>" in str(exc_info.value)

    def test_overwrite_registration(self):
        reg = self._fresh_registry()
        src1 = ReplaySource()
        src2 = ReplaySource()
        reg.register("replay", src1)
        reg.register("replay", src2)
        assert reg.get("replay") is src2

    def test_register_non_source_raises(self):
        reg = self._fresh_registry()
        with pytest.raises(TypeError):
            reg.register("bad", "not-a-source")  # type: ignore[arg-type]

    def test_multiple_sources(self):
        reg = self._fresh_registry()
        reg.register("replay", ReplaySource())
        reg.register("live-local", LiveLocalSource())
        assert set(reg.list_sources()) == {"replay", "live-local"}


# ── ReplaySource stub ─────────────────────────────────────────────────────────

class TestReplaySource:
    def setup_method(self):
        self.src = ReplaySource()

    def test_is_telemetry_source(self):
        assert isinstance(self.src, TelemetrySource)

    def test_describe_name(self):
        assert self.src.describe().name == "replay"

    def test_describe_fidelity(self):
        assert self.src.describe().fidelity == "replay"

    def test_describe_supported_platforms(self):
        desc = self.src.describe()
        assert "windows" in desc.supported_platforms
        assert "linux" in desc.supported_platforms
        assert "macos" in desc.supported_platforms

    def test_ensure_raises_not_available(self):
        with pytest.raises(NotAvailable):
            self.src.ensure("T1059", "windows")

    def test_ensure_reason_mentions_technique(self):
        with pytest.raises(NotAvailable) as exc_info:
            self.src.ensure("T1190", "linux")
        assert "T1190" in exc_info.value.reason

    def test_ensure_reason_mentions_platform(self):
        with pytest.raises(NotAvailable) as exc_info:
            self.src.ensure("T1059", "macos")
        assert "macos" in exc_info.value.reason


# ── LiveLocalSource stub ──────────────────────────────────────────────────────

class TestLiveLocalSource:
    def setup_method(self):
        self.src = LiveLocalSource()

    def test_is_telemetry_source(self):
        assert isinstance(self.src, TelemetrySource)

    def test_describe_name(self):
        assert self.src.describe().name == "live-local"

    def test_describe_fidelity(self):
        assert self.src.describe().fidelity == "live"

    def test_describe_supported_platforms(self):
        desc = self.src.describe()
        assert "linux" in desc.supported_platforms

    def test_ensure_raises_not_available(self):
        with pytest.raises(NotAvailable):
            self.src.ensure("T1059", "linux")

    def test_ensure_reason_mentions_technique(self):
        with pytest.raises(NotAvailable) as exc_info:
            self.src.ensure("T1546", "linux")
        assert "T1546" in exc_info.value.reason

    def test_ensure_reason_mentions_platform(self):
        with pytest.raises(NotAvailable) as exc_info:
            self.src.ensure("T1059", "windows")
        assert "windows" in exc_info.value.reason


# ── Global registry ───────────────────────────────────────────────────────────

class TestGlobalRegistry:
    def test_registry_is_source_registry(self):
        assert isinstance(registry, SourceRegistry)

    def test_replay_registered(self):
        src = registry.get("replay")
        assert isinstance(src, ReplaySource)

    def test_live_local_registered(self):
        src = registry.get("live-local")
        assert isinstance(src, LiveLocalSource)

    def test_list_includes_both_defaults(self):
        names = registry.list_sources()
        assert "replay" in names
        assert "live-local" in names

"""Map raw OTRF Security-Datasets JSON events to the TelemetryEvent schema.

OTRF events come in two layouts:
  Flat  – top-level fields like EventID, Image, CommandLine, TimeCreated
  Nested – System/EventData/UserData sub-dicts (Windows Event Log XML-to-JSON)

Both are normalised to the ECS/Sysmon-aligned TelemetryEvent dataclass so
downstream code never has to know which format was in the file.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from detection_validator.telemetry.base import TelemetryEvent

# Windows hex PIDs (e.g. "0x9f4") appear in some WEL events
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")

# Fields that are explicitly mapped; everything else lands in ``extra``
_MAPPED = frozenset({
    "TimeCreated", "@timestamp", "timestamp", "UtcTime",
    "Image", "NewProcessName",
    "CommandLine", "NewProcessCommandLine",
    "ParentImage", "ParentProcessName",
    "ParentCommandLine", "ParentProcessCmdLine",
    "ProcessId", "NewProcessId", "ProcessGuid",
    "User", "SubjectUserName", "TargetUserName",
    "EventID",
    "Channel",
    "Hostname", "Computer",
    # Nested keys we flatten from System/EventData
    "System", "EventData", "UserData",
})


def _flatten(raw: dict) -> dict:
    """Flatten nested WEL structure into a single dict.

    Moves EventData/* and System/* into the top level, with System fields
    taking lower precedence than any existing top-level values.
    """
    out: dict = {}
    for k, v in raw.items():
        if k == "System" and isinstance(v, dict):
            for sk, sv in v.items():
                out.setdefault(sk, sv)
        elif k == "EventData" and isinstance(v, dict):
            for dk, dv in v.items():
                out.setdefault(dk, dv)
        elif k == "UserData" and isinstance(v, dict):
            for uk, uv in v.items():
                out.setdefault(uk, uv)
        else:
            out[k] = v
    return out


def _parse_ts(raw: Any) -> datetime:
    """Parse a timestamp from any OTRF format into an aware datetime."""
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    if isinstance(raw, dict):
        # {"SystemTime": "2019-05-18T21:31:27.590Z"}
        raw = raw.get("SystemTime") or raw.get("@timestamp") or ""
    s = str(raw).strip()
    # Replace space-separator with T for fromisoformat
    s = s.replace(" ", "T", 1)
    # Strip trailing Z and append +00:00
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(tz=timezone.utc)


def _to_int(val: Any) -> int | None:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if _HEX_RE.match(s):
        return int(s, 16)
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def normalize_otrf_event(
    raw: dict,
    technique_id: str,
    fidelity: str = "replay",
) -> TelemetryEvent:
    """Map one OTRF or Sysmon-for-Linux event dict to a TelemetryEvent.

    Unknown fields survive in ``extra`` so no information is discarded.
    Pass fidelity="live" for events captured by LiveLocalSource.
    """
    flat = _flatten(raw)

    ts_raw = (
        flat.get("UtcTime")
        or flat.get("TimeCreated")
        or flat.get("@timestamp")
        or flat.get("timestamp")
    )
    ts = _parse_ts(ts_raw) if ts_raw is not None else datetime.now(tz=timezone.utc)

    image = flat.get("Image") or flat.get("NewProcessName")
    cmd = flat.get("CommandLine") or flat.get("NewProcessCommandLine")
    parent_image = flat.get("ParentImage") or flat.get("ParentProcessName")
    parent_cmd = flat.get("ParentCommandLine") or flat.get("ParentProcessCmdLine")
    pid = _to_int(flat.get("ProcessId") or flat.get("NewProcessId"))
    user = flat.get("User") or flat.get("SubjectUserName") or flat.get("TargetUserName")
    event_id = _to_int(flat.get("EventID"))
    channel = flat.get("Channel")
    computer = flat.get("Hostname") or flat.get("Computer")

    extra = {k: v for k, v in flat.items() if k not in _MAPPED}

    return TelemetryEvent(
        technique_id=technique_id,
        source_fidelity=fidelity,  # type: ignore[arg-type]
        timestamp=ts,
        Image=str(image) if image is not None else None,
        CommandLine=str(cmd) if cmd is not None else None,
        ParentImage=str(parent_image) if parent_image is not None else None,
        ParentCommandLine=str(parent_cmd) if parent_cmd is not None else None,
        ProcessId=pid,
        User=str(user) if user is not None else None,
        EventID=event_id,
        Channel=str(channel) if channel is not None else None,
        Computer=str(computer) if computer is not None else None,
        extra=extra,
    )


def normalize_events(
    raw_events: list[dict],
    technique_id: str,
    fidelity: str = "replay",
) -> list[TelemetryEvent]:
    """Normalise a list of raw event dicts. Skips non-dict entries silently."""
    return [
        normalize_otrf_event(e, technique_id, fidelity=fidelity)
        for e in raw_events
        if isinstance(e, dict)
    ]

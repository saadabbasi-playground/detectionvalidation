"""
Offline rule matcher — evaluates detection rules against a local JSONL event file.

Same two-layer strategy as the live SIEM validators:
  1. Technique matching — event['technique'] == a rule technique ID.
  2. Keyword matching  — keyword tokens found in free-text event fields.

Returns the same RuleResult objects as validate_corpus, so output pipes
directly into `dv report`.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from detection_validator.validator.engine import (
    RuleResult,
    _sigma_keywords,
    _sigma_techniques,
    _strip_wildcards,
)

_FREE_TEXT_FIELDS = ("proctitle", "cmd_output", "message", "raw", "a2", "key")


def _parse_ts(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def load_events(path: Path, since_dt: datetime | None) -> list[dict]:
    """Read a JSONL file and return events, optionally filtered by time."""
    events: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since_dt:
                ts = _parse_ts(ev.get("timestamp") or ev.get("@timestamp"))
                if ts and ts < since_dt:
                    continue
            events.append(ev)
    return events


def _keyword_tokens(keywords: list[str]) -> list[str]:
    """Extract unique lowercase tokens (≥4 chars) from Sigma keyword list."""
    seen: set[str] = set()
    tokens: list[str] = []
    for kw in keywords:
        clean = _strip_wildcards(kw)
        for tok in re.split(r"[^a-zA-Z0-9_-]", clean):
            if len(tok) >= 4:
                low = tok.lower()
                if low not in seen:
                    seen.add(low)
                    tokens.append(low)
    return tokens


def _match_one(
    techniques: list[str],
    kw_tokens: list[str],
    events: list[dict],
) -> tuple[int, list[dict]]:
    """Return (hit_count, sample_events[≤3]) for one rule against all events."""
    tech_set: set[str] = set()
    for tid in techniques:
        tech_set.add(tid.upper())
        tech_set.add(tid.split(".")[0].upper())

    hits: list[dict] = []
    for ev in events:
        # Layer 1 — technique field exact match
        ev_tech = str(ev.get("technique", "")).upper()
        if ev_tech and ev_tech in tech_set:
            hits.append(ev)
            continue

        # Layer 2 — keyword tokens in free-text fields
        if kw_tokens:
            haystack = " ".join(str(ev.get(f, "")) for f in _FREE_TEXT_FIELDS).lower()
            if any(tok in haystack for tok in kw_tokens):
                hits.append(ev)

    return len(hits), hits[:3]


def match_corpus(
    detections: list[Any],
    events_path: Path,
    since_hours: float = 24.0,
) -> list[RuleResult]:
    """Match a list of CanonicalDetection objects against a local JSONL file."""
    from detection_validator.normalizer.schema import ValidationStatus

    since_dt: datetime | None = None
    if since_hours > 0:
        since_dt = datetime.fromtimestamp(
            time.time() - since_hours * 3600, tz=timezone.utc
        )

    try:
        events = load_events(events_path, since_dt)
    except OSError as exc:
        return [
            RuleResult(
                rule_id=str(d.id), name=d.name,
                techniques=[], siem="local",
                query_desc="", hit_count=0,
                status="error", error=str(exc),
            )
            for d in detections
        ]

    results: list[RuleResult] = []
    for detection in detections:
        techniques = [t.full_id for t in (detection.mitre_techniques or [])]
        keywords: list[str] = []

        if detection.detection_logic and detection.detection_logic.raw:
            raw = detection.detection_logic.raw
            if not techniques:
                techniques = _sigma_techniques(raw)
            keywords = _sigma_keywords(raw)

        if not techniques and not keywords:
            results.append(RuleResult(
                rule_id=str(detection.id), name=detection.name,
                techniques=techniques, siem="local",
                query_desc="(no techniques or keywords found)",
                hit_count=0, status="skip",
                error="Rule has no technique IDs or keywords to match against",
            ))
            continue

        kw_tokens = _keyword_tokens(keywords)
        query_desc = (
            f"techniques=[{', '.join(techniques)}]"
            + (f"  keywords={len(keywords)}" if keywords else "")
            + (f"  since={since_dt.isoformat()[:16]}" if since_dt else "  (all time)")
            + f"  events={len(events)}"
        )

        hit_count, samples = _match_one(techniques, kw_tokens, events)
        passed = hit_count > 0

        detection.validation_status = ValidationStatus.PASSED if passed else ValidationStatus.FAILED
        detection.last_validated = datetime.now(tz=timezone.utc)

        results.append(RuleResult(
            rule_id=str(detection.id), name=detection.name,
            techniques=techniques, siem="local",
            query_desc=query_desc,
            hit_count=hit_count, sample_events=samples,
            status="pass" if passed else "fail",
        ))

    return results

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


def _match_techniques(techniques: list[str], events: list[dict]) -> tuple[int, list[dict]]:
    """Return (hit_count, samples≤3) for technique-ID matching only."""
    tech_set: set[str] = set()
    for tid in techniques:
        tech_set.add(tid.upper())
        tech_set.add(tid.split(".")[0].upper())

    hits = [
        ev for ev in events
        if str(ev.get("technique", "")).upper() in tech_set
    ]
    return len(hits), hits[:3]


def _match_keywords(kw_tokens: list[str], events: list[dict]) -> tuple[int, list[dict]]:
    """Return (hit_count, samples≤3) for keyword-overlap matching only."""
    hits = []
    for ev in events:
        haystack = " ".join(str(ev.get(f, "")) for f in _FREE_TEXT_FIELDS).lower()
        if any(tok in haystack for tok in kw_tokens):
            hits.append(ev)
    return len(hits), hits[:3]


def _match_one(
    techniques: list[str],
    kw_tokens: list[str],
    events: list[dict],
) -> tuple[int, list[dict]]:
    """Combined match — used by callers that don't need verdict granularity."""
    tech_count, tech_samples = _match_techniques(techniques, events)
    if tech_count > 0:
        return tech_count, tech_samples
    if kw_tokens:
        return _match_keywords(kw_tokens, events)
    return 0, []


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
        base_desc = (
            f"techniques=[{', '.join(techniques)}]"
            + (f"  keywords={len(keywords)}" if keywords else "")
            + (f"  since={since_dt.isoformat()[:16]}" if since_dt else "  (all time)")
            + f"  events={len(events)}"
        )

        # Layer 2: technique-ID match (strong signal)
        if techniques:
            tech_count, tech_samples = _match_techniques(techniques, events)
            if tech_count > 0:
                detection.validation_status = ValidationStatus.PASSED
                detection.last_validated = datetime.now(tz=timezone.utc)
                results.append(RuleResult(
                    rule_id=str(detection.id), name=detection.name,
                    techniques=techniques, siem="local",
                    query_desc=base_desc,
                    hit_count=tech_count, sample_events=tech_samples,
                    status="likely_fires",
                ))
                continue

        # Layer 3: keyword-overlap (weak signal)
        if kw_tokens:
            kw_count, kw_samples = _match_keywords(kw_tokens, events)
            if kw_count > 0:
                detection.validation_status = ValidationStatus.PASSED
                detection.last_validated = datetime.now(tz=timezone.utc)
                results.append(RuleResult(
                    rule_id=str(detection.id), name=detection.name,
                    techniques=techniques, siem="local",
                    query_desc=base_desc + "  [keyword-overlap]",
                    hit_count=kw_count, sample_events=kw_samples,
                    status="keyword_partial",
                ))
                continue

        detection.validation_status = ValidationStatus.FAILED
        detection.last_validated = datetime.now(tz=timezone.utc)
        results.append(RuleResult(
            rule_id=str(detection.id), name=detection.name,
            techniques=techniques, siem="local",
            query_desc=base_desc,
            hit_count=0, sample_events=[],
            status="no_keyword_match",
        ))

    return results

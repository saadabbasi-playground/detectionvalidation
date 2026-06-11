"""
Offline rule matcher — evaluates detection rules against a local JSONL event file.

Matching tiers (applied in order; first hit wins):
  1. condition_match  — rule's Sigma field logic evaluated in-memory against the event.
                        Only this tier produces ValidationStatus.PASSED.
  2. technique_only   — no field match, but an event carries the same ATT&CK technique ID.
                        Produces ValidationStatus.FAILED (weak/coincidental signal).
  3. keyword_only     — no field/technique match, only loose keyword-token overlap.
                        Produces ValidationStatus.FAILED (weakest signal).

Special cases:
  untranslatable      — detection block has a condition the in-memory evaluator does not
                        support (e.g. complex sub-expressions).  Never falls through to
                        technique_only.  Produces ValidationStatus.FAILED + error string.
  no_match            — no events matched at any tier.
  skip                — rule has no techniques, keywords, or evaluable detection block.
  error               — JSONL file could not be read.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from detection_validator.validator.engine import (
    RuleResult,
    _sigma_keywords,
    _sigma_techniques,
    _strip_wildcards,
)

_FREE_TEXT_FIELDS = ("proctitle", "cmd_output", "message", "raw", "a2", "key")


# ── Timestamp helpers ─────────────────────────────────────────────────────────


def _parse_ts(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


# ── Correlation helpers (run_id + time window) ───────────────────────────────


def _extract_run_id(ev: dict) -> str | None:
    """Pull a run_id from an event, tolerating ECS-nested and flat shapes.

    Supported keys (in order):
      labels.run_id   (ECS object form)
      "labels.run_id" (flat/dotted form, sometimes how OpenSearch returns it)
      run_id          (degenerate / pre-ECS shape)
    """
    labels = ev.get("labels")
    if isinstance(labels, dict):
        rid = labels.get("run_id")
        if rid:
            return str(rid)
    rid = ev.get("labels.run_id")
    if rid:
        return str(rid)
    rid = ev.get("run_id")
    if rid:
        return str(rid)
    return None


def _event_timestamp(ev: dict) -> datetime | None:
    """Read @timestamp (ECS) or timestamp (legacy) from an event."""
    return _parse_ts(ev.get("@timestamp") or ev.get("timestamp"))


def correlate_events(
    events: list[dict],
    run_id: str | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict]:
    """Filter *events* to those tagged with *run_id* and inside the window.

    When ``run_id`` is provided, an event without a matching ``labels.run_id``
    is dropped even if its timestamp is inside the window. Both filters apply
    independently — a hit outside the window is NOT a pass even if it carries
    the right run_id, and vice versa.
    """
    if run_id is None and window_start is None and window_end is None:
        return events
    out: list[dict] = []
    for ev in events:
        if run_id is not None:
            if _extract_run_id(ev) != run_id:
                continue
        if window_start is not None or window_end is not None:
            ts = _event_timestamp(ev)
            if ts is None:
                continue
            if window_start is not None and ts < window_start:
                continue
            if window_end is not None and ts > window_end:
                continue
        out.append(ev)
    return out


# ── Event loading ─────────────────────────────────────────────────────────────


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


# ── Keyword helpers ───────────────────────────────────────────────────────────


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


# ── Tier-2/3 matchers (technique-ID and keyword overlap) ─────────────────────


def _match_techniques(techniques: list[str], events: list[dict]) -> tuple[int, list[dict]]:
    """Return (hit_count, samples≤3) for technique-ID matching only."""
    if not techniques:
        return 0, []
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
    if not kw_tokens:
        return 0, []
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
    """Combined technique+keyword match — used by callers that don't need tier granularity."""
    tech_count, tech_samples = _match_techniques(techniques, events)
    if tech_count > 0:
        return tech_count, tech_samples
    if kw_tokens:
        return _match_keywords(kw_tokens, events)
    return 0, []


# ── Tier-1: in-memory Sigma field evaluator ───────────────────────────────────
#
# Mirrors the condition-parsing logic in engine._sigma_detection_to_os_query
# but evaluates against an event dict instead of building an OpenSearch clause.
# Kept local to this module (engine.py uses a nested function); the two share
# the same semantics — any divergence is a bug to fix in both places.


def _eval_field_condition(field_raw: str, value: Any, event: dict) -> bool:
    """
    Evaluate a single Sigma field condition against one event dict.

    Supported modifiers: contains, endswith, startswith, re, (none = exact).
    Multiple values (list) → OR (any value matches → True).
    Field lookup is case-insensitive against event keys.
    """
    parts = field_raw.split("|", 1)
    field = parts[0].strip()
    modifier = parts[1].lower() if len(parts) > 1 else ""

    # Case-insensitive flat lookup
    ev_val = event.get(field)
    if ev_val is None:
        field_lower = field.lower()
        for k, v in event.items():
            if k.lower() == field_lower:
                ev_val = v
                break

    # ECS dotted-path lookup: "process.executable" → event["process"]["executable"]
    if ev_val is None and "." in field:
        cursor: Any = event
        for seg in field.split("."):
            if isinstance(cursor, dict):
                # case-insensitive segment lookup
                if seg in cursor:
                    cursor = cursor[seg]
                else:
                    seg_lower = seg.lower()
                    found = False
                    for k, v in cursor.items():
                        if k.lower() == seg_lower:
                            cursor = v
                            found = True
                            break
                    if not found:
                        cursor = None
                        break
            else:
                cursor = None
                break
        if cursor is not None and not isinstance(cursor, (dict, list)):
            ev_val = cursor

    if ev_val is None:
        return False

    ev_str = str(ev_val).lower()
    values = value if isinstance(value, list) else [value]

    for v in values:
        sv = str(v).lower()
        if modifier == "contains":
            if sv in ev_str:
                return True
        elif modifier == "endswith":
            if ev_str.endswith(sv):
                return True
        elif modifier == "startswith":
            if ev_str.startswith(sv):
                return True
        elif modifier == "re":
            if re.search(sv, ev_str, re.I):
                return True
        else:
            if ev_str == sv:
                return True

    return False


def _eval_group(group: dict, event: dict) -> bool:
    """Evaluate a Sigma detection group (AND of all field conditions) against one event."""
    for field_raw, value in group.items():
        if not _eval_field_condition(field_raw, value, event):
            return False
    return True


def _eval_condition_expr(
    cond: str,
    groups: dict[str, dict],
    event: dict,
) -> bool | None:
    """
    Recursively evaluate a Sigma condition expression against one event.

    Returns True/False for supported patterns.
    Returns None for unsupported patterns (the caller will report 'untranslatable').

    Supported patterns (same set as engine._sigma_detection_to_os_query):
      selection
      not selection
      a and b  /  a and not b
      a or b
      1 of name*
      all of name*
    """
    cond = cond.strip()

    # "1 of name*" or "1 of name"
    m = re.match(r"^1\s+of\s+(\S+)$", cond, re.I)
    if m:
        pattern = m.group(1)
        if "*" in pattern:
            prefix = pattern.replace("*", "")
            candidates = [g for n, g in groups.items() if n.startswith(prefix)]
        else:
            g = groups.get(pattern)
            candidates = [g] if g is not None else []
        return any(_eval_group(g, event) for g in candidates)

    # "all of name*" or "all of name"
    m = re.match(r"^all\s+of\s+(\S+)$", cond, re.I)
    if m:
        pattern = m.group(1)
        prefix = pattern.replace("*", "")
        candidates = [g for n, g in groups.items() if n.startswith(prefix)]
        if not candidates:
            return False
        return all(_eval_group(g, event) for g in candidates)

    # OR — lowest precedence
    or_parts = re.split(r"\bor\b", cond, flags=re.I)
    if len(or_parts) > 1:
        results = [_eval_condition_expr(p.strip(), groups, event) for p in or_parts]
        if any(r is None for r in results):
            return None  # propagate untranslatable
        return any(results)

    # AND (with optional NOT per part)
    and_parts = re.split(r"\band\b", cond, flags=re.I)
    result = True
    for part in and_parts:
        part = part.strip()
        neg = re.match(r"^not\s+(.+)$", part, re.I)
        name = neg.group(1).strip() if neg else part

        # Resolve name to a bool
        if "*" in name:
            prefix = name.replace("*", "")
            sub: bool = any(
                _eval_group(g, event) for n, g in groups.items() if n.startswith(prefix)
            )
        else:
            g = groups.get(name)
            if g is None:
                # Unknown group — condition references a name we can't resolve
                return None
            sub = _eval_group(g, event)

        result = result and (not sub if neg else sub)

    return result


def _eval_sigma_corpus(
    raw_yaml: str,
    events: list[dict],
) -> tuple[str, list[dict], str]:
    """
    Evaluate a Sigma rule's detection block against all events in the corpus.

    Returns (verdict, matching_samples≤3, detail_string).

    Verdicts
    --------
    "condition_match"   at least one event satisfied the field conditions
    "no_match"          condition parsed and evaluated; no event matched
    "untranslatable"    condition exists but uses a pattern we cannot evaluate
                        (detail_string names the unsupported pattern)
    "skip"              no detection block, no condition, or empty raw YAML
                        (caller should fall through to technique/keyword tiers)
    """
    if not raw_yaml or not raw_yaml.strip():
        return "skip", [], "empty raw YAML"

    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        return "skip", [], f"YAML parse error: {exc}"

    if not isinstance(data, dict):
        return "skip", [], "YAML did not parse to a mapping"

    detection = data.get("detection", {})
    if not isinstance(detection, dict) or not detection:
        return "skip", [], "no detection block"

    condition_raw: str = str(detection.get("condition", "")).strip()
    if not condition_raw:
        # Rule has a detection block but no condition (DV-L004) — fall through
        return "skip", [], "no condition field"

    # Build named groups (exclude 'condition' and 'keywords' special keys)
    groups: dict[str, dict] = {
        name: val
        for name, val in detection.items()
        if name not in ("condition", "keywords") and isinstance(val, dict)
    }

    if not groups:
        # Only keywords: or a condition referencing non-dict values — untranslatable
        # because keywords-only rules use full-text search, not field conditions.
        return "untranslatable", [], (
            f"condition '{condition_raw}' references no field-condition groups "
            "(keywords-only rules cannot be evaluated in-memory)"
        )

    # Evaluate each event
    hits: list[dict] = []
    last_none_reason = ""
    for ev in events:
        val = _eval_condition_expr(condition_raw, groups, ev)
        if val is None:
            last_none_reason = f"unsupported condition pattern: {condition_raw!r}"
            # Don't break — confirm it's consistently untranslatable
            continue
        if val:
            hits.append(ev)

    # If every evaluation returned None → untranslatable
    if not hits and last_none_reason:
        return "untranslatable", [], last_none_reason

    if hits:
        return "condition_match", hits[:3], ""

    return "no_match", [], ""


# ── Main corpus matcher ───────────────────────────────────────────────────────


def _count_condition_hits(raw_yaml: str, events: list[dict]) -> int:
    """Count how many *events* satisfy the rule's field-level condition.

    Used by benign-baseline FP scoring: we run the same translated query
    against a known-good corpus and the count is the false-positive count.
    Untranslatable rules count 0 — they would not be deployable to a SIEM,
    so they cannot produce FPs in production either.
    """
    if not raw_yaml.strip():
        return 0
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError:
        return 0
    if not isinstance(data, dict):
        return 0
    detection = data.get("detection", {})
    if not isinstance(detection, dict) or not detection:
        return 0
    condition_raw = str(detection.get("condition", "")).strip()
    if not condition_raw:
        return 0
    groups: dict[str, dict] = {
        name: val
        for name, val in detection.items()
        if name not in ("condition", "keywords") and isinstance(val, dict)
    }
    if not groups:
        return 0
    hits = 0
    for ev in events:
        v = _eval_condition_expr(condition_raw, groups, ev)
        if v is True:
            hits += 1
    return hits


def match_corpus(
    detections: list[Any],
    events_path: Path,
    since_hours: float = 24.0,
    *,
    run_id: str | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    benign_events_path: Path | None = None,
    fp_threshold: int = 0,
) -> list[RuleResult]:
    """Match a list of CanonicalDetection objects against a local JSONL file.

    Status tiers on the returned RuleResult:
      "condition_match"  field logic matched → ValidationStatus.PASSED
      "technique_only"   technique-ID overlap only → ValidationStatus.FAILED
      "keyword_only"     keyword-token overlap only → ValidationStatus.FAILED
      "untranslatable"   detection condition unsupported → ValidationStatus.FAILED
      "no_match"         nothing matched → ValidationStatus.FAILED
      "skip"             rule unmatachable (no techniques/keywords/condition)
      "error"            JSONL file unreadable

    Correlation (run_id / window):
      When ``run_id`` is set, events whose ``labels.run_id`` does not match
      are dropped BEFORE evaluation — a hit outside the run does not count.
      When ``window_start`` / ``window_end`` are set, events outside the
      window are dropped likewise. Both filters apply independently.

    FP scoring (benign_events_path):
      For each rule, the same field-level condition is re-evaluated against
      the benign corpus; the count populates ``fp_hits``. ``precision`` is
      tp/(tp+fp). ``working`` is True only when:
        status == 'condition_match'  AND  fp_hits <= fp_threshold
    """
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

    # Run-correlation filter applies after time-since filter.
    events = correlate_events(events, run_id, window_start, window_end)

    benign_events: list[dict] = []
    if benign_events_path is not None:
        try:
            benign_events = load_events(Path(benign_events_path), since_dt=None)
        except OSError as exc:
            return [
                RuleResult(
                    rule_id=str(d.id), name=d.name,
                    techniques=[], siem="local",
                    query_desc="", hit_count=0,
                    status="error", error=f"benign corpus unreadable: {exc}",
                )
                for d in detections
            ]

    return _match_corpus_inner(
        detections, events,
        since_dt=since_dt,
        benign_events=benign_events,
        fp_threshold=fp_threshold,
        run_id=run_id,
    )


def match_corpus_correlated(
    detections: list[Any],
    events: list[dict],
    *,
    run_id: str | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    benign_events: list[dict] | None = None,
    fp_threshold: int = 0,
) -> list[RuleResult]:
    """In-memory variant of :func:`match_corpus` used by ``dv loop`` and tests.

    Takes events as a list (no file I/O), applies run_id+window correlation,
    then runs the standard three-tier matcher with optional FP scoring.
    """
    events = correlate_events(events, run_id, window_start, window_end)
    return _match_corpus_inner(
        detections, events,
        since_dt=None,
        benign_events=list(benign_events or []),
        fp_threshold=fp_threshold,
        run_id=run_id,
    )


def _match_corpus_inner(
    detections: list[Any],
    events: list[dict],
    *,
    since_dt: datetime | None,
    benign_events: list[dict],
    fp_threshold: int,
    run_id: str | None,
) -> list[RuleResult]:
    from detection_validator.normalizer.schema import ValidationStatus

    results: list[RuleResult] = []

    for detection in detections:
        techniques = [t.full_id for t in (detection.mitre_techniques or [])]
        keywords: list[str] = []
        raw_yaml = ""

        if detection.detection_logic and detection.detection_logic.raw:
            raw_yaml = detection.detection_logic.raw
            if not techniques:
                techniques = _sigma_techniques(raw_yaml)
            keywords = _sigma_keywords(raw_yaml)

        if not techniques and not keywords and not raw_yaml.strip():
            results.append(RuleResult(
                rule_id=str(detection.id), name=detection.name,
                techniques=techniques, siem="local",
                query_desc="(no techniques, keywords, or detection logic found)",
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

        # ── Tier 1: field-condition evaluation ────────────────────────────────
        if raw_yaml.strip():
            verdict, samples, detail = _eval_sigma_corpus(raw_yaml, events)

            if verdict == "condition_match":
                detection.validation_status = ValidationStatus.PASSED
                detection.last_validated = datetime.now(tz=timezone.utc)
                results.append(RuleResult(
                    rule_id=str(detection.id), name=detection.name,
                    techniques=techniques, siem="local",
                    query_desc=base_desc,
                    hit_count=len(samples), sample_events=samples,
                    status="condition_match",
                ))
                continue

            if verdict == "untranslatable":
                # Do NOT fall through to technique_only — that would be dishonest.
                detection.validation_status = ValidationStatus.FAILED
                detection.last_validated = datetime.now(tz=timezone.utc)
                results.append(RuleResult(
                    rule_id=str(detection.id), name=detection.name,
                    techniques=techniques, siem="local",
                    query_desc=base_desc,
                    hit_count=0, sample_events=[],
                    status="untranslatable",
                    error=detail,
                ))
                continue

            # verdict == "no_match" or "skip" → fall through to technique/keyword tiers

        # ── Tier 2: technique-ID match ────────────────────────────────────────
        if techniques:
            tech_count, tech_samples = _match_techniques(techniques, events)
            if tech_count > 0:
                detection.validation_status = ValidationStatus.FAILED
                detection.last_validated = datetime.now(tz=timezone.utc)
                results.append(RuleResult(
                    rule_id=str(detection.id), name=detection.name,
                    techniques=techniques, siem="local",
                    query_desc=base_desc,
                    hit_count=tech_count, sample_events=tech_samples,
                    status="technique_only",
                ))
                continue

        # ── Tier 3: keyword-token overlap ─────────────────────────────────────
        if kw_tokens:
            kw_count, kw_samples = _match_keywords(kw_tokens, events)
            if kw_count > 0:
                detection.validation_status = ValidationStatus.FAILED
                detection.last_validated = datetime.now(tz=timezone.utc)
                results.append(RuleResult(
                    rule_id=str(detection.id), name=detection.name,
                    techniques=techniques, siem="local",
                    query_desc=base_desc + "  [keyword-overlap]",
                    hit_count=kw_count, sample_events=kw_samples,
                    status="keyword_only",
                ))
                continue

        # ── Nothing matched ───────────────────────────────────────────────────
        detection.validation_status = ValidationStatus.FAILED
        detection.last_validated = datetime.now(tz=timezone.utc)
        results.append(RuleResult(
            rule_id=str(detection.id), name=detection.name,
            techniques=techniques, siem="local",
            query_desc=base_desc,
            hit_count=0, sample_events=[],
            status="no_match",
        ))

    # ── Post-pass: tag results with run_id and (optionally) FP score ─────────
    fp_scoring = len(benign_events) > 0
    for detection, result in zip(detections, results):
        if run_id is not None:
            result.run_id = run_id
        if not fp_scoring:
            continue
        # Recover the rule's raw Sigma YAML so we can re-run the condition
        # against the benign corpus. If there is no parseable detection block,
        # FP scoring is meaningless — leave fp_hits=0 and precision=None.
        raw_yaml = ""
        if detection.detection_logic and detection.detection_logic.raw:
            raw_yaml = detection.detection_logic.raw
        if not raw_yaml.strip():
            continue
        fp = _count_condition_hits(raw_yaml, benign_events)
        # tp here means "true positive on the run we just measured":
        # only a condition_match against attack telemetry is a real TP.
        # technique_only / keyword_only / no_match do NOT count as TPs.
        tp = result.hit_count if result.status == "condition_match" else 0
        result.fp_hits = fp
        if (tp + fp) > 0:
            result.precision = tp / (tp + fp)
        else:
            result.precision = None
        result.working = (result.status == "condition_match") and (fp <= fp_threshold)

    return results

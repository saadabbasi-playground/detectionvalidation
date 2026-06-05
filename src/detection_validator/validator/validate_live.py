"""Recall-oriented validation against guaranteed attack telemetry.

⚠  RECALL TEST — NOT a false-positive assessment.

This module runs a detection rule against events we *know* are attack activity
(sourced from OTRF Security-Datasets or a live capture agent).  It answers:

    "Does this rule fire on real attack events?"

That is RECALL (true-positive rate on attack traffic).  It says nothing about
false-positive rate — for that you need benign baseline traffic.

Verdicts
--------
VALIDATED_RECALL  rule fired on the tagged attack events ≥1 time
MISSED            attack events were indexed but the rule returned zero hits
NOT_VALIDATABLE   source.ensure() could not produce telemetry (reason included)

Workflow (per technique declared in the rule):
  1. source.ensure(technique_id, platform) → TelemetryBatch  |  raise NotAvailable
  2. bulk_index(batch) → events in telemetry-replay-{technique}
  3. Translate Sigma rule → OpenSearch query  (via engine._sigma_detection_to_os_query)
  4. Execute against the replay index; count hits
  5. Emit verdict + Lucene query string + Dashboards URL for human eyeballing
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection_validator.normalizer.schema import CanonicalDetection
    from detection_validator.telemetry.base import TelemetrySource


# ── Verdicts ──────────────────────────────────────────────────────────────────


class RecallVerdict(str, Enum):
    VALIDATED_RECALL = "VALIDATED_RECALL"
    MISSED = "MISSED"
    NOT_VALIDATABLE = "NOT_VALIDATABLE"


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class TechniqueResult:
    """Recall-validation outcome for a single ATT&CK technique."""

    technique_id: str
    verdict: RecallVerdict = RecallVerdict.NOT_VALIDATABLE
    event_count: int = 0            # events indexed from ensure()
    match_count: int = 0            # OpenSearch query hits
    index: str = ""                 # telemetry-replay-{technique}
    lucene_query: str | None = None # human-readable Lucene string for Dashboards
    not_available_reason: str | None = None
    sample_events: list[dict] = field(default_factory=list)


@dataclass
class LiveValidationResult:
    """Aggregate recall-validation outcome for one rule across all its techniques."""

    rule_id: str
    rule_name: str
    source_name: str
    platform: str
    os_url: str
    technique_results: list[TechniqueResult] = field(default_factory=list)

    @property
    def overall_verdict(self) -> RecallVerdict:
        """Best single verdict across all techniques (highest specificity wins)."""
        verdicts = {r.verdict for r in self.technique_results}
        if RecallVerdict.VALIDATED_RECALL in verdicts:
            return RecallVerdict.VALIDATED_RECALL
        if RecallVerdict.MISSED in verdicts:
            return RecallVerdict.MISSED
        return RecallVerdict.NOT_VALIDATABLE


# ── Rule resolution ───────────────────────────────────────────────────────────


def resolve_rule(
    rule_id: str,
    rules_dir: Path,
) -> tuple["CanonicalDetection", Path | None]:
    """Return (CanonicalDetection, source_path).

    Accepts:
      • a file path to a Sigma YAML file — loads it directly.
      • a UUID string — scans *rules_dir* recursively until a rule whose
        ``id`` field matches is found.

    Raises ``FileNotFoundError`` if neither strategy locates the rule.
    """
    from detection_validator.parsers.sigma import SigmaParser

    parser = SigmaParser()

    # Path-first: accept an existing file path as rule_id
    as_path = Path(rule_id)
    if as_path.exists() and as_path.is_file():
        return parser.parse_file(as_path), as_path

    # UUID scan
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            if not parser.can_parse(path):
                continue
            det = parser.parse_file(path)
            if det.id == rule_id:
                return det, path
        except Exception:
            continue

    raise FileNotFoundError(
        f"Rule {rule_id!r} not found as a file or by ID under {rules_dir}.\n"
        "  Pass a path:  dv validate-live --rule-id path/to/rule.yml\n"
        "  Or pass a UUID matching the rule's 'id:' field."
    )


# ── OpenSearch helpers ────────────────────────────────────────────────────────


def _run_os_query(
    index: str, query_body: dict, os_url: str, size: int = 5
) -> tuple[int, list[dict]]:
    """Execute a search against *index* and return (total_hits, sample_sources)."""
    url = f"{os_url.rstrip('/')}/{index}/_search"
    payload = json.dumps({"query": query_body, "size": size}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        # HTTPError is a subclass of URLError — must be caught first
        if exc.code == 404:
            return 0, []  # index doesn't exist yet
        raise ConnectionError(f"OpenSearch error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"OpenSearch not reachable at {os_url}: {exc}\n"
            "  Start the local stack: dv siem up"
        ) from exc

    total_obj = body.get("hits", {}).get("total", 0)
    total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj)
    samples = [h.get("_source", {}) for h in body.get("hits", {}).get("hits", [])]
    return total, samples


def _lucene_from_rule(rule_path: Path | None, technique_ids: list[str]) -> str | None:
    """Return a Lucene query string for the rule, or None on failure."""
    if rule_path is None:
        return None
    try:
        from detection_validator.siem.query_gen import generate_queries

        results = generate_queries(rule_path, siems=["opensearch"])
        for r in results:
            if r.fmt == "default" and r.query:
                return r.query
    except Exception:
        pass
    # Fallback: bare technique-ID Lucene clause
    if technique_ids:
        return " OR ".join(f'technique_id:"{tid}"' for tid in technique_ids)
    return None


# ── Core validator ────────────────────────────────────────────────────────────


def validate_live(
    detection: "CanonicalDetection",
    source: "TelemetrySource",
    rule_path: Path | None = None,
    platform: str = "windows",
    os_url: str = "http://localhost:9200",
) -> LiveValidationResult:
    """Run recall-validation for every ATT&CK technique declared in *detection*.

    For each technique:
      1. Call ``source.ensure(technique_id, platform)``.
      2. Bulk-index the returned batch into ``telemetry-replay-{technique}``.
      3. Translate the rule's Sigma detection block to an OpenSearch query and
         execute it against the replay index.
      4. Produce a :class:`TechniqueResult` with a :class:`RecallVerdict`.

    Does not raise — all per-technique errors are captured in the result so
    one broken technique doesn't abort the others.
    """
    from detection_validator.telemetry.base import NotAvailable
    from detection_validator.telemetry.indexer import bulk_index, index_name_for
    from detection_validator.validator.engine import _sigma_detection_to_os_query

    technique_ids = [t.full_id for t in (detection.mitre_techniques or [])]
    if not technique_ids:
        # Extract directly from raw YAML if parser missed them
        if detection.detection_logic and detection.detection_logic.raw:
            from detection_validator.validator.engine import _sigma_techniques
            technique_ids = _sigma_techniques(detection.detection_logic.raw)

    lucene_str = _lucene_from_rule(rule_path, technique_ids)

    raw_yaml = ""
    if rule_path and rule_path.exists():
        raw_yaml = rule_path.read_text(encoding="utf-8")
    elif detection.detection_logic and detection.detection_logic.raw:
        raw_yaml = detection.detection_logic.raw

    result = LiveValidationResult(
        rule_id=detection.id,
        rule_name=detection.name,
        source_name=source.describe().name,
        platform=platform,
        os_url=os_url,
    )

    if not technique_ids:
        result.technique_results.append(
            TechniqueResult(
                technique_id="(none)",
                verdict=RecallVerdict.NOT_VALIDATABLE,
                not_available_reason=(
                    "Rule declares no ATT&CK technique IDs — "
                    "add attack.TXXXX tags to make it validatable."
                ),
            )
        )
        return result

    for tid in technique_ids:
        idx = index_name_for(tid)
        tech_result = TechniqueResult(technique_id=tid, index=idx, lucene_query=lucene_str)

        # ── Step 1: ensure telemetry ──────────────────────────────────────────
        try:
            batch = source.ensure(tid, platform)
        except NotAvailable as exc:
            tech_result.verdict = RecallVerdict.NOT_VALIDATABLE
            tech_result.not_available_reason = exc.reason
            result.technique_results.append(tech_result)
            continue

        tech_result.event_count = len(batch)

        # ── Step 2: index into replay index ───────────────────────────────────
        try:
            indexed, _ = bulk_index(batch, os_url=os_url)
        except IndexError as exc:
            tech_result.verdict = RecallVerdict.NOT_VALIDATABLE
            tech_result.not_available_reason = (
                f"OpenSearch unavailable — could not index {len(batch)} events: {exc}"
            )
            result.technique_results.append(tech_result)
            continue

        # ── Step 3: build the OS query ────────────────────────────────────────
        sigma_clause = _sigma_detection_to_os_query(raw_yaml) if raw_yaml else None
        if sigma_clause:
            query_body = {"bool": {"must": sigma_clause}}
        else:
            # Fallback: exact match on the technique_id tag we injected at index time
            query_body = {"term": {"technique_id": tid}}

        # ── Step 4: execute query ─────────────────────────────────────────────
        try:
            total, samples = _run_os_query(idx, query_body, os_url)
        except ConnectionError as exc:
            tech_result.verdict = RecallVerdict.NOT_VALIDATABLE
            tech_result.not_available_reason = str(exc)
            result.technique_results.append(tech_result)
            continue

        tech_result.match_count = total
        tech_result.sample_events = samples

        if total > 0:
            tech_result.verdict = RecallVerdict.VALIDATED_RECALL
        else:
            tech_result.verdict = RecallVerdict.MISSED

        result.technique_results.append(tech_result)

    return result

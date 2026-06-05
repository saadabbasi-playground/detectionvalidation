"""
Validation engine — executes detection rules against live SIEM telemetry.

Strategy (three-layer, tried in order):
  1. Sigma field matching — translates the Sigma detection: block into a
                            proper OpenSearch field-level query so the actual
                            detection logic is evaluated against real auditd fields.
  2. Technique matching   — queries for events with technique IDs declared in
                            the rule's ATT&CK tags (reliable for auditd-agent events).
  3. Keyword matching     — extracts literal keywords from the rule's detection
                            section and multi-matches them across free-text fields.

A rule PASSES if any layer returns at least one hit in the time window.
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class RuleResult:
    rule_id: str
    name: str
    techniques: list[str]
    siem: str
    query_desc: str          # human-readable summary of what was queried
    hit_count: int
    sample_events: list[dict] = field(default_factory=list)
    status: str = "fail"     # pass | fail | error | skip
    error: str | None = None


# ── Sigma YAML helpers ────────────────────────────────────────────────────────

def _sigma_keywords(raw_yaml: str) -> list[str]:
    """Return keyword strings from a Sigma rule's detection.keywords list."""
    try:
        import yaml
        data = yaml.safe_load(raw_yaml)
        kws = data.get("detection", {}).get("keywords", [])
        if isinstance(kws, list):
            return [str(k) for k in kws if k]
        if isinstance(kws, str):
            return [kws]
    except Exception:
        pass
    return []


def _sigma_techniques(raw_yaml: str) -> list[str]:
    """Extract ATT&CK technique IDs from Sigma rule tags (attack.TXXXX)."""
    try:
        import yaml
        data = yaml.safe_load(raw_yaml)
        ids = []
        for tag in data.get("tags", []):
            m = re.match(r"attack\.(T\d{4}(?:\.\d{3})?)", str(tag), re.I)
            if m:
                ids.append(m.group(1).upper())
        return ids
    except Exception:
        return []


def _strip_wildcards(kw: str) -> str:
    """Remove leading/trailing Sigma wildcards and strip whitespace."""
    return kw.strip("*?|").strip()


# ── Sigma detection block → OpenSearch translator ────────────────────────────

def _sigma_field_clause(field_raw: str, value: Any) -> dict | None:
    """
    Translate a single Sigma field condition to an OpenSearch clause.

    Supported modifiers (appended to field name with |):
      contains   → wildcard *value*
      endswith   → wildcard *value
      startswith → wildcard value*
      re         → regexp
      (none)     → term / terms exact match
    """
    parts = field_raw.split("|", 1)
    field = parts[0].strip()
    modifier = parts[1].lower() if len(parts) > 1 else ""

    # keyword sub-field for exact/wildcard matching on text fields
    kf = f"{field}.keyword"

    values = value if isinstance(value, list) else [value]

    clauses: list[dict] = []
    for v in values:
        sv = str(v)
        if modifier == "contains":
            clauses.append({"wildcard": {kf: f"*{sv}*"}})
        elif modifier == "endswith":
            clauses.append({"wildcard": {kf: f"*{sv}"}})
        elif modifier == "startswith":
            clauses.append({"wildcard": {kf: f"{sv}*"}})
        elif modifier == "re":
            clauses.append({"regexp": {kf: sv}})
        else:
            clauses.append({"term": {kf: sv}})

    if not clauses:
        return None
    if len(clauses) == 1:
        return clauses[0]
    return {"bool": {"should": clauses, "minimum_should_match": 1}}


def _sigma_group_to_clause(group: dict) -> dict | None:
    """Translate a Sigma named condition group (dict of field conditions) to a bool must clause."""
    must: list[dict] = []
    for field_raw, value in group.items():
        clause = _sigma_field_clause(field_raw, value)
        if clause:
            must.append(clause)
    if not must:
        return None
    if len(must) == 1:
        return must[0]
    return {"bool": {"must": must}}


def _sigma_detection_to_os_query(raw_yaml: str) -> dict | None:
    """
    Translate a Sigma rule's detection: block into an OpenSearch bool query.

    Supports condition patterns:
      - selection
      - selection and not filter
      - sel1 or sel2
      - 1 of selection*  (any group whose name starts with selection)
    Returns None if the detection block cannot be translated.
    """
    try:
        import yaml
        data = yaml.safe_load(raw_yaml)
    except Exception:
        return None

    detection = data.get("detection", {})
    if not detection:
        return None

    condition_raw: str = str(detection.get("condition", "")).strip()
    if not condition_raw:
        return None

    # Build a dict of named groups (exclude 'condition' and 'keywords' keys)
    groups: dict[str, dict] = {}
    for name, val in detection.items():
        if name in ("condition", "keywords") or not isinstance(val, dict):
            continue
        groups[name] = val

    if not groups:
        return None

    def resolve(name: str) -> dict | None:
        """Resolve a group name or wildcard pattern to an OpenSearch clause."""
        if "*" in name:
            # e.g. "selection*" — OR of all matching groups
            prefix = name.replace("*", "")
            matched = [_sigma_group_to_clause(g) for n, g in groups.items() if n.startswith(prefix)]
            matched = [c for c in matched if c]
            if not matched:
                return None
            if len(matched) == 1:
                return matched[0]
            return {"bool": {"should": matched, "minimum_should_match": 1}}
        clause = groups.get(name)
        return _sigma_group_to_clause(clause) if clause else None

    def parse_condition(cond: str) -> dict | None:
        """
        Parse common Sigma condition expressions into an OpenSearch bool query.
        Handles: term, not term, a and b, a and not b, a or b,
                 1 of name*, all of name*.
        """
        cond = cond.strip()

        # "1 of name*"
        m = re.match(r"^1\s+of\s+(\S+)$", cond, re.I)
        if m:
            return resolve(m.group(1))

        # "all of name*"
        m = re.match(r"^all\s+of\s+(\S+)$", cond, re.I)
        if m:
            prefix = m.group(1).replace("*", "")
            matched = [_sigma_group_to_clause(g) for n, g in groups.items() if n.startswith(prefix)]
            matched = [c for c in matched if c]
            if not matched:
                return None
            return {"bool": {"must": matched}}

        # Split on " or " (lowest precedence)
        or_parts = re.split(r"\bor\b", cond, flags=re.I)
        if len(or_parts) > 1:
            clauses = [c for p in or_parts if (c := parse_condition(p.strip()))]
            if not clauses:
                return None
            if len(clauses) == 1:
                return clauses[0]
            return {"bool": {"should": clauses, "minimum_should_match": 1}}

        # Split on " and " — each part may be "not X"
        and_parts = re.split(r"\band\b", cond, flags=re.I)
        must: list[dict] = []
        must_not: list[dict] = []
        for part in and_parts:
            part = part.strip()
            negated = re.match(r"^not\s+(.+)$", part, re.I)
            name = negated.group(1).strip() if negated else part
            clause = resolve(name)
            if clause:
                (must_not if negated else must).append(clause)

        if not must and not must_not:
            return None
        result: dict[str, Any] = {"bool": {}}
        if must:
            result["bool"]["must"] = must if len(must) > 1 else must[0]
        if must_not:
            result["bool"]["must_not"] = must_not if len(must_not) > 1 else must_not[0]
        return result

    return parse_condition(condition_raw)


# ── OpenSearch query builder ──────────────────────────────────────────────────

def _build_os_query(
    techniques: list[str],
    keywords: list[str],
    since_iso: str | None,
    size: int = 5,
) -> dict[str, Any]:
    should: list[dict] = []

    # Technique terms — exact match on the `technique.keyword` sub-field
    for tid in dict.fromkeys(techniques):           # deduplicate, preserve order
        should.append({"term": {"technique.keyword": tid}})
        base = tid.split(".")[0]
        if base != tid:
            should.append({"term": {"technique.keyword": base}})

    # Keyword match — plain words extracted from the Sigma keywords list.
    # We strip special chars so the standard text analyser can match them;
    # longer tokens (≥4 chars) are required to avoid noise.
    seen_kw: set[str] = set()
    for kw in keywords:
        clean = _strip_wildcards(kw)
        # Extract meaningful tokens: split on non-alphanumeric, keep 4+ char words
        tokens = [t for t in re.split(r"[^a-zA-Z0-9_-]", clean) if len(t) >= 4]
        for tok in tokens:
            tok_lower = tok.lower()
            if tok_lower in seen_kw:
                continue
            seen_kw.add(tok_lower)
            should.append({
                "multi_match": {
                    "query": tok,
                    "fields": ["proctitle", "cmd_output", "message", "raw", "a2"],
                    "type": "best_fields",
                    "operator": "and",
                }
            })

    if not should:
        return {}

    query: dict[str, Any] = {
        "size": size,
        "_source": ["timestamp", "technique", "key", "source",
                    "exe", "comm", "proctitle", "cmd_output", "vm", "host",
                    "type", "uid", "a0", "a1", "a2"],
        "query": {
            "bool": {
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    if since_iso:
        query["query"]["bool"]["filter"] = [
            {"range": {"timestamp": {"gte": since_iso}}}
        ]

    return query


# ── OpenSearch validator ──────────────────────────────────────────────────────

class OpenSearchValidator:
    def __init__(
        self,
        host: str = "https://localhost:9200",
        user: str = "admin",
        password: str = "DetectVal123!",
        index: str = "dv-telemetry-*",
        since_hours: float = 24.0,
    ) -> None:
        self._host = host.rstrip("/")
        self._index = index
        self._auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        since_dt = datetime.fromtimestamp(
            time.time() - since_hours * 3600, tz=timezone.utc
        )
        self._since_iso: str | None = since_dt.isoformat() if since_hours > 0 else None

    def _request(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{self._host}{path}",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {self._auth}",
            },
        )
        with urllib.request.urlopen(req, context=self._ctx, timeout=15) as resp:
            return json.loads(resp.read())

    def _search(self, query: dict) -> tuple[int, list[dict]]:
        resp = self._request(f"/{self._index}/_search", query)
        total_obj = resp.get("hits", {}).get("total", 0)
        total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj)
        samples = [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])[:3]]
        return total, samples

    def _add_time_filter(self, query: dict) -> dict:
        if self._since_iso:
            query["query"]["bool"].setdefault("filter", []).append(
                {"range": {"timestamp": {"gte": self._since_iso}}}
            )
        return query

    def validate(self, detection: Any) -> RuleResult:
        from detection_validator.normalizer.schema import ValidationStatus

        techniques = [t.full_id for t in (detection.mitre_techniques or [])]
        keywords: list[str] = []
        raw = ""

        if detection.detection_logic and detection.detection_logic.raw:
            raw = detection.detection_logic.raw
            if not techniques:
                techniques = _sigma_techniques(raw)
            keywords = _sigma_keywords(raw)

        # ── Layer 1: Sigma field-level translation ────────────────────────────
        # Most precise — evaluates the actual Sigma detection: block.
        sigma_clause = _sigma_detection_to_os_query(raw) if raw else None
        if sigma_clause:
            size = 5
            sigma_query: dict[str, Any] = {
                "size": size,
                "_source": ["timestamp", "technique", "key", "source",
                            "exe", "comm", "uid", "proctitle", "cmd_output", "vm"],
                "query": {"bool": {"must": sigma_clause}},
                "sort": [{"timestamp": {"order": "desc"}}],
            }
            if self._since_iso:
                sigma_query["query"]["bool"]["filter"] = [
                    {"range": {"timestamp": {"gte": self._since_iso}}}
                ]
            try:
                total, samples = self._search(sigma_query)
                if total > 0:
                    detection.validation_status = ValidationStatus.PASSED
                    detection.last_validated = datetime.now(tz=timezone.utc)
                    return RuleResult(
                        rule_id=str(detection.id),
                        name=detection.name,
                        techniques=techniques,
                        siem="opensearch",
                        query_desc=f"sigma-fields  techniques=[{', '.join(techniques)}]"
                                   + (f"  since={self._since_iso[:16]}" if self._since_iso else ""),
                        hit_count=total,
                        sample_events=samples,
                        status="likely_fires",
                    )
            except Exception:
                pass  # fall through to technique/keyword layers

        # ── Layer 2: technique ID match ───────────────────────────────────────
        # Strong signal — event carries the same ATT&CK technique ID as the rule.
        tech_query = _build_os_query(techniques, [], self._since_iso) if techniques else {}
        kw_query = _build_os_query([], keywords, self._since_iso) if keywords else {}

        if not tech_query and not kw_query:
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="opensearch",
                query_desc="(no techniques, keywords, or translatable detection block)",
                hit_count=0,
                status="skip",
                error="Rule has no technique IDs or keywords to match against",
            )

        base_desc = (
            f"techniques=[{', '.join(techniques)}]"
            + (f"  keywords={len(keywords)}" if keywords else "")
            + (f"  since={self._since_iso[:16]}" if self._since_iso else "  (all time)")
        )

        try:
            if tech_query:
                total, samples = self._search(tech_query)
                if total > 0:
                    detection.validation_status = ValidationStatus.PASSED
                    detection.last_validated = datetime.now(tz=timezone.utc)
                    return RuleResult(
                        rule_id=str(detection.id),
                        name=detection.name,
                        techniques=techniques,
                        siem="opensearch",
                        query_desc=base_desc,
                        hit_count=total,
                        sample_events=samples,
                        status="likely_fires",
                    )

            # ── Layer 3: keyword-overlap fallback ─────────────────────────────
            # Weaker signal — keywords from detection block appear in event text.
            if kw_query:
                total, samples = self._search(kw_query)
                if total > 0:
                    detection.validation_status = ValidationStatus.PASSED
                    detection.last_validated = datetime.now(tz=timezone.utc)
                    return RuleResult(
                        rule_id=str(detection.id),
                        name=detection.name,
                        techniques=techniques,
                        siem="opensearch",
                        query_desc=base_desc + "  [keyword-overlap]",
                        hit_count=total,
                        sample_events=samples,
                        status="keyword_partial",
                    )

            detection.validation_status = ValidationStatus.FAILED
            detection.last_validated = datetime.now(tz=timezone.utc)
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="opensearch",
                query_desc=base_desc,
                hit_count=0,
                sample_events=[],
                status="no_keyword_match",
            )
        except Exception as exc:
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="opensearch",
                query_desc=base_desc,
                hit_count=0,
                status="error",
                error=str(exc),
            )


# ── Splunk validator ──────────────────────────────────────────────────────────

class SplunkValidator:
    def __init__(
        self,
        hec_host: str = "http://localhost:8088",
        rest_host: str = "http://localhost:8089",
        token: str = "detectval-hec-token",
        since_hours: float = 24.0,
    ) -> None:
        self._rest = rest_host.rstrip("/")
        self._token = token
        since_dt = datetime.fromtimestamp(
            time.time() - since_hours * 3600, tz=timezone.utc
        )
        self._since_ts: float = since_dt.timestamp() if since_hours > 0 else 0.0

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(
            f"{self._rest}{path}",
            headers={"Authorization": f"Splunk {self._token}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def _post_search(self, search: str) -> str:
        """Submit a search job, return the sid."""
        from urllib.parse import urlencode
        body = urlencode({"search": search}).encode()
        req = urllib.request.Request(
            f"{self._rest}/services/search/jobs",
            data=body,
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read()).get("sid", "")

    def validate(self, detection: Any) -> RuleResult:
        from detection_validator.normalizer.schema import ValidationStatus

        techniques = [t.full_id for t in (detection.mitre_techniques or [])]
        keywords: list[str] = []

        if detection.detection_logic and detection.detection_logic.raw:
            raw = detection.detection_logic.raw
            if not techniques:
                techniques = _sigma_techniques(raw)
            keywords = _sigma_keywords(raw)

        # Build separate technique-only and keyword-only term lists.
        kw_tokens: list[str] = []
        for kw in keywords:
            tokens = [t for t in re.split(r"[^a-zA-Z0-9_-]", _strip_wildcards(kw)) if len(t) >= 4]
            kw_tokens.extend(tokens[:2])
        kw_tokens = list(dict.fromkeys(kw_tokens))

        if not techniques and not kw_tokens:
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="splunk",
                query_desc="(no terms to search)",
                hit_count=0,
                status="skip",
                error="No technique IDs or keywords to search",
            )

        def _splunk_search(terms: list[str]) -> tuple[int, list[dict]]:
            search_str = " OR ".join(terms)
            sid = self._post_search(search_str)
            if not sid:
                raise RuntimeError("Empty sid from search job POST")
            resp = self._get(f"/services/search/jobs/{sid}/results")
            hits = resp.get("results", [])
            if self._since_ts:
                hits = [r for r in hits if float(r.get("_time", 0)) >= self._since_ts]
            return len(hits), hits[:3]

        try:
            # Layer 2: technique-ID match (strong signal)
            if techniques:
                total, samples = _splunk_search(list(techniques))
                if total > 0:
                    detection.validation_status = ValidationStatus.PASSED
                    detection.last_validated = datetime.now(tz=timezone.utc)
                    return RuleResult(
                        rule_id=str(detection.id),
                        name=detection.name,
                        techniques=techniques,
                        siem="splunk",
                        query_desc=f"search: {' OR '.join(techniques)[:80]}",
                        hit_count=total,
                        sample_events=samples,
                        status="likely_fires",
                    )

            # Layer 3: keyword-overlap (weak signal)
            if kw_tokens:
                total, samples = _splunk_search(kw_tokens)
                if total > 0:
                    detection.validation_status = ValidationStatus.PASSED
                    detection.last_validated = datetime.now(tz=timezone.utc)
                    return RuleResult(
                        rule_id=str(detection.id),
                        name=detection.name,
                        techniques=techniques,
                        siem="splunk",
                        query_desc=f"search: {' OR '.join(kw_tokens)[:80]}  [keyword-overlap]",
                        hit_count=total,
                        sample_events=samples,
                        status="keyword_partial",
                    )

            detection.validation_status = ValidationStatus.FAILED
            detection.last_validated = datetime.now(tz=timezone.utc)
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="splunk",
                query_desc=f"search: {' OR '.join(techniques + kw_tokens)[:80]}",
                hit_count=0,
                sample_events=[],
                status="no_keyword_match",
            )
        except Exception as exc:
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="splunk",
                query_desc="(search failed)",
                hit_count=0,
                status="error",
                error=str(exc),
            )


# ── Top-level orchestrator ────────────────────────────────────────────────────

def validate_corpus(
    detections: list[Any],
    siem: str = "opensearch",
    since_hours: float = 24.0,
    os_host: str = "https://localhost:9200",
    os_user: str = "admin",
    os_pass: str = "DetectVal123!",
    os_index: str = "dv-telemetry-*",
    splunk_rest: str = "http://localhost:8089",
    splunk_hec: str = "http://localhost:8088",
    splunk_token: str = "detectval-hec-token",
) -> list[RuleResult]:
    """Validate a list of CanonicalDetection objects against the configured SIEM(s)."""
    siems = [s.strip() for s in siem.split(",")]
    results: list[RuleResult] = []

    os_validator: OpenSearchValidator | None = None
    sp_validator: SplunkValidator | None = None

    if "opensearch" in siems or "elastic" in siems:
        os_validator = OpenSearchValidator(
            host=os_host, user=os_user, password=os_pass,
            index=os_index, since_hours=since_hours,
        )
    if "splunk" in siems:
        sp_validator = SplunkValidator(
            hec_host=splunk_hec, rest_host=splunk_rest,
            token=splunk_token, since_hours=since_hours,
        )

    for det in detections:
        if os_validator:
            results.append(os_validator.validate(det))
        if sp_validator:
            results.append(sp_validator.validate(det))

    return results

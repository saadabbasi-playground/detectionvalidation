"""
Validation engine — executes detection rules against live SIEM telemetry.

Strategy (two-layer):
  1. Technique matching  — queries for events with technique IDs declared in
                           the rule's ATT&CK tags (reliable for auditd-agent events).
  2. Keyword matching    — extracts literal keywords from the rule's detection
                           section and multi-matches them across free-text fields
                           (catches real auditd proctitle/cmd_output events).

A rule PASSES if either layer returns at least one hit in the time window.
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
        host: str = "http://localhost:9200",
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

    def validate(self, detection: Any) -> RuleResult:
        from detection_validator.normalizer.schema import ValidationStatus

        # Collect techniques: prefer pre-parsed mitre_techniques, fall back to Sigma tags
        techniques = [t.full_id for t in (detection.mitre_techniques or [])]
        keywords: list[str] = []

        if detection.detection_logic and detection.detection_logic.raw:
            raw = detection.detection_logic.raw
            if not techniques:
                techniques = _sigma_techniques(raw)
            keywords = _sigma_keywords(raw)

        query = _build_os_query(techniques, keywords, self._since_iso)
        if not query:
            result = RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="opensearch",
                query_desc="(no techniques or keywords found)",
                hit_count=0,
                status="skip",
                error="Rule has no technique IDs or keywords to match against",
            )
            return result

        query_desc = (
            f"techniques=[{', '.join(techniques)}]"
            + (f"  keywords={len(keywords)}" if keywords else "")
            + (f"  since={self._since_iso[:16]}" if self._since_iso else "  (all time)")
        )

        try:
            resp = self._request(f"/{self._index}/_search", query)
            total_obj = resp.get("hits", {}).get("total", 0)
            total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj)
            samples = [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])[:3]]
            passed = total > 0

            # Persist validation status back onto the detection object
            detection.validation_status = ValidationStatus.PASSED if passed else ValidationStatus.FAILED
            detection.last_validated = datetime.now(tz=timezone.utc)

            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="opensearch",
                query_desc=query_desc,
                hit_count=total,
                sample_events=samples,
                status="pass" if passed else "fail",
            )
        except Exception as exc:
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="opensearch",
                query_desc=query_desc,
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

        # Build a simple OR search for the mock (it does raw LIKE matching)
        terms: list[str] = list(techniques)
        for kw in keywords:
            tokens = [t for t in re.split(r"[^a-zA-Z0-9_-]", _strip_wildcards(kw)) if len(t) >= 4]
            terms.extend(tokens[:2])  # cap keywords per rule to avoid huge OR chains

        terms = list(dict.fromkeys(terms))  # deduplicate
        if not terms:
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

        search_str = " OR ".join(terms)
        query_desc = f"search: {search_str[:80]}"

        try:
            sid = self._post_search(search_str)
            if not sid:
                raise RuntimeError("Empty sid from search job POST")
            resp = self._get(f"/services/search/jobs/{sid}/results")
            results = resp.get("results", [])
            # Filter by time window on client side (mock doesn't support time filter)
            if self._since_ts:
                results = [r for r in results if float(r.get("_time", 0)) >= self._since_ts]
            total = len(results)
            passed = total > 0

            detection.validation_status = ValidationStatus.PASSED if passed else ValidationStatus.FAILED
            detection.last_validated = datetime.now(tz=timezone.utc)

            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="splunk",
                query_desc=query_desc,
                hit_count=total,
                sample_events=results[:3],
                status="pass" if passed else "fail",
            )
        except Exception as exc:
            return RuleResult(
                rule_id=str(detection.id),
                name=detection.name,
                techniques=techniques,
                siem="splunk",
                query_desc=query_desc,
                hit_count=0,
                status="error",
                error=str(exc),
            )


# ── Top-level orchestrator ────────────────────────────────────────────────────

def validate_corpus(
    detections: list[Any],
    siem: str = "opensearch",
    since_hours: float = 24.0,
    os_host: str = "http://localhost:9200",
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

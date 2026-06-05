"""Offline Sigma → SIEM query compiler.

Converts a raw Sigma rule YAML to runnable queries for OpenSearch, Elasticsearch,
and Splunk using pySigma backends — no live SIEM or API keys needed.

Supported output formats
------------------------
OpenSearch:
  default       Plain Lucene query string
  monitor_rule  OpenSearch Alerting monitor (JSON) — deployable

Elasticsearch:
  default       Plain Lucene query string
  kibana_ndjson Kibana saved-search NDJSON — deployable

Splunk:
  default       Plain SPL search
  savedsearches savedsearches.conf stanza — deployable

Limitations (documented, not crashing)
---------------------------------------
- Keyword-only Sigma rules (detection.keywords without a condition field) are
  automatically normalised before parsing: condition: keywords is injected.
- Rules with logsource.category=webserver or no product use no field-mapping
  pipeline; queries come out as free-text keyword searches.
- Rules with unsupported logsource products (e.g. linux in Splunk without a
  linux pipeline) fall back to no-pipeline conversion and may produce generic
  field names. The error is reported, not raised.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ── Public types ──────────────────────────────────────────────────────────────

@dataclass
class QueryResult:
    siem: str
    fmt: str          # output format name
    query: str | None # None means conversion failed
    error: str | None = None
    deployable: bool = False


# ── Sigma normalisation ───────────────────────────────────────────────────────

def _normalise_sigma_yaml(raw: str) -> str:
    """Inject ``condition: keywords`` for keyword-only rules that omit it.

    pySigma ≥ 0.11 requires every rule to have at least one condition.
    The Sigma spec allows omitting condition when detection only has
    a keywords key, but pySigma does not implement that shortcut.
    """
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        return raw  # let pySigma report the parse error

    det = data.get("detection") if isinstance(data, dict) else None
    if isinstance(det, dict) and "keywords" in det and "condition" not in det:
        det["condition"] = "keywords"
        data["detection"] = det
        return yaml.dump(data, allow_unicode=True, default_flow_style=False)
    return raw


# ── Pipeline selection ────────────────────────────────────────────────────────

def _windows_rule(raw_yaml: str) -> bool:
    """Return True if the rule targets Windows."""
    try:
        data = yaml.safe_load(raw_yaml)
        ls = data.get("logsource", {}) if isinstance(data, dict) else {}
        return str(ls.get("product", "")).lower() == "windows"
    except Exception:
        return False


def _os_pipeline(windows: bool):
    """Return the appropriate processing pipeline for OpenSearch/Elasticsearch."""
    if windows:
        from sigma.pipelines.elasticsearch import ecs_windows
        return ecs_windows()
    return None


def _splunk_pipeline(windows: bool):
    """Return the appropriate processing pipeline for Splunk."""
    if windows:
        from sigma.pipelines.splunk import splunk_windows_pipeline
        return splunk_windows_pipeline()
    return None


# ── Per-backend converters ────────────────────────────────────────────────────

def _render(value: Any) -> str:
    """Serialise backend output to a plain string regardless of type."""
    if isinstance(value, list):
        if not value:
            return ""
        if isinstance(value[0], dict):
            # monitor_rule / kibana_ndjson → newline-delimited JSON
            return "\n".join(json.dumps(item, indent=2) for item in value)
        return "\n".join(str(v) for v in value)
    return str(value)


def _convert_opensearch(
    sc, windows: bool, deployable: bool
) -> list[QueryResult]:
    from sigma.backends.opensearch import OpensearchLuceneBackend

    pipeline = _os_pipeline(windows)
    results: list[QueryResult] = []

    # Default: Lucene string
    try:
        b = OpensearchLuceneBackend(processing_pipeline=pipeline)
        out = b.convert(sc, output_format="default")
        results.append(QueryResult(
            siem="opensearch", fmt="default", query=_render(out)
        ))
    except Exception as exc:
        results.append(QueryResult(
            siem="opensearch", fmt="default", query=None, error=str(exc)
        ))

    if deployable:
        try:
            from sigma.collection import SigmaCollection as _SC
            b2 = OpensearchLuceneBackend(processing_pipeline=_os_pipeline(windows))
            out2 = b2.convert(sc, output_format="monitor_rule")
            results.append(QueryResult(
                siem="opensearch", fmt="monitor_rule",
                query=_render(out2), deployable=True,
            ))
        except Exception as exc:
            results.append(QueryResult(
                siem="opensearch", fmt="monitor_rule",
                query=None, error=str(exc), deployable=True,
            ))

    return results


def _convert_elasticsearch(
    sc, windows: bool, deployable: bool
) -> list[QueryResult]:
    from sigma.backends.elasticsearch import LuceneBackend

    pipeline = _os_pipeline(windows)
    results: list[QueryResult] = []

    try:
        b = LuceneBackend(processing_pipeline=pipeline)
        out = b.convert(sc, output_format="default")
        results.append(QueryResult(
            siem="elastic", fmt="default", query=_render(out)
        ))
    except Exception as exc:
        results.append(QueryResult(
            siem="elastic", fmt="default", query=None, error=str(exc)
        ))

    if deployable:
        try:
            b2 = LuceneBackend(processing_pipeline=_os_pipeline(windows))
            out2 = b2.convert(sc, output_format="kibana_ndjson")
            results.append(QueryResult(
                siem="elastic", fmt="kibana_ndjson",
                query=_render(out2), deployable=True,
            ))
        except Exception as exc:
            results.append(QueryResult(
                siem="elastic", fmt="kibana_ndjson",
                query=None, error=str(exc), deployable=True,
            ))

    return results


def _convert_splunk(sc, windows: bool, deployable: bool) -> list[QueryResult]:
    from sigma.backends.splunk import SplunkBackend

    pipeline = _splunk_pipeline(windows)
    results: list[QueryResult] = []

    try:
        b = SplunkBackend(processing_pipeline=pipeline)
        out = b.convert(sc, output_format="default")
        results.append(QueryResult(
            siem="splunk", fmt="default", query=_render(out)
        ))
    except Exception as exc:
        results.append(QueryResult(
            siem="splunk", fmt="default", query=None, error=str(exc)
        ))

    if deployable:
        try:
            b2 = SplunkBackend(processing_pipeline=_splunk_pipeline(windows))
            out2 = b2.convert(sc, output_format="savedsearches")
            results.append(QueryResult(
                siem="splunk", fmt="savedsearches",
                query=_render(out2), deployable=True,
            ))
        except Exception as exc:
            results.append(QueryResult(
                siem="splunk", fmt="savedsearches",
                query=None, error=str(exc), deployable=True,
            ))

    return results


# ── Public API ────────────────────────────────────────────────────────────────

_SIEM_ALIASES = {
    "opensearch": "opensearch",
    "elastic": "elastic",
    "elasticsearch": "elastic",
    "splunk": "splunk",
}

_CONVERTERS = {
    "opensearch": _convert_opensearch,
    "elastic": _convert_elasticsearch,
    "splunk": _convert_splunk,
}


def generate_queries(
    rule_path: Path | str,
    siems: list[str] | None = None,
    deployable: bool = False,
) -> list[QueryResult]:
    """Compile a Sigma rule file to queries for one or more SIEM backends.

    Parameters
    ----------
    rule_path:
        Path to a Sigma YAML rule file.
    siems:
        List of backend names: any of ``opensearch``, ``elastic``,
        ``elasticsearch``, ``splunk``.  Defaults to all three.
    deployable:
        When True, also produce deployable artifact formats (monitor_rule,
        kibana_ndjson, savedsearches).

    Returns
    -------
    List of :class:`QueryResult` objects — one per (siem, format) pair.
    Failures are represented as results with ``query=None`` and ``error``
    set; they never raise.
    """
    from sigma.collection import SigmaCollection

    if siems is None:
        siems = ["opensearch", "elastic", "splunk"]

    normalised_siems = []
    for s in siems:
        canonical = _SIEM_ALIASES.get(s.lower())
        if canonical and canonical not in normalised_siems:
            normalised_siems.append(canonical)

    raw = Path(rule_path).read_text(encoding="utf-8")
    normalised = _normalise_sigma_yaml(raw)
    windows = _windows_rule(normalised)

    # Parse once; each converter re-parses to avoid shared state between backends.
    try:
        sc_probe = SigmaCollection.from_yaml(normalised)
    except Exception as exc:
        # If the rule itself can't be parsed at all, return errors for all siems.
        return [
            QueryResult(siem=s, fmt="default", query=None, error=str(exc))
            for s in normalised_siems
        ]

    results: list[QueryResult] = []
    for siem in normalised_siems:
        converter = _CONVERTERS[siem]
        try:
            sc = SigmaCollection.from_yaml(normalised)
            results.extend(converter(sc, windows, deployable))
        except Exception as exc:
            results.append(QueryResult(
                siem=siem, fmt="default", query=None, error=str(exc)
            ))

    return results

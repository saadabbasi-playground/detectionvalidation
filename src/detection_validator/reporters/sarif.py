"""SARIF 2.1.0 reporter — for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from pathlib import Path

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_VERSION = "0.1.0"


def build(results: list[dict]) -> dict:
    """Build a SARIF 2.1.0 document from a list of RuleResult dicts."""

    # One SARIF rule entry per unique rule_id
    seen: set[str] = set()
    sarif_rules: list[dict] = []
    for r in results:
        rid = r.get("rule_id") or r.get("name", "unknown")
        if rid in seen:
            continue
        seen.add(rid)
        techs = ", ".join(r.get("techniques") or [])
        sarif_rules.append({
            "id": rid,
            "name": r.get("name", rid),
            "shortDescription": {"text": r.get("name", rid)},
            "fullDescription": {
                "text": (
                    f"ATT&CK: {techs}. "
                    f"Query: {r.get('query', '')}."
                ) if techs else r.get("query", ""),
            },
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "tags": r.get("techniques") or [],
                "siem": r.get("siem", ""),
            },
        })

    # One SARIF result per non-covered / erroring rule
    _COVERED = {"likely_fires", "keyword_partial", "pass"}  # pass = legacy compat
    sarif_results: list[dict] = []
    for r in results:
        status = r.get("status", "no_keyword_match")
        if status in _COVERED or status == "skip":
            continue

        rid = r.get("rule_id") or r.get("name", "unknown")
        level = "error" if status == "error" else "warning"

        if status == "error":
            msg = f"Static analysis error: {r.get('error', 'unknown error')}"
        else:
            techs = ", ".join(r.get("techniques") or [])
            msg = (
                f"No keyword or technique overlap found in local telemetry. "
                f"Techniques: {techs or '(none)'}. "
                f"Query: {r.get('query', '')}."
            )

        sarif_results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": msg},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": r.get("name", rid),
                            "kind": "detection-rule",
                        }
                    ]
                }
            ],
            "properties": {
                "siem": r.get("siem", ""),
                "hit_count": r.get("hits", 0),
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "detection-validator",
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/your-org/detection-validator",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write(results: list[dict], path: Path) -> None:
    path.write_text(json.dumps(build(results), indent=2))

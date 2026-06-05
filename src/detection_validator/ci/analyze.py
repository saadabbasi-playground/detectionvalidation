"""Offline analysis pipeline for CI — no SIEM or network required.

Produces a JSON snapshot suitable for feeding into comment.render_comment().

Usage (CLI entry-point):
    python -m detection_validator.ci.analyze rules/  --output /tmp/head.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


_RULE_EXTENSIONS = (".yml", ".yaml", ".json", ".toml", ".spl", ".kql", ".yar")


def run_analysis(rules_dir: Path) -> dict:
    """Return a JSON-serialisable analysis snapshot for *rules_dir*.

    Keys
    ----
    rule_count          int
    covered_techniques  list[str]   sorted unique ATT&CK IDs
    avg_lint_score      float       0-100
    lint_results        list[dict]  [{name, path, score, findings}]
    gaps                list[dict]  [{technique_id, name, tactic, score, reasons}]
    gaps_available      bool        False when ATT&CK STIX cache is absent
    """
    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.validator.static_lint import StaticLinter

    registry = ParserRegistry()
    linter = StaticLinter()

    rule_files = sorted(
        f for f in rules_dir.rglob("*") if f.suffix in _RULE_EXTENSIONS
    )

    detections = []
    for fpath in rule_files:
        try:
            result = registry.parse_file(fpath)
            if result:
                if isinstance(result, list):
                    detections.extend(result)
                else:
                    detections.append(result)
        except Exception:
            continue

    lint_all = linter.lint_all(detections)

    lint_results: list[dict] = []
    technique_set: set[str] = set()
    score_sum = 0.0

    for det in detections:
        findings = lint_all.get(str(det.id), [])
        score = linter.score(findings)
        score_sum += score

        # Collect covered techniques
        for t in det.mitre_techniques or []:
            technique_set.add(t.full_id)

        # Fallback: parse tags from raw YAML
        if not det.mitre_techniques and det.detection_logic and det.detection_logic.raw:
            import re
            for m in re.finditer(r"attack\.(T\d{4}(?:\.\d{3})?)", det.detection_logic.raw, re.I):
                technique_set.add(m.group(1).upper())

        lint_results.append({
            "name": det.name,
            "path": str(getattr(det, "_source_path", "") or ""),
            "score": score,
            "findings": [
                {
                    "severity": str(f.severity),
                    "code": f.code,
                    "message": f.message,
                }
                for f in findings
            ],
        })

    avg_lint = round(score_sum / len(detections), 1) if detections else 0.0

    gaps, gaps_available = _run_gaps(rules_dir, list(technique_set))

    return {
        "rule_count": len(detections),
        "covered_techniques": sorted(technique_set),
        "avg_lint_score": avg_lint,
        "lint_results": lint_results,
        "gaps": gaps,
        "gaps_available": gaps_available,
    }


def _run_gaps(rules_dir: Path, covered: list[str]) -> tuple[list[dict], bool]:
    """Run gap analysis using the local ATT&CK STIX cache.

    Returns (gaps_list, gaps_available).  gaps_available is False if the
    cache is missing; in that case gaps_list is empty.
    """
    try:
        from detection_validator.intel.attack import AttackIntel
        from detection_validator.coverage.gap_analyzer import GapAnalyzer

        intel = AttackIntel()
        if not intel.is_cached():
            return [], False

        analyzer = GapAnalyzer(intel)
        gaps = analyzer.find_gaps(covered_techniques=covered)
        gaps_sorted = analyzer.prioritize(gaps)[:30]

        return [
            {
                "technique_id": g.technique_id,
                "name": g.name,
                "tactic": g.tactic,
                "score": round(g.score, 1),
                "reasons": g.reasons,
            }
            for g in gaps_sorted
        ], True

    except Exception:
        return [], False


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Run detectval analysis and write JSON snapshot."
    )
    parser.add_argument("rules_dir", help="Path to detection rules directory")
    parser.add_argument(
        "--output", "-o", default="-", help="Output path (- = stdout)"
    )
    args = parser.parse_args()

    snapshot = run_analysis(Path(args.rules_dir))
    out = json.dumps(snapshot, indent=2)

    if args.output == "-":
        print(out)
    else:
        Path(args.output).write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main()

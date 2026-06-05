"""Render a GitHub-flavored Markdown PR comment from detectval analysis snapshots.

Public API
----------
render_comment(head, base, *, min_lint_score, top_n_gaps) -> str
    Render a markdown string.  base=None means first run (no comparison).

snapshot_from_json(data: dict) -> dict
    Identity pass-through for forward-compat; caller can pass the raw dict.

Usage (CLI entry-point):
    python -m detection_validator.ci.comment \\
        --head /tmp/head.json --base /tmp/base.json --output /tmp/comment.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# HTML comment used to find/replace the PR comment across pushes.
_MARKER = "<!-- detectval-pr-comment -->"

_TACTIC_LABELS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Dev",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "C2",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


# ── Section builders ──────────────────────────────────────────────────────────


def _header(head: dict, base: dict | None) -> str:
    n = head["rule_count"]
    cov = len(head["covered_techniques"])
    avg = head["avg_lint_score"]
    avg_color = "🟢" if avg >= 70 else "🟡" if avg >= 50 else "🔴"

    cov_delta = ""
    if base is not None:
        delta = cov - len(base["covered_techniques"])
        if delta > 0:
            cov_delta = f" _(+{delta} vs. base)_"
        elif delta < 0:
            cov_delta = f" _({delta} vs. base)_"

    avg_delta = ""
    if base is not None:
        da = round(avg - base["avg_lint_score"], 1)
        if da > 0:
            avg_delta = f" _(+{da})_"
        elif da < 0:
            avg_delta = f" _({da})_"

    return (
        f"{_MARKER}\n"
        f"## 🔍 DetectVal Analysis\n\n"
        f"| Rules | ATT&CK Coverage | Avg Lint Score |\n"
        f"|---|---|---|\n"
        f"| {n} | {cov} techniques{cov_delta} | {avg_color} {avg:.0f}/100{avg_delta} |\n"
    )


def _coverage_section(head: dict, base: dict | None) -> str:
    if base is None:
        return ""

    head_set = set(head["covered_techniques"])
    base_set = set(base["covered_techniques"])
    added = sorted(head_set - base_set)
    lost = sorted(base_set - head_set)

    if not added and not lost:
        return ""

    parts = ["### 📊 Coverage Changes\n"]
    if added:
        badges = " ".join(f"`{t}`" for t in added)
        parts.append(f"**Added ({len(added)}):** {badges}\n")
    if lost:
        badges = " ".join(f"`{t}`" for t in lost)
        parts.append(f"**Lost ({len(lost)}) ⚠️:** {badges}\n")

    return "\n".join(parts) + "\n"


def _lint_section(head: dict, base: dict | None, min_score: int) -> str:
    low_rules = [r for r in head["lint_results"] if r["score"] < min_score]

    regressions: list[tuple[dict, dict]] = []
    if base is not None:
        base_by_name = {r["name"]: r for r in base["lint_results"]}
        for r in head["lint_results"]:
            prev = base_by_name.get(r["name"])
            if prev and r["score"] < prev["score"]:
                regressions.append((r, prev))

    if not low_rules and not regressions:
        return "### 🧹 Rule Quality\n\n✅ All rules pass the quality threshold.\n\n"

    parts = ["### 🧹 Rule Quality\n"]

    if regressions:
        parts.append("**Regressions vs. base:**\n")
        parts.append("| Rule | Before | After | Δ |")
        parts.append("|---|---|---|---|")
        for cur, prev in sorted(regressions, key=lambda x: x[0]["score"] - x[1]["score"]):
            delta = cur["score"] - prev["score"]
            parts.append(f"| {cur['name']} | {prev['score']} | {cur['score']} | {delta} |")
        parts.append("")

    if low_rules:
        parts.append(f"**Rules below threshold ({min_score}/100):**\n")
        parts.append("| Rule | Score | Issues |")
        parts.append("|---|---|---|")
        for r in sorted(low_rules, key=lambda x: x["score"]):
            codes = ", ".join(
                f"`{f['code']}`" for f in r["findings"] if f["severity"] in ("error", "warning")
            ) or "—"
            parts.append(f"| {r['name']} | {r['score']} | {codes} |")
        parts.append("")

    return "\n".join(parts) + "\n"


def _gaps_section(head: dict, top_n: int) -> str:
    if not head["gaps_available"]:
        return (
            "### 🗺️ Coverage Gaps\n\n"
            "ATT\\&CK KB not cached — run `dv intel update --source attack` "
            "to enable gap analysis.\n\n"
        )

    gaps = head["gaps"][:top_n]
    if not gaps:
        return "### 🗺️ Coverage Gaps\n\n✅ No high-priority gaps detected.\n\n"

    parts = [
        f"### 🗺️ Priority Gaps (top {len(gaps)})\n",
        "| Technique | Tactic | Priority | Why |",
        "|---|---|---|---|",
    ]
    for g in gaps:
        tactic = _TACTIC_LABELS.get(g["tactic"], g["tactic"])
        score = int(g["score"])
        reason = g["reasons"][0] if g["reasons"] else "—"
        parts.append(
            f"| `{g['technique_id']}` {g['name']} | {tactic} | {score}/100 | {reason} |"
        )

    return "\n".join(parts) + "\n\n"


def _footer(rules_dir: str = ".") -> str:
    return (
        "---\n"
        "<details><summary>Run locally</summary>\n\n"
        "```bash\n"
        f"dv lint {rules_dir}\n"
        f"dv ingest {rules_dir} | dv map -i - -o mapped.jsonl\n"
        "dv gaps -d mapped.jsonl --prioritize --top-n 10\n"
        "```\n\n"
        "</details>\n"
    )


# ── Public API ────────────────────────────────────────────────────────────────


def render_comment(
    head: dict,
    base: dict | None = None,
    *,
    min_lint_score: int = 70,
    top_n_gaps: int = 10,
    rules_dir: str = ".",
) -> str:
    """Return a GitHub-flavored Markdown PR comment string.

    Parameters
    ----------
    head:           Analysis snapshot for the PR branch (from analyze.run_analysis).
    base:           Analysis snapshot for the base branch, or None (no comparison).
    min_lint_score: Rules with score below this are highlighted.
    top_n_gaps:     Maximum priority gaps to show.
    rules_dir:      Path shown in the "run locally" footer snippet.
    """
    sections = [
        _header(head, base),
        _coverage_section(head, base),
        _lint_section(head, base, min_lint_score),
        _gaps_section(head, top_n_gaps),
        _footer(rules_dir),
    ]
    return "\n".join(s for s in sections if s)


# ── CLI entry-point ───────────────────────────────────────────────────────────


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Render a PR comment from detectval analysis JSON files."
    )
    parser.add_argument("--head", required=True, help="Path to head analysis JSON")
    parser.add_argument("--base", default=None, help="Path to base analysis JSON (optional)")
    parser.add_argument("--output", "-o", default="-", help="Output path (- = stdout)")
    parser.add_argument("--min-lint-score", type=int, default=70)
    parser.add_argument("--top-n-gaps", type=int, default=10)
    parser.add_argument("--rules-dir", default=".")
    args = parser.parse_args()

    head = json.loads(Path(args.head).read_text())
    base = json.loads(Path(args.base).read_text()) if args.base else None

    md = render_comment(
        head,
        base,
        min_lint_score=args.min_lint_score,
        top_n_gaps=args.top_n_gaps,
        rules_dir=args.rules_dir,
    )

    if args.output == "-":
        print(md)
    else:
        Path(args.output).write_text(md, encoding="utf-8")


if __name__ == "__main__":
    main()

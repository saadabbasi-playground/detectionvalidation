"""Comprehensive HTML reporter — one self-contained file, no external requests.

Sections
--------
1. Posture score ring (0–100, SVG arc)
2. Summary stat cards
3. ATT&CK coverage heatmap (tactic tabs, covered/partial/gap cells)
4. Prioritized gap list (from GapAnalyzer)
5. Rule quality — per-rule lint score bars + expandable findings
6. SIEM query snippets (collapsible <details> per rule, per SIEM)

Public API
----------
ReportData          — serialisable data bundle produced by gather_report_data()
RuleSummary         — per-rule lint + query data
gather_report_data  — parse rules dir, run lint + queries + gap analysis
build_full          — ReportData → HTML string
write_report        — build_full + write to path
build               — backward-compat: takes list[dict] from dv validate --format json
write               — backward-compat file writer
"""

from __future__ import annotations

import html as _html
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class RuleSummary:
    rule_id: str
    name: str
    path: str
    techniques: list[str]
    lint_score: int                 # 0–100
    lint_findings: list[dict]       # [{severity, code, message}]
    queries: dict[str, str]         # {siem: query_string} — successful only
    query_errors: dict[str, str]    # {siem: error_message}


@dataclass
class ReportData:
    generated_at: str               # ISO-8601 UTC
    rules_dir: str
    posture_score: float            # 0–100
    rules: list[RuleSummary]
    gaps: list[dict]                # serialised PriorityGap (top 30)
    covered_techniques: list[str]
    # tactic → [{id, name, covered, gap_score}]  (base techniques only)
    tactic_groups: dict[str, list[dict]]
    kb_available: bool


# ── ATT&CK metadata ────────────────────────────────────────────────────────────

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

_TACTIC_LABELS = {
    "reconnaissance":       "Reconnaissance",
    "resource-development": "Resource Dev",
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Priv. Esc.",
    "defense-evasion":      "Def. Evasion",
    "credential-access":    "Cred. Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Move.",
    "collection":           "Collection",
    "command-and-control":  "C2",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}


# ── Data gathering ─────────────────────────────────────────────────────────────

def gather_report_data(rules_dir: Path) -> ReportData:
    """Parse every Sigma YAML in *rules_dir*, lint, generate queries, gap-analyse.

    Does NOT require OpenSearch or any running service.  If the ATT&CK STIX
    cache is missing the heatmap and gap list are omitted (kb_available=False);
    run ``dv intel update --source attack`` to enable them.
    """
    from detection_validator.parsers.sigma import SigmaParser
    from detection_validator.siem.query_gen import generate_queries
    from detection_validator.validator.static_lint import StaticLinter

    parser = SigmaParser()
    linter = StaticLinter()

    rule_summaries: list[RuleSummary] = []
    covered_full: set[str] = set()   # base + sub-technique IDs
    detections = []

    for path in sorted(rules_dir.rglob("*.yml")):
        if not parser.can_parse(path):
            continue
        try:
            det = parser.parse_file(path)
        except Exception:
            continue

        detections.append(det)

        techs: list[str] = []
        for mt in (det.mitre_techniques or []):
            try:
                fid = mt.full_id
            except AttributeError:
                fid = mt.technique_id
            if fid:
                techs.append(fid)
                covered_full.add(fid)

        findings = linter.lint(det)
        score = linter.score(findings)

        queries: dict[str, str] = {}
        q_errors: dict[str, str] = {}
        try:
            for qr in generate_queries(path):
                if qr.fmt == "default":
                    if qr.query:
                        queries[qr.siem] = qr.query
                    elif qr.error:
                        q_errors[qr.siem] = qr.error
        except Exception as exc:
            q_errors["all"] = str(exc)[:200]

        try:
            rel_path = str(path.relative_to(rules_dir.parent))
        except ValueError:
            rel_path = str(path)

        rule_summaries.append(RuleSummary(
            rule_id=str(det.id),
            name=det.name,
            path=rel_path,
            techniques=techs,
            lint_score=score,
            lint_findings=[
                {"severity": str(f.severity), "code": f.code, "message": f.message}
                for f in findings
            ],
            queries=queries,
            query_errors=q_errors,
        ))

    # ── ATT&CK KB + gap analysis ───────────────────────────────────────────────
    kb_available = False
    tactic_groups: dict[str, list[dict]] = {}
    gaps: list[dict] = []

    try:
        from detection_validator.mappers.attack_mapper import (
            AttackKnowledgeBase,
            _DEFAULT_CACHE_DIR,
        )
        from detection_validator.coverage.gap_analyzer import GapAnalyzer

        kb = AttackKnowledgeBase(cache_dir=_DEFAULT_CACHE_DIR)
        if kb._bundle_path.exists():
            kb.ensure_loaded()
            kb_available = True

            covered_base = {t.split(".")[0] for t in covered_full}

            for tech in kb.get_all_techniques(include_subtechniques=False):
                tactic = tech.tactic
                tactic_groups.setdefault(tactic, []).append({
                    "id": tech.technique_id,
                    "name": tech.name,
                    # direct coverage (base technique ID exactly in covered)
                    "covered": tech.technique_id in covered_full,
                    # partial: sub-technique covered but base itself not
                    "partial": (
                        tech.technique_id not in covered_full
                        and tech.technique_id in covered_base
                    ),
                    "gap_score": 0.0,
                })
            for tac in tactic_groups:
                tactic_groups[tac].sort(key=lambda c: c["id"])

            analyzer = GapAnalyzer(kb)
            all_gaps = analyzer.analyze(detections, include_subtechniques=True)

            gap_map = {g.technique_id: g.score for g in all_gaps}
            for tac in tactic_groups:
                for cell in tactic_groups[tac]:
                    cell["gap_score"] = round(gap_map.get(cell["id"], 0.0), 1)

            gaps = [
                {
                    "technique_id": g.technique_id,
                    "name": g.name,
                    "tactic": g.tactic,
                    "score": round(g.score, 1),
                    "prevalence": g.prevalence,
                    "reasons": g.reasons[:3],
                }
                for g in all_gaps[:30]
            ]
    except Exception:
        pass

    # ── Posture score ──────────────────────────────────────────────────────────
    n = len(rule_summaries)
    avg_lint = (sum(r.lint_score for r in rule_summaries) / n) if n else 0.0
    query_pct = (sum(1 for r in rule_summaries if r.queries) / n * 100) if n else 0.0

    if kb_available:
        total_kb = sum(len(v) for v in tactic_groups.values())
        cov_pct = len(covered_full) / total_kb * 100 if total_kb else 0.0
        posture = 0.50 * cov_pct + 0.30 * avg_lint + 0.20 * query_pct
    else:
        posture = 0.70 * avg_lint + 0.30 * query_pct

    return ReportData(
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        rules_dir=str(rules_dir),
        posture_score=round(min(100.0, posture), 1),
        rules=rule_summaries,
        gaps=gaps,
        covered_techniques=sorted(covered_full),
        tactic_groups=tactic_groups,
        kb_available=kb_available,
    )


# ── HTML helpers ───────────────────────────────────────────────────────────────

def _e(s: object) -> str:
    return _html.escape(str(s))


def _score_color(score: float) -> str:
    if score >= 70:
        return "#4ade80"
    if score >= 40:
        return "#f59e0b"
    return "#f87171"


def _score_ring(score: float) -> str:
    r = 54
    circ = 2 * math.pi * r
    offset = circ * (1 - score / 100)
    color = _score_color(score)
    label = f"{score:.0f}"
    return (
        f'<svg viewBox="0 0 120 120" class="score-ring" aria-label="Posture score {label}/100">'
        f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="#1e2433" stroke-width="12"/>'
        f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="{color}" stroke-width="12"'
        f' stroke-dasharray="{circ:.2f}" stroke-dashoffset="{offset:.2f}"'
        f' transform="rotate(-90 60 60)" stroke-linecap="round"/>'
        f'<text x="60" y="55" text-anchor="middle" class="ring-num" fill="{color}">{label}</text>'
        f'<text x="60" y="72" text-anchor="middle" class="ring-lbl" fill="#94a3b8">/ 100</text>'
        f'</svg>'
    )


def _stat_cards(data: ReportData) -> str:
    n = len(data.rules)
    avg_lint = round(sum(r.lint_score for r in data.rules) / n) if n else 0
    gap_n = len(data.gaps)
    cov_n = len(data.covered_techniques)

    cards = [
        ("Total Rules",       str(n),        "#e2e8f0"),
        ("Avg Lint Score",    f"{avg_lint}",  _score_color(avg_lint)),
        ("Techniques Covered", str(cov_n),   "#60a5fa"),
        ("Priority Gaps",     str(gap_n),     "#f87171" if gap_n else "#4ade80"),
    ]
    parts = []
    for label, val, color in cards:
        parts.append(
            f'<div class="card">'
            f'<div class="num" style="color:{color}">{_e(val)}</div>'
            f'<div class="lbl">{_e(label)}</div>'
            f'</div>'
        )
    return '<div class="cards">' + "".join(parts) + "</div>"


def _heatmap_section(data: ReportData) -> str:
    if not data.kb_available:
        return (
            '<section>'
            '<h2>ATT&amp;CK Coverage Heatmap</h2>'
            '<p class="no-data">ATT&amp;CK STIX cache not found. '
            'Run <code>dv intel update --source attack</code> to enable the heatmap.</p>'
            '</section>'
        )

    ordered_tactics = [t for t in _TACTIC_ORDER if t in data.tactic_groups]
    for tac in data.tactic_groups:
        if tac not in ordered_tactics:
            ordered_tactics.append(tac)

    if not ordered_tactics:
        return ""

    tabs = []
    for i, tac in enumerate(ordered_tactics):
        label = _TACTIC_LABELS.get(tac, tac.replace("-", " ").title())
        active = ' class="tac-tab active"' if i == 0 else ' class="tac-tab"'
        tabs.append(
            f'<button{active} data-tac="{_e(tac)}" onclick="showTac(\'{_e(tac)}\')">'
            f'{_e(label)}'
            f'</button>'
        )

    panels = []
    for i, tac in enumerate(ordered_tactics):
        cells_html = []
        for cell in data.tactic_groups[tac]:
            if cell.get("covered"):
                cls = "cell-covered"
                title = "Covered"
            elif cell.get("partial"):
                cls = "cell-partial"
                title = "Sub-technique covered"
            elif cell.get("gap_score", 0) >= 60:
                cls = "cell-gap-high"
                title = f"Priority gap  score={cell['gap_score']}"
            elif cell.get("gap_score", 0) >= 30:
                cls = "cell-gap-med"
                title = f"Gap  score={cell['gap_score']}"
            else:
                cls = "cell-uncovered"
                title = "Not covered"
            short_name = cell["name"][:22] + "…" if len(cell["name"]) > 22 else cell["name"]
            cell_name = cell["name"]
            cell_id = cell["id"]
            cells_html.append(
                f'<div class="hm-cell {cls}" title="{_e(title)}: {_e(cell_name)}">'
                f'<span class="hm-tid">{_e(cell_id)}</span>'
                f'<span class="hm-name">{_e(short_name)}</span>'
                f'</div>'
            )
        display = "" if i == 0 else ' style="display:none"'
        panels.append(
            f'<div class="tac-panel" id="panel-{_e(tac)}"{display}>'
            + "".join(cells_html)
            + "</div>"
        )

    legend = (
        '<div class="hm-legend">'
        '<span class="leg-swatch cell-covered"></span> Covered &nbsp;'
        '<span class="leg-swatch cell-partial"></span> Sub-technique covered &nbsp;'
        '<span class="leg-swatch cell-gap-high"></span> High-priority gap &nbsp;'
        '<span class="leg-swatch cell-gap-med"></span> Medium gap &nbsp;'
        '<span class="leg-swatch cell-uncovered"></span> Not covered'
        '</div>'
    )

    return (
        '<section>'
        '<h2>ATT&amp;CK Coverage Heatmap</h2>'
        + legend
        + '<div class="tac-tabs">' + "".join(tabs) + "</div>"
        + '<div class="tac-panels">' + "".join(panels) + "</div>"
        + "</section>"
    )


def _gap_table(data: ReportData) -> str:
    if not data.gaps:
        return (
            '<section><h2>Prioritized Coverage Gaps</h2>'
            '<p class="no-data">No gaps found — all known ATT&amp;CK techniques are covered.</p>'
            '</section>'
        )

    rows = []
    for g in data.gaps:
        bar_w = min(100, int(g["score"]))
        bar_color = "#f87171" if g["score"] >= 60 else "#f59e0b" if g["score"] >= 30 else "#64748b"
        tactic_label = _TACTIC_LABELS.get(g["tactic"], g["tactic"])
        rows.append(
            f"<tr>"
            f'<td><code>{_e(g["technique_id"])}</code></td>'
            f'<td>{_e(g["name"])}</td>'
            f'<td><span class="badge-tactic">{_e(tactic_label)}</span></td>'
            f"<td>"
            f'<div style="display:flex;align-items:center;gap:6px">'
            f'<div class="progress-bar" style="width:80px">'
            f'<div class="progress-fill" style="width:{bar_w}%;background:{bar_color}"></div>'
            f"</div>"
            f'<span style="font-size:.8rem;color:{bar_color}">{g["score"]:.0f}</span>'
            f"</div>"
            f"</td>"
            f'<td style="text-align:right">{g["prevalence"]}</td>'
            f"</tr>"
        )

    return (
        '<section>'
        '<h2>Prioritized Coverage Gaps <span class="subtitle-hint">(top 30 by risk score)</span></h2>'
        '<table><thead><tr>'
        "<th>Technique</th><th>Name</th><th>Tactic</th><th>Priority Score</th><th style='text-align:right'>Groups+SW</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def _lint_score_bar(score: int) -> str:
    color = _score_color(score)
    return (
        f'<div style="display:flex;align-items:center;gap:6px">'
        f'<div class="progress-bar" style="width:70px">'
        f'<div class="progress-fill" style="width:{score}%;background:{color}"></div>'
        f'</div>'
        f'<span style="font-size:.8rem;color:{color};font-weight:600">{score}</span>'
        f'</div>'
    )


_SEVERITY_COLOR = {"error": "#f87171", "warning": "#fbbf24", "info": "#60a5fa"}


def _lint_table(data: ReportData) -> str:
    if not data.rules:
        return '<section><h2>Rule Quality</h2><p class="no-data">No rules found.</p></section>'

    sorted_rules = sorted(data.rules, key=lambda r: r.lint_score)
    rows = []
    for r in sorted_rules:
        techs_html = " ".join(
            f'<span class="tech">{_e(t)}</span>' for t in r.techniques
        ) or '<span style="color:#64748b">–</span>'

        findings_html = ""
        if r.lint_findings:
            f_parts = []
            for f in r.lint_findings:
                col = _SEVERITY_COLOR.get(f["severity"], "#94a3b8")
                f_parts.append(
                    f'<div style="font-size:.78rem;margin-top:4px">'
                    f'<span style="color:{col};font-weight:600">{_e(f["severity"].upper())}</span>'
                    f' <code style="color:#94a3b8">{_e(f["code"])}</code>'
                    f' {_e(f["message"])}'
                    f'</div>'
                )
            findings_html = "".join(f_parts)

        query_icons = ""
        for siem in ("opensearch", "elastic", "splunk"):
            if siem in r.queries:
                query_icons += f'<span class="siem-ok" title="{siem}">✓</span> '
            elif siem in r.query_errors:
                query_icons += f'<span class="siem-err" title="{siem}: {_e(r.query_errors[siem][:60])}">✗</span> '

        rows.append(
            f"<tr>"
            f'<td><div style="font-weight:600">{_e(r.name)}</div>'
            f'<div style="font-size:.75rem;color:#64748b;margin-top:2px">{_e(r.path)}</div>'
            f"{findings_html}</td>"
            f"<td>{techs_html}</td>"
            f"<td>{_lint_score_bar(r.lint_score)}</td>"
            f"<td>{query_icons or '—'}</td>"
            f"</tr>"
        )

    return (
        '<section>'
        '<h2>Rule Quality &amp; Lint Scores</h2>'
        '<table><thead><tr>'
        "<th>Rule</th><th>Techniques</th><th>Lint Score</th><th>SIEM Queries</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def _query_section(data: ReportData) -> str:
    rules_with_queries = [r for r in data.rules if r.queries or r.query_errors]
    if not rules_with_queries:
        return (
            '<section><h2>SIEM Query Snippets</h2>'
            '<p class="no-data">No SIEM queries generated — '
            'rules may lack logsource / detection fields (see lint scores above).</p>'
            '</section>'
        )

    parts = ['<section><h2>SIEM Query Snippets</h2>']
    for r in sorted(rules_with_queries, key=lambda x: x.name):
        query_blocks = []
        for siem in ("opensearch", "elastic", "splunk"):
            if siem in r.queries:
                q = _e(r.queries[siem])
                query_blocks.append(
                    f'<div class="query-block">'
                    f'<div class="query-header">'
                    f'<span class="siem-label">{siem}</span>'
                    f'<button class="copy-btn" onclick="copyQuery(this)">Copy</button>'
                    f'</div>'
                    f'<pre><code>{q}</code></pre>'
                    f'</div>'
                )
            elif siem in r.query_errors:
                query_blocks.append(
                    f'<div class="query-block query-err">'
                    f'<span class="siem-label">{siem}</span>'
                    f'<span class="err-msg">{_e(r.query_errors[siem][:120])}</span>'
                    f'</div>'
                )
        if query_blocks:
            techs = ", ".join(r.techniques) or "—"
            parts.append(
                f'<details class="rule-accordion">'
                f'<summary>'
                f'<span class="acc-name">{_e(r.name)}</span>'
                f'<span class="acc-techs">{_e(techs)}</span>'
                f'<span class="acc-score" style="color:{_score_color(r.lint_score)}">'
                f'lint:{r.lint_score}</span>'
                f'</summary>'
                f'<div class="acc-body">'
                + "".join(query_blocks)
                + "</div></details>"
            )
    parts.append("</section>")
    return "\n".join(parts)


# ── CSS + JS ───────────────────────────────────────────────────────────────────

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#0f1117;color:#e2e8f0;line-height:1.5;font-size:14px}
.wrap{max-width:1180px;margin:0 auto;padding:2rem 1.5rem}
header{display:flex;align-items:baseline;gap:1.5rem;margin-bottom:.5rem}
h1{font-size:1.5rem;font-weight:700}
.ts{color:#64748b;font-size:.85rem}
.rules-dir{color:#64748b;font-size:.82rem;margin-bottom:2rem}
.overview{display:flex;align-items:center;gap:2rem;margin-bottom:2.5rem;flex-wrap:wrap}
.score-ring{width:140px;height:140px;flex-shrink:0}
.ring-num{font-size:28px;font-weight:700}
.ring-lbl{font-size:11px}
.cards{display:flex;gap:1rem;flex-wrap:wrap;flex:1}
.card{background:#1e2433;border-radius:8px;padding:1.1rem 1.3rem;flex:1;min-width:120px}
.card .num{font-size:1.75rem;font-weight:700}
.card .lbl{font-size:.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}
section{margin-bottom:2.5rem}
h2{font-size:1rem;font-weight:600;margin-bottom:1rem;padding-bottom:.5rem;
   border-bottom:1px solid #2d3748;display:flex;align-items:baseline;gap:.5rem}
.subtitle-hint{font-size:.8rem;font-weight:400;color:#64748b}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:.55rem .75rem;font-size:.72rem;text-transform:uppercase;
   letter-spacing:.05em;color:#64748b;background:#1a2035;border-bottom:1px solid #2d3748}
td{padding:.55rem .75rem;border-bottom:1px solid #1e2433;vertical-align:top}
tr:hover td{background:#1e2433}
.tech{display:inline-block;background:#1e3a5f;color:#93c5fd;border-radius:4px;
      padding:.1rem .4rem;font-size:.72rem;margin:.1rem;font-family:monospace}
code{font-family:monospace;font-size:.82rem;background:#1a2035;
     padding:.1rem .35rem;border-radius:3px;color:#94a3b8}
.no-data{color:#64748b;font-style:italic;padding:2rem;text-align:center}
.progress-bar{height:7px;background:#1e2433;border-radius:4px;overflow:hidden}
.progress-fill{height:100%;background:#4ade80;border-radius:4px;transition:width .3s}
.badge-tactic{display:inline-block;background:#1e2433;color:#94a3b8;
              border-radius:4px;padding:.1rem .45rem;font-size:.72rem}
/* Heatmap */
.hm-legend{margin-bottom:.75rem;font-size:.78rem;color:#94a3b8;display:flex;
           flex-wrap:wrap;gap:.25rem .75rem;align-items:center}
.leg-swatch{display:inline-block;width:14px;height:14px;border-radius:2px;vertical-align:middle}
.tac-tabs{display:flex;flex-wrap:wrap;gap:.35rem;margin-bottom:.75rem}
.tac-tab{background:#1e2433;border:none;color:#94a3b8;padding:.35rem .7rem;
         border-radius:5px;cursor:pointer;font-size:.78rem;transition:background .15s}
.tac-tab:hover{background:#2d3748;color:#e2e8f0}
.tac-tab.active{background:#1e3a5f;color:#93c5fd;font-weight:600}
.tac-panels{}
.tac-panel{display:flex;flex-wrap:wrap;gap:5px}
.hm-cell{display:flex;flex-direction:column;width:130px;padding:5px 7px;
         border-radius:5px;cursor:default;transition:opacity .15s}
.hm-cell:hover{opacity:.85}
.hm-tid{font-family:monospace;font-size:.72rem;font-weight:600}
.hm-name{font-size:.68rem;line-height:1.3;margin-top:1px;color:rgba(255,255,255,.7)}
.cell-covered   {background:#052e16;border:1px solid #166534;color:#4ade80}
.cell-partial   {background:#2d1f00;border:1px solid #78350f;color:#fde68a}
.cell-gap-high  {background:#2d0a0a;border:1px solid #7f1d1d;color:#fca5a5}
.cell-gap-med   {background:#1c1607;border:1px solid #451a03;color:#fed7aa}
.cell-uncovered {background:#131a27;border:1px solid #1e2433;color:#475569}
/* SIEM query icons */
.siem-ok{color:#4ade80;font-weight:700;font-size:.82rem}
.siem-err{color:#f87171;font-weight:700;font-size:.82rem;cursor:help}
/* Query accordions */
.rule-accordion{background:#1a2035;border-radius:7px;margin-bottom:.5rem;
                border:1px solid #2d3748;overflow:hidden}
.rule-accordion summary{cursor:pointer;padding:.75rem 1rem;display:flex;
                         align-items:center;gap:.75rem;list-style:none}
.rule-accordion summary::-webkit-details-marker{display:none}
.rule-accordion summary::before{content:"▶";font-size:.7rem;color:#64748b;
                                 transition:transform .2s}
.rule-accordion[open] summary::before{transform:rotate(90deg)}
.acc-name{font-weight:600;flex:1}
.acc-techs{font-family:monospace;font-size:.75rem;color:#64748b}
.acc-score{font-size:.78rem;font-weight:600}
.acc-body{padding:.75rem 1rem 1rem;border-top:1px solid #2d3748}
.query-block{margin-bottom:.75rem}
.query-header{display:flex;align-items:center;justify-content:space-between;
              margin-bottom:.3rem}
.siem-label{font-size:.75rem;font-weight:600;color:#60a5fa;text-transform:uppercase}
.copy-btn{background:#1e2433;border:1px solid #2d3748;color:#94a3b8;
          padding:.2rem .55rem;border-radius:4px;cursor:pointer;font-size:.72rem;
          transition:background .15s}
.copy-btn:hover{background:#2d3748;color:#e2e8f0}
.query-block pre{background:#0d1117;border:1px solid #1e2433;border-radius:5px;
                 padding:.75rem;overflow-x:auto;font-size:.78rem;
                 color:#94a3b8;white-space:pre-wrap;word-break:break-all}
.query-block pre code{background:none;padding:0;color:inherit;font-size:inherit}
.query-err{display:flex;flex-direction:column;gap:.25rem;padding:.4rem 0}
.query-err .siem-label{margin-right:.5rem}
.err-msg{font-size:.78rem;color:#f87171}
"""

_JS = """
function showTac(tac) {
    document.querySelectorAll('.tac-panel').forEach(p => { p.style.display = 'none'; });
    document.querySelectorAll('.tac-tab').forEach(t => { t.classList.remove('active'); });
    var panel = document.getElementById('panel-' + tac);
    if (panel) panel.style.display = 'flex';
    document.querySelectorAll('.tac-tab[data-tac="' + tac + '"]').forEach(function(t) {
        t.classList.add('active');
    });
}
function copyQuery(btn) {
    var code = btn.closest('.query-block').querySelector('code');
    if (!code) return;
    navigator.clipboard.writeText(code.textContent).then(function() {
        var orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = orig; }, 2000);
    }).catch(function() {
        btn.textContent = 'Error';
    });
}
"""


# ── Main builder ───────────────────────────────────────────────────────────────

def build_full(data: ReportData) -> str:
    """Build the comprehensive HTML report from a ReportData bundle."""
    posture_note = "" if data.kb_available else " (ATT&amp;CK KB unavailable — run dv intel update)"
    overview = (
        '<div class="overview">'
        + _score_ring(data.posture_score)
        + '<div style="flex:1">'
        + f'<div style="font-size:.95rem;color:#94a3b8;margin-bottom:.5rem">Overall Posture Score{posture_note}</div>'
        + _stat_cards(data)
        + "</div></div>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Detection Posture Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Detection Posture Report</h1>
    <span class="ts">{_e(data.generated_at)}</span>
  </header>
  <div class="rules-dir">Rules: {_e(data.rules_dir)}</div>
  {overview}
  {_heatmap_section(data)}
  {_gap_table(data)}
  {_lint_table(data)}
  {_query_section(data)}
</div>
<script>{_JS}</script>
</body>
</html>"""


def write_report(data: ReportData, path: Path) -> None:
    """Write the comprehensive report to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_full(data), encoding="utf-8")


# ── Backward-compatible API (used by existing `dv report --format html`) ──────

_BADGE_LABEL = {
    # Current three-tier statuses (matcher.py / engine.py)
    "condition_match":  ("likely-fires",     "CONDITION_MATCH"),
    "technique_only":   ("keyword-partial",  "TECHNIQUE_ONLY"),
    "keyword_only":     ("keyword-partial",  "KEYWORD_ONLY"),
    "no_match":         ("no-keyword-match", "NO_MATCH"),
    "untranslatable":   ("skip",             "UNTRANSLATABLE"),
    "error":            ("error",            "ERROR"),
    "skip":             ("skip",             "SKIP"),
    # Legacy aliases kept for backward compatibility
    "likely_fires":     ("likely-fires",     "LIKELY FIRES"),
    "keyword_partial":  ("keyword-partial",  "KEYWORD PARTIAL"),
    "no_keyword_match": ("no-keyword-match", "NO KEYWORD MATCH"),
    "pass":             ("pass",             "PASS"),
    "fail":             ("fail",             "FAIL"),
}

_BC_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#0f1117;color:#e2e8f0;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}
h1{font-size:1.6rem;font-weight:700;margin-bottom:.25rem}
.subtitle{color:#94a3b8;font-size:.9rem;margin-bottom:2rem}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
.card{background:#1e2433;border-radius:8px;padding:1.25rem 1.5rem;flex:1;min-width:140px}
.card .num{font-size:2rem;font-weight:700}
.card .lbl{font-size:.8rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
section{margin-bottom:2.5rem}
h2{font-size:1.1rem;font-weight:600;margin-bottom:1rem;padding-bottom:.5rem;border-bottom:1px solid #2d3748}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{text-align:left;padding:.6rem .75rem;font-size:.75rem;text-transform:uppercase;
   letter-spacing:.05em;color:#64748b;background:#1a2035;border-bottom:1px solid #2d3748}
td{padding:.6rem .75rem;border-bottom:1px solid #1e2433;vertical-align:top}
tr:hover td{background:#1e2433}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:9999px;font-size:.75rem;font-weight:600}
.badge-likely-fires{background:#052e16;color:#4ade80}
.badge-keyword-partial{background:#2d2200;color:#fde68a}
.badge-no-keyword-match{background:#2d0a0a;color:#f87171}
.badge-error{background:#2d1f00;color:#fbbf24}
.badge-skip{background:#1a2035;color:#64748b}
.badge-pass{background:#052e16;color:#4ade80}
.badge-fail{background:#2d0a0a;color:#f87171}
.tech{display:inline-block;background:#1e3a5f;color:#93c5fd;border-radius:4px;
      padding:.1rem .4rem;font-size:.75rem;margin:.1rem;font-family:monospace}
.snippet{font-family:monospace;font-size:.78rem;color:#94a3b8;white-space:pre-wrap;word-break:break-all}
.progress-bar{height:6px;background:#1e2433;border-radius:3px;overflow:hidden;margin-top:4px}
.progress-fill{height:100%;background:#4ade80;border-radius:3px}
.no-data{color:#64748b;font-style:italic;text-align:center;padding:2rem}
"""


def build(results: list[dict]) -> str:
    """Backward-compatible builder used by ``dv report --format html``.

    Takes the ``list[dict]`` produced by ``dv validate --format json``.
    """
    _COVERED = {"condition_match", "likely_fires", "keyword_partial", "pass"}
    _FAILED  = {"no_match", "technique_only", "keyword_only", "no_keyword_match", "fail"}
    passed  = [r for r in results if r.get("status") in _COVERED]
    failed  = [r for r in results if r.get("status") in _FAILED]
    errors  = [r for r in results if r.get("status") == "error"]
    total   = len(results)
    pass_pct = round(len(passed) / total * 100) if total else 0

    covered: set[str] = set()
    for r in passed:
        covered.update(r.get("techniques") or [])
    all_techs: set[str] = set()
    for r in results:
        all_techs.update(r.get("techniques") or [])

    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for r in results:
        status = r.get("status", "fail")
        css, label = _BADGE_LABEL.get(status, (status, status.upper()))
        techs_html = " ".join(
            f'<span class="tech">{_e(t)}</span>'
            for t in (r.get("techniques") or [])
        )
        sample = ""
        for ev in (r.get("samples") or [])[:1]:
            snippet = (
                ev.get("proctitle") or ev.get("cmd_output") or
                ev.get("technique") or ev.get("key") or ""
            )
            if snippet:
                sample = f'<div class="snippet">{_e(str(snippet)[:120])}</div>'
        err_html = ""
        if r.get("error"):
            err_html = (
                f'<div class="snippet" style="color:#fbbf24">'
                f'{_e(str(r["error"])[:120])}</div>'
            )
        rows.append(
            f"<tr>"
            f"<td>{_e(r.get('name') or r.get('rule_id', '?'))}{sample}{err_html}</td>"
            f"<td>{techs_html}</td>"
            f"<td>{_e(r.get('siem', ''))}</td>"
            f"<td style='text-align:right'>"
            f"{r.get('hits', 0) if status not in ('error', 'skip') else '-'}</td>"
            f'<td><span class="badge badge-{css}">{label}</span></td>'
            f"</tr>"
        )

    # tactic coverage
    tactic_map: dict[str, dict] = {}
    for tid in all_techs:
        tac = tid.split(".")[0]
        tactic_map.setdefault(tac, {"covered": set(), "total": set()})
        tactic_map[tac]["total"].add(tid)
        if tid in covered:
            tactic_map[tac]["covered"].add(tid)

    tactic_rows = []
    for tac, d in sorted(tactic_map.items()):
        nc, nt = len(d["covered"]), len(d["total"])
        pct = round(nc / nt * 100) if nt else 0
        tactic_rows.append(
            f"<tr><td>{_e(tac)}</td><td>{nc}/{nt}</td>"
            f"<td style='min-width:120px'>"
            f"<div class='progress-bar'><div class='progress-fill' style='width:{pct}%'></div></div>"
            f"</td></tr>"
        )

    tac_sec = (
        "<table><thead><tr><th>Tactic</th><th>Coverage</th><th>Progress</th></tr></thead><tbody>"
        + "".join(tactic_rows) + "</tbody></table>"
        if tactic_rows else '<p class="no-data">No technique data</p>'
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Detection Validation Report</title>
<style>{_BC_CSS}</style>
</head><body><div class="wrap">
<h1>Detection Validation Report</h1>
<p class="subtitle">Generated {generated}</p>
<div class="cards">
  <div class="card"><div class="num">{total}</div><div class="lbl">Rules</div></div>
  <div class="card"><div class="num" style="color:#4ade80">{len(passed)}</div><div class="lbl">Pass</div></div>
  <div class="card"><div class="num" style="color:#f87171">{len(failed)}</div><div class="lbl">Fail</div></div>
  <div class="card"><div class="num" style="color:#fbbf24">{len(errors)}</div><div class="lbl">Error</div></div>
  <div class="card"><div class="num" style="color:#4ade80">{pass_pct}%</div><div class="lbl">Pass rate</div></div>
  <div class="card"><div class="num" style="color:#4ade80">{len(covered)}</div><div class="lbl">Techniques covered</div></div>
</div>
<section><h2>Results</h2>
{"<table><thead><tr><th>Rule</th><th>Techniques</th><th>SIEM</th><th style='text-align:right'>Hits</th><th>Status</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>" if rows else '<p class="no-data">No results</p>'}
</section>
<section><h2>ATT&amp;CK Tactic Coverage</h2>{tac_sec}</section>
</div></body></html>"""


def write(results: list[dict], path: Path) -> None:
    """Backward-compatible file writer."""
    path.write_text(build(results), encoding="utf-8")

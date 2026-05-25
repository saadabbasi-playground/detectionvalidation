"""Self-contained HTML reporter — no external dependencies."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path


_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       background: #0f1117; color: #e2e8f0; line-height: 1.5; }
.wrap { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem; }
.subtitle { color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }
.cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.card { background: #1e2433; border-radius: 8px; padding: 1.25rem 1.5rem;
        flex: 1; min-width: 140px; }
.card .num { font-size: 2rem; font-weight: 700; }
.card .lbl { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase;
             letter-spacing: 0.05em; margin-top: 0.25rem; }
.pass { color: #4ade80; }
.fail { color: #f87171; }
.error { color: #fbbf24; }
.skip { color: #64748b; }
.neutral { color: #e2e8f0; }
section { margin-bottom: 2.5rem; }
h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem;
     padding-bottom: 0.5rem; border-bottom: 1px solid #2d3748; }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th { text-align: left; padding: 0.6rem 0.75rem; font-size: 0.75rem;
     text-transform: uppercase; letter-spacing: 0.05em; color: #64748b;
     background: #1a2035; border-bottom: 1px solid #2d3748; }
td { padding: 0.6rem 0.75rem; border-bottom: 1px solid #1e2433;
     vertical-align: top; }
tr:hover td { background: #1e2433; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 9999px;
         font-size: 0.75rem; font-weight: 600; }
.badge-pass { background: #052e16; color: #4ade80; }
.badge-fail { background: #2d0a0a; color: #f87171; }
.badge-error { background: #2d1f00; color: #fbbf24; }
.badge-skip { background: #1a2035; color: #64748b; }
.tech { display: inline-block; background: #1e3a5f; color: #93c5fd;
        border-radius: 4px; padding: 0.1rem 0.4rem; font-size: 0.75rem;
        margin: 0.1rem; font-family: monospace; }
.snippet { font-family: monospace; font-size: 0.78rem; color: #94a3b8;
           white-space: pre-wrap; word-break: break-all; }
.tactic-row td:first-child { font-weight: 600; }
.progress-bar { height: 6px; background: #1e2433; border-radius: 3px;
                overflow: hidden; margin-top: 4px; }
.progress-fill { height: 100%; background: #4ade80; border-radius: 3px; }
.no-data { color: #64748b; font-style: italic; text-align: center;
           padding: 2rem; }
"""

_TACTIC_NAMES = {
    "T1001": "C2", "T1003": "Credential Access", "T1005": "Collection",
    "T1027": "Defense Evasion", "T1046": "Discovery",
    "T1059": "Execution", "T1068": "Privilege Escalation",
    "T1071": "C2", "T1078": "Defense Evasion / Persistence",
    "T1090": "C2", "T1110": "Credential Access",
    "T1190": "Initial Access", "T1218": "Defense Evasion",
    "T1499": "Impact", "T1505": "Persistence",
    "T1547": "Persistence / Privilege Escalation",
    "T1552": "Credential Access", "T1574": "Persistence / Privilege Escalation",
}


def _badge(status: str) -> str:
    return f'<span class="badge badge-{status}">{status.upper()}</span>'


def _tactic_for(tid: str) -> str:
    base = tid.split(".")[0]
    return _TACTIC_NAMES.get(base, "Other")


def build(results: list[dict]) -> str:
    passed = [r for r in results if r.get("status") == "pass"]
    failed = [r for r in results if r.get("status") == "fail"]
    errors = [r for r in results if r.get("status") == "error"]
    skipped = [r for r in results if r.get("status") == "skip"]
    total = len(results)
    pass_pct = round(len(passed) / total * 100) if total else 0

    # Covered technique IDs
    covered: set[str] = set()
    for r in passed:
        covered.update(r.get("techniques") or [])

    all_techs: set[str] = set()
    for r in results:
        all_techs.update(r.get("techniques") or [])

    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── results table rows ────────────────────────────────────────────────────
    rows = []
    for r in results:
        status = r.get("status", "fail")
        techs_html = " ".join(
            f'<span class="tech">{html.escape(t)}</span>'
            for t in (r.get("techniques") or [])
        )
        sample = ""
        samples = r.get("samples") or []
        if samples:
            ev = samples[0]
            snippet = (
                ev.get("proctitle") or ev.get("cmd_output") or
                ev.get("technique") or ev.get("key") or ""
            )
            if snippet:
                sample = (
                    f'<div class="snippet">{html.escape(str(snippet)[:120])}</div>'
                )
        error_html = ""
        if r.get("error"):
            error_html = (
                f'<div class="snippet" style="color:#fbbf24">'
                f'{html.escape(str(r["error"])[:120])}</div>'
            )
        rows.append(
            f"<tr>"
            f"<td>{html.escape(r.get('name', r.get('rule_id', '?')))}"
            f"{sample}{error_html}</td>"
            f"<td>{techs_html}</td>"
            f"<td>{html.escape(r.get('siem', ''))}</td>"
            f"<td style='text-align:right'>{r.get('hits', 0) if status not in ('error','skip') else '-'}</td>"
            f"<td>{_badge(status)}</td>"
            f"</tr>"
        )

    # ── tactic coverage table ─────────────────────────────────────────────────
    tactic_map: dict[str, dict] = {}
    for tid in all_techs:
        tactic = _tactic_for(tid)
        if tactic not in tactic_map:
            tactic_map[tactic] = {"covered": set(), "total": set()}
        tactic_map[tactic]["total"].add(tid)
        if tid in covered:
            tactic_map[tactic]["covered"].add(tid)

    tactic_rows = []
    for tactic, data in sorted(tactic_map.items()):
        n_cov = len(data["covered"])
        n_tot = len(data["total"])
        pct = round(n_cov / n_tot * 100) if n_tot else 0
        tactic_rows.append(
            f"<tr class='tactic-row'>"
            f"<td>{html.escape(tactic)}</td>"
            f"<td>{n_cov}/{n_tot}</td>"
            f"<td style='min-width:120px'>"
            f"<div class='progress-bar'>"
            f"<div class='progress-fill' style='width:{pct}%'></div></div>"
            f"</td>"
            f"</tr>"
        )

    tactic_section = (
        "<table><thead><tr>"
        "<th>Tactic</th><th>Coverage</th><th>Progress</th>"
        "</tr></thead><tbody>"
        + "".join(tactic_rows)
        + "</tbody></table>"
        if tactic_rows else '<p class="no-data">No technique data</p>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Validation Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>Detection Validation Report</h1>
  <p class="subtitle">Generated {generated}</p>

  <div class="cards">
    <div class="card">
      <div class="num neutral">{total}</div>
      <div class="lbl">Rules</div>
    </div>
    <div class="card">
      <div class="num pass">{len(passed)}</div>
      <div class="lbl">Pass</div>
    </div>
    <div class="card">
      <div class="num fail">{len(failed)}</div>
      <div class="lbl">Fail</div>
    </div>
    <div class="card">
      <div class="num error">{len(errors)}</div>
      <div class="lbl">Error</div>
    </div>
    <div class="card">
      <div class="num pass">{pass_pct}%</div>
      <div class="lbl">Pass rate</div>
    </div>
    <div class="card">
      <div class="num pass">{len(covered)}</div>
      <div class="lbl">Techniques covered</div>
    </div>
  </div>

  <section>
    <h2>Results</h2>
    {"<table><thead><tr>"
     "<th>Rule</th><th>Techniques</th><th>SIEM</th>"
     "<th style='text-align:right'>Hits</th><th>Status</th>"
     "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
     if rows else '<p class="no-data">No results</p>'}
  </section>

  <section>
    <h2>ATT&amp;CK Tactic Coverage</h2>
    {tactic_section}
  </section>
</div>
</body>
</html>"""


def write(results: list[dict], path: Path) -> None:
    path.write_text(build(results), encoding="utf-8")

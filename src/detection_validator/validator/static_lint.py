"""Static linter — structural quality checks for detection rules.

Checks performed (and their score deductions):
  DV-L001  Missing ATT&CK tag           -20  (error)
  DV-L002  Missing logsource             -15  (warning)
  DV-L003  No detection fields           -25  (error)
  DV-L004  Missing condition             -20  (error)
  DV-L005  Overly broad wildcard         -10  (warning, capped at -15 total)
  DV-L006  Network-only rule             info  (no deduction — NETWORK_RULE label)
  DV-L007  Behavioural baseline rule     info  (no deduction — BEHAVIOURAL_RULE label)

Final score = max(0, 100 - sum(deductions)).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

from detection_validator.validator.linter import DetectionLinter, LintFinding, LintSeverity


# ── Scoring weights ────────────────────────────────────────────────────────────

_DEDUCTIONS: dict[str, int] = {
    "DV-L001": 20,   # no ATT&CK tag
    "DV-L002": 15,   # no logsource
    "DV-L003": 25,   # no detection fields
    "DV-L004": 20,   # no condition
    "DV-L005": 10,   # overly broad wildcard (per occurrence, max 15 total)
}

# Wildcards that are considered "overly broad" when they appear as a full value.
_BROAD_WILDCARD_RE = re.compile(r"^\*+$|^\?+$|^\*\w{1,2}\*$")

# logsource categories that signal a network-layer rule
_NETWORK_CATEGORIES = {"dns", "proxy", "firewall", "network", "web", "http"}

# Keywords in rule name/description that suggest a behavioural/baseline rule
_BEHAVIOURAL_PATTERNS = re.compile(
    r"\b(baseline|behaviour|behavioral|anomal|deviation|threshold|spike|unusual)\b",
    re.I,
)


class StaticLinter(DetectionLinter):
    """Concrete static linter for CanonicalDetection objects."""

    def lint(self, rule) -> list[LintFinding]:
        findings: list[LintFinding] = []
        rid = str(rule.id)

        # ── DV-L001: Missing ATT&CK tag ───────────────────────────────────────
        has_attack_tag = bool(rule.mitre_techniques)
        if not has_attack_tag:
            # Also check raw detection logic for attack.TXXXX tags
            raw = _raw(rule)
            if raw and re.search(r"attack\.T\d{4}", raw, re.I):
                has_attack_tag = True
        if not has_attack_tag:
            findings.append(LintFinding(
                rule_id=rid,
                severity=LintSeverity.ERROR,
                code="DV-L001",
                message="No ATT&CK technique tag found; rule cannot be mapped to a tactic.",
            ))

        # Parse raw YAML once for the remaining checks (Sigma-specific)
        raw = _raw(rule)
        parsed: dict = {}
        if raw:
            try:
                parsed = yaml.safe_load(raw) or {}
            except yaml.YAMLError:
                pass

        # ── DV-L002: Missing logsource ────────────────────────────────────────
        logsource = parsed.get("logsource") or {}
        if raw and not logsource:
            findings.append(LintFinding(
                rule_id=rid,
                severity=LintSeverity.WARNING,
                code="DV-L002",
                message="No logsource block; rule cannot be scoped to a data source.",
            ))

        # ── DV-L003 / DV-L004: detection block checks ─────────────────────────
        detection_block = parsed.get("detection") or {}
        if raw and not detection_block:
            findings.append(LintFinding(
                rule_id=rid,
                severity=LintSeverity.ERROR,
                code="DV-L003",
                message="No detection block; rule has no matching logic.",
            ))
        else:
            condition = detection_block.get("condition", "")
            if raw and not condition:
                findings.append(LintFinding(
                    rule_id=rid,
                    severity=LintSeverity.ERROR,
                    code="DV-L004",
                    message="detection block has no condition; rule will never evaluate.",
                ))

            # ── DV-L005: Overly broad wildcards ───────────────────────────────
            wildcard_count = 0
            for key, val in detection_block.items():
                if key in ("condition", "keywords"):
                    continue
                for v in _iter_values(val):
                    sv = str(v).strip()
                    if _BROAD_WILDCARD_RE.match(sv):
                        wildcard_count += 1
                        if wildcard_count <= 2:   # report at most 2 individual findings
                            findings.append(LintFinding(
                                rule_id=rid,
                                severity=LintSeverity.WARNING,
                                code="DV-L005",
                                message=f"Overly broad wildcard value {sv!r} in detection field.",
                            ))

        # ── DV-L006: Network-only rule (NETWORK_RULE) ─────────────────────────
        ls_category = str(logsource.get("category", "")).lower()
        ls_product  = str(logsource.get("product", "")).lower()
        if ls_category in _NETWORK_CATEGORIES or ls_product in _NETWORK_CATEGORIES:
            findings.append(LintFinding(
                rule_id=rid,
                severity=LintSeverity.INFO,
                code="NETWORK_RULE",
                message="Rule targets network telemetry; lab corpus may not cover this source.",
            ))

        # ── DV-L007: Behavioural / baseline rule (BEHAVIOURAL_RULE) ──────────
        rule_text = f"{rule.name} {rule.description or ''}"
        if _BEHAVIOURAL_PATTERNS.search(rule_text):
            findings.append(LintFinding(
                rule_id=rid,
                severity=LintSeverity.INFO,
                code="BEHAVIOURAL_RULE",
                message="Rule appears to rely on baseline/behavioural analysis; "
                        "static keyword matching will not confirm it.",
            ))

        return findings

    def score(self, findings: list[LintFinding]) -> int:
        """Return a 0-100 quality score for a rule given its lint findings."""
        deduction = 0
        wildcard_deduction = 0
        for f in findings:
            if f.code == "DV-L005":
                wildcard_deduction = min(wildcard_deduction + _DEDUCTIONS["DV-L005"], 15)
            elif f.code in _DEDUCTIONS:
                deduction += _DEDUCTIONS[f.code]
        return max(0, 100 - deduction - wildcard_deduction)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _raw(rule) -> str:
    """Extract raw YAML string from a CanonicalDetection, if available."""
    try:
        logic = rule.detection_logic
        if logic and logic.raw:
            return logic.raw
    except AttributeError:
        pass
    return ""


def _iter_values(val) -> list:
    """Flatten a detection field value (dict, list, or scalar) into a flat list."""
    if isinstance(val, dict):
        out = []
        for v in val.values():
            out.extend(_iter_values(v))
        return out
    if isinstance(val, list):
        out = []
        for item in val:
            out.extend(_iter_values(item))
        return out
    return [val]

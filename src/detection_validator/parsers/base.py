"""
Base parser ABC and shared utilities used by all format-specific parsers.

Every concrete parser must subclass ``BaseParser`` and implement the three
abstract methods.  Helper methods (normalisation, AST building) are provided
here so implementations stay thin.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from detection_validator.normalizer.schema import (
    ASTNode,
    CanonicalDetection,
    CVEReference,
    DetectionLogic,
    LogSource,
    MitreTechnique,
    Severity,
)


# ─── Exceptions ───────────────────────────────────────────────────────────────

class ParseError(Exception):
    """Raised when a parser cannot produce a valid CanonicalDetection."""

    def __init__(self, message: str, path: Path | None = None, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.path = path
        self.cause = cause

    def __str__(self) -> str:
        loc = f" [{self.path}]" if self.path else ""
        cause = f" — caused by: {self.cause}" if self.cause else ""
        return f"{super().__str__()}{loc}{cause}"


class PartialParseWarning(UserWarning):
    """Emitted when a rule is parsed but some fields could not be extracted."""


# ─── Normalisation helpers ────────────────────────────────────────────────────

# Matches T1234 or T1234.567 optionally prefixed with "attack."
_TECH_RE = re.compile(
    r"(?:attack\.)?[Tt](\d{4})(?:\.(\d{3}))?(?!\d)",
    re.IGNORECASE,
)
# Matches CVE-YYYY-NNNN+ in any separator style (-, ., _)
_CVE_RE = re.compile(r"CVE[-._](\d{4})[-._](\d{4,})", re.IGNORECASE)
# Matches tactic slugs (attack.ta0002 or bare tactic names)
_TACTIC_RE = re.compile(r"(?:attack\.)?[Tt][Aa]\d{4}", re.IGNORECASE)

# Known tactic slugs → canonical form used in MitreTechnique.tactic
_TACTIC_SLUG_MAP: dict[str, str] = {
    "initial-access": "initial-access",
    "initial_access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege-escalation",
    "privilege_escalation": "privilege-escalation",
    "defense-evasion": "defense-evasion",
    "defense_evasion": "defense-evasion",
    "credential-access": "credential-access",
    "credential_access": "credential-access",
    "discovery": "discovery",
    "lateral-movement": "lateral-movement",
    "lateral_movement": "lateral-movement",
    "collection": "collection",
    "command-and-control": "command-and-control",
    "command_and_control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "reconnaissance": "reconnaissance",
    "resource-development": "resource-development",
    "resource_development": "resource-development",
}

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MED,
    "med": Severity.MED,
    "moderate": Severity.MED,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "minimal": Severity.INFO,
    "notice": Severity.INFO,
    "unknown": Severity.MED,
}


def normalise_technique_id(raw: str) -> str | None:
    """
    Convert any technique-like string to canonical ``T1234`` or ``T1234.567``.

    Returns None if *raw* does not look like an ATT&CK technique.
    Ignores tactic IDs (TA0002).
    """
    raw = raw.strip()
    if _TACTIC_RE.fullmatch(raw):
        return None  # skip tactic IDs
    m = _TECH_RE.search(raw)
    if not m:
        return None
    base = f"T{m.group(1)}"
    return f"{base}.{m.group(2)}" if m.group(2) else base


def normalise_cve_id(raw: str) -> str | None:
    """
    Convert any CVE-like string to canonical ``CVE-YYYY-NNNNN`` form.

    Handles Sigma tag format (``cve.2021.44228``), dashes, dots, underscores.
    Returns None if no CVE pattern is found.
    """
    m = _CVE_RE.search(raw)
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def normalise_severity(raw: str | None, default: Severity = Severity.MED) -> Severity:
    """Map a raw severity string to ``Severity``; returns *default* if unknown."""
    if raw is None:
        return default
    return _SEVERITY_MAP.get(raw.strip().lower(), default)


def extract_techniques_from_text(text: str) -> list[str]:
    """
    Scan *text* for ATT&CK technique IDs (T1234 / T1234.567).

    Returns a deduplicated list in insertion order.
    """
    seen: dict[str, None] = {}
    for raw in _TECH_RE.findall(text):
        # findall returns tuples of groups
        base, sub = raw if isinstance(raw, tuple) else (raw, "")
        canonical = f"T{base}.{sub}" if sub else f"T{base}"
        seen[canonical] = None
    return list(seen)


def extract_cves_from_text(text: str) -> list[str]:
    """Scan *text* for CVE IDs and return canonical forms, deduplicated."""
    seen: dict[str, None] = {}
    for m in _CVE_RE.finditer(text):
        seen[f"CVE-{m.group(1)}-{m.group(2)}"] = None
    return list(seen)


def techniques_to_models(
    technique_ids: list[str],
    tactic: str = "unknown",
    confidence: float = 0.8,
) -> list[MitreTechnique]:
    """Convert a list of technique ID strings to ``MitreTechnique`` models."""
    out: list[MitreTechnique] = []
    for tid in technique_ids:
        canon = normalise_technique_id(tid)
        if not canon:
            continue
        if "." in canon:
            base, sub = canon.split(".", 1)
            out.append(MitreTechnique(
                technique_id=base,
                sub_technique_id=canon,
                tactic=tactic,
                confidence=confidence,
            ))
        else:
            out.append(MitreTechnique(
                technique_id=canon,
                tactic=tactic,
                confidence=confidence,
            ))
    return out


def cves_to_models(cve_ids: list[str], confidence: float = 0.9) -> list[CVEReference]:
    """Convert a list of CVE ID strings to ``CVEReference`` models."""
    out: list[CVEReference] = []
    for raw in cve_ids:
        canon = normalise_cve_id(raw)
        if canon:
            out.append(CVEReference(cve_id=canon, confidence=confidence))
    return out


def make_detection_logic(
    raw: str,
    language: str | None = None,
    field_refs: list[str] | None = None,
    conditions: list[str] | None = None,
    ast: ASTNode | None = None,
) -> DetectionLogic:
    return DetectionLogic(
        raw=raw,
        language=language,
        ast=ast,
        normalized_conditions=conditions or [],
        field_references=sorted(set(field_refs or [])),
    )


# ─── BaseParser ───────────────────────────────────────────────────────────────

class BaseParser(ABC):
    """
    Abstract base for all detection rule parsers.

    Subclasses must implement ``can_parse``, ``parse``, and should declare
    ``name`` and ``supported_extensions`` as class attributes.
    """

    #: Human-readable parser name used in logging and registry output
    name: str = "base"

    #: File extensions this parser handles (lower-case, with leading dot)
    supported_extensions: tuple[str, ...] = ()

    # ── Abstract interface ────────────────────────────────────────────────────

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Return True if this parser is the right choice for *file_path*.

        May read the file for content sniffing; should be fast and not raise.
        """

    @abstractmethod
    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        """
        Parse *content* and return a ``CanonicalDetection``.

        *source_path* is provided for context (file name in error messages,
        deriving the rule ID from the file stem, etc.) but the implementation
        must not require it.

        Raises ``ParseError`` on unrecoverable parse failures.
        """

    # ── Default implementation ────────────────────────────────────────────────

    def parse_file(self, path: Path) -> CanonicalDetection:
        """Read *path* and call ``parse(content, source_path=path)``."""
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = path.read_text(encoding="latin-1")
        except OSError as exc:
            raise ParseError(f"Cannot read file", path=path, cause=exc) from exc
        return self.parse(content, source_path=path)

    # ── Shared helpers (available to all subclasses) ──────────────────────────

    @staticmethod
    def _norm_technique(raw: str) -> str | None:
        return normalise_technique_id(raw)

    @staticmethod
    def _norm_cve(raw: str) -> str | None:
        return normalise_cve_id(raw)

    @staticmethod
    def _norm_severity(raw: str | None) -> Severity:
        return normalise_severity(raw)

    @staticmethod
    def _make_logic(
        raw: str,
        language: str | None = None,
        field_refs: list[str] | None = None,
        conditions: list[str] | None = None,
        ast: ASTNode | None = None,
    ) -> DetectionLogic:
        return make_detection_logic(raw, language, field_refs, conditions, ast)

    @staticmethod
    def _techniques(
        ids: list[str], tactic: str = "unknown", confidence: float = 0.8
    ) -> list[MitreTechnique]:
        return techniques_to_models(ids, tactic, confidence)

    @staticmethod
    def _cves(ids: list[str]) -> list[CVEReference]:
        return cves_to_models(ids)

    def _sniff(self, path: Path, markers: list[str], required_all: bool = False) -> bool:
        """
        Quick content-sniff: return True if *markers* appear in the file.

        Reads only the first 8 KB to keep detection fast.
        If *required_all* is True, every marker must be present.
        """
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
        except OSError:
            return False
        if required_all:
            return all(m in head for m in markers)
        return any(m in head for m in markers)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

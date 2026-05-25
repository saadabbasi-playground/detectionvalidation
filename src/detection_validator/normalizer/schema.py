"""
Canonical detection rule schema — universal intermediate representation.

All parsers produce a ``CanonicalDetection``; all exporters consume one.
This single model is the stable API contract between every pipeline stage.

Schema versioning
-----------------
* ``VERSION`` is bumped for every breaking change.
* Snapshot modules live in ``normalizer/migrations/v{major}_{minor}.py``.
* ``CanonicalDetection.json_schema()`` embeds ``x-schema-version`` for tooling.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ─── Schema version ──────────────────────────────────────────────────────────

VERSION: str = "1.0"
SCHEMA_URI: str = "https://detection-validator.io/schemas/canonical-detection/1.0"


# ─── Enumerations ─────────────────────────────────────────────────────────────

class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MED = "med"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionFormat(StrEnum):
    SIGMA = "sigma"
    SPLUNK_SPL = "splunk-spl"
    KQL = "kql"
    YARA = "yara"
    ELASTIC_EQL = "elastic-eql"
    SNORT = "snort"
    SURICATA = "suricata"
    CUSTOM = "custom"
    # Legacy aliases kept for backward compatibility with old DetectionRule callers
    SPL = "spl"          # noqa: PIE796 – intentional alias
    ES_QUERY = "es-query"
    YARA_L = "yara-l"
    UNKNOWN = "unknown"


class Platform(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CLOUD = "cloud"
    NETWORK = "network"
    CONTAINERS = "containers"


class ValidationStatus(StrEnum):
    UNTESTED = "untested"
    PASSED = "passed"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


class DeploymentStatus(StrEnum):
    DEPLOYED = "deployed"
    DISABLED = "disabled"
    ARCHIVED = "archived"
    FAILED = "failed"


class DetectionTestType(StrEnum):
    """Test execution mode for ValidationResult.  Named to avoid pytest collection."""

    ATOMIC_RED_TEAM = "atomic_red_team"
    SYNTHETIC = "synthetic"
    LINTER = "linter"


# Aliases — keep callers using the old names working
ValidationType = DetectionTestType
TestType = DetectionTestType


class LegacySeverity(StrEnum):
    """Severity enum for the backward-compatible DetectionRule model."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ─── Sub-models ───────────────────────────────────────────────────────────────

class LogSource(BaseModel):
    """Structured log-source reference (Sigma-style)."""

    model_config = ConfigDict(populate_by_name=True)

    product: str | None = Field(None, examples=["windows", "aws", "linux", "zeek"])
    category: str | None = Field(None, examples=["process_creation", "network_connection", "dns"])
    service: str | None = Field(None, examples=["security", "sysmon", "system"])
    definition: str | None = Field(None, description="Custom log-source definition override")

    @model_validator(mode="after")
    def _at_least_one(self) -> "LogSource":
        if not any([self.product, self.category, self.service, self.definition]):
            raise ValueError(
                "LogSource must specify at least one of: product, category, service, definition"
            )
        return self


class ASTNode(BaseModel):
    """
    Node in a parsed detection-logic abstract syntax tree.

    Supports recursive composition; call ``ASTNode.model_rebuild()`` after class
    definition (done at module level below).
    """

    model_config = ConfigDict(populate_by_name=True)

    node_type: str = Field(
        ...,
        description=(
            "condition | field_match | conjunction | disjunction | "
            "negation | near | sequence | literal"
        ),
    )
    field_name: str | None = None
    operator: str | None = Field(
        None,
        description="eq | contains | startswith | endswith | re | exists | gt | lt | cidr",
    )
    value: str | list[str] | int | float | None = None
    modifiers: list[str] = Field(default_factory=list, examples=[["contains|all"], ["base64"]])
    children: list["ASTNode"] = Field(default_factory=list)


# Forward-reference resolution for the recursive model.
ASTNode.model_rebuild()


class DetectionLogic(BaseModel):
    """Raw query string with an optional structured AST."""

    model_config = ConfigDict(populate_by_name=True)

    raw: str = Field(..., description="Raw query string in its source language")
    language: str | None = Field(
        None,
        description="Query language; mirrors source_format when omitted",
    )
    ast: ASTNode | None = Field(
        None,
        description="Parsed abstract syntax tree — populated by the parser, None until parsed",
    )
    normalized_conditions: list[str] = Field(
        default_factory=list,
        description="Human-readable summary of each top-level condition branch",
    )
    field_references: list[str] = Field(
        default_factory=list,
        description="Flat list of every field name referenced in the query",
    )


class MitreTechnique(BaseModel):
    """ATT&CK technique reference with confidence weighting."""

    model_config = ConfigDict(populate_by_name=True)

    technique_id: str = Field(
        ...,
        pattern=r"^T\d{4}$",
        description="Base technique ID, e.g. T1059",
        examples=["T1059", "T1078"],
    )
    sub_technique_id: str | None = Field(
        None,
        pattern=r"^T\d{4}\.\d{3}$",
        description="Sub-technique ID, e.g. T1059.001",
        examples=["T1059.001"],
    )
    tactic: str = Field(
        ...,
        description="ATT&CK tactic slug, e.g. execution, persistence, lateral-movement",
        examples=["execution", "persistence", "defense-evasion"],
    )
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(
        default=1.0,
        description="How confident the mapping is (0 = guess, 1 = certain)",
    )
    name: str | None = Field(None, description="Human-readable technique name (enriched from ATT&CK intel)")
    url: str | None = Field(None, description="MITRE ATT&CK technique URL")

    @property
    def full_id(self) -> str:
        """Return sub-technique ID if present, else base technique ID."""
        return self.sub_technique_id or self.technique_id


class CVEReference(BaseModel):
    """CVE / NVD reference with confidence and optional CVSS enrichment."""

    model_config = ConfigDict(populate_by_name=True)

    cve_id: str = Field(
        ...,
        pattern=r"^CVE-\d{4}-\d{4,}$",
        description="CVE identifier, e.g. CVE-2021-44228",
        examples=["CVE-2021-44228", "CVE-2022-30190"],
    )
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(
        default=1.0,
        description="How confident the CVE-to-detection mapping is",
    )
    cvss_score: Annotated[float, Field(ge=0.0, le=10.0)] | None = None
    description: str | None = None


class DeploymentRecord(BaseModel):
    """Audit record for a single rule deployment event on a SIEM backend."""

    model_config = ConfigDict(populate_by_name=True)

    backend: str = Field(..., description="Backend name, e.g. splunk, opensearch, sentinel")
    deployed_at: datetime
    rule_version: str = Field(..., description="Rule semver at time of deployment")
    status: DeploymentStatus = DeploymentStatus.DEPLOYED
    deployed_by: str | None = Field(None, description="User or CI identity that triggered the deploy")
    commit_sha: str | None = Field(None, description="Git commit SHA of the rule at deploy time")
    backend_rule_id: str | None = Field(
        None, description="ID assigned by the backend after successful deployment"
    )
    notes: str | None = None


# ─── DeTT&CT-inspired maturity rubric ────────────────────────────────────────

MATURITY_RUBRIC: dict[int, str] = {
    0: "No detection / placeholder — rule exists in name only",
    1: "Untested — broad query filed, high false-positive risk, no review",
    2: "Basic — query narrowed, false-positive notes documented, linting passes",
    3: "Moderate — validated with synthetic events, CI gate in place",
    4: "Good — validated against live ART telemetry, FP rate measured and tracked",
    5: "Excellent — continuous validation in prod, threat-intel mapped, peer reviewed",
}


# ─── CanonicalDetection ───────────────────────────────────────────────────────

class CanonicalDetection(BaseModel):
    """
    Universal intermediate representation for any detection rule.

    Schema version: 1.0  (``VERSION`` constant)

    Field groups
    ------------
    Identity      : id, name, description, author, version, created_at, modified_at
    Classification: severity, source_format, platforms, tags
    Logic         : detection_logic, log_sources
    Threat context: mitre_techniques, cve_references, data_components,
                    false_positive_notes, cim_models
    Validation    : validation_status, last_validated
    Scoring       : detection_maturity_score, portability_score
    Translations  : siem_native
    History       : deployment_history
    """

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "x-schema-version": VERSION,
            "x-schema-uri": SCHEMA_URI,
        },
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Stable UUID — set once at rule creation, never changed",
    )
    name: str = Field(..., min_length=1, description="Short, human-readable rule name")
    description: str = Field(default="", description="Full narrative of what the rule detects and why")
    author: str | list[str] = Field(
        default="",
        description="Rule author(s) — string or list of strings",
    )
    version: str = Field(default="1.0.0", description="Rule version in semver format")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of first rule creation",
    )
    modified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of last modification",
    )

    # ── Classification ────────────────────────────────────────────────────────
    severity: Severity = Field(default=Severity.MED)
    source_format: DetectionFormat = Field(
        default=DetectionFormat.CUSTOM,
        description="Originating rule format",
    )
    platforms: list[Platform] = Field(
        default_factory=list,
        description="Target OS / deployment environments",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Free-form tags, e.g. ['attack.execution', 'attack.t1059.001']",
    )

    # ── Detection logic ───────────────────────────────────────────────────────
    detection_logic: DetectionLogic = Field(
        ...,
        description="Raw query string in source language plus optional parsed AST",
    )
    log_sources: list[LogSource] = Field(
        default_factory=list,
        description="Structured log-source references (Sigma product/category/service)",
    )

    # ── Threat context ────────────────────────────────────────────────────────
    mitre_techniques: list[MitreTechnique] = Field(
        default_factory=list,
        description="ATT&CK technique / sub-technique mappings with confidence",
    )
    cve_references: list[CVEReference] = Field(
        default_factory=list,
        description="CVE IDs this rule is intended to detect",
    )
    data_components: list[str] = Field(
        default_factory=list,
        description=(
            "ATT&CK data components required, e.g. "
            "['Process Creation', 'Network Traffic Flow', 'File Modification']"
        ),
    )
    false_positive_notes: list[str] = Field(
        default_factory=list,
        description="Known legitimate scenarios that trigger this rule",
    )
    cim_models: list[str] = Field(
        default_factory=list,
        description=(
            "Splunk Common Information Model data models targeted, "
            "e.g. ['Endpoint', 'Authentication', 'Network_Traffic']"
        ),
    )

    # ── Validation state ──────────────────────────────────────────────────────
    validation_status: ValidationStatus = Field(default=ValidationStatus.UNTESTED)
    last_validated: datetime | None = Field(
        default=None,
        description="UTC timestamp of the most recent successful validation run",
    )

    # ── Scoring ───────────────────────────────────────────────────────────────
    detection_maturity_score: Annotated[int, Field(ge=0, le=5)] = Field(
        default=0,
        description=(
            "DeTT&CT-inspired maturity (0–5). "
            "See MATURITY_RUBRIC for level definitions."
        ),
    )
    portability_score: Annotated[float, Field(ge=0.0, le=100.0)] = Field(
        default=0.0,
        description=(
            "Percent of configured SIEM backends this rule successfully translates to. "
            "Computed by the deployer after attempting translation to all configured backends."
        ),
    )

    # ── Translations ──────────────────────────────────────────────────────────
    siem_native: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Translated native queries keyed by backend name. "
            "Example: {'splunk': 'index=main ...', 'opensearch': '{\"query\":...}'}"
        ),
    )

    # ── History ───────────────────────────────────────────────────────────────
    deployment_history: list[DeploymentRecord] = Field(
        default_factory=list,
        description="Ordered list of deployment events; newest entry last",
    )

    # ── Field validators ─────────────────────────────────────────────────────

    @field_validator("tags", mode="before")
    @classmethod
    def _dedup_tags(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))

    @field_validator("created_at", "modified_at", mode="before")
    @classmethod
    def _ensure_utc(cls, v: Any) -> Any:
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("detection_maturity_score", mode="before")
    @classmethod
    def _clamp_maturity(cls, v: Any) -> int:
        return max(0, min(5, int(v)))

    # ── Computed properties ───────────────────────────────────────────────────

    @property
    def primary_technique(self) -> MitreTechnique | None:
        """Highest-confidence ATT&CK technique, or None."""
        if not self.mitre_techniques:
            return None
        return max(self.mitre_techniques, key=lambda t: t.confidence)

    @property
    def maturity_label(self) -> str:
        """Human-readable maturity level description."""
        return MATURITY_RUBRIC.get(self.detection_maturity_score, "Unknown")

    @property
    def is_validated(self) -> bool:
        return self.validation_status in (ValidationStatus.PASSED, ValidationStatus.FAILED)

    @property
    def latest_deployment(self) -> DeploymentRecord | None:
        if not self.deployment_history:
            return None
        return max(self.deployment_history, key=lambda d: d.deployed_at)

    @property
    def technique_ids(self) -> list[str]:
        """Flat list of full ATT&CK IDs (sub-technique preferred over base)."""
        return [t.full_id for t in self.mitre_techniques]

    # ── JSON Schema export ────────────────────────────────────────────────────

    @classmethod
    def json_schema(cls) -> dict[str, Any]:
        """Return the JSON Schema 2020-12 document for CanonicalDetection."""
        schema = cls.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["x-schema-version"] = VERSION
        schema["x-schema-uri"] = SCHEMA_URI
        return schema

    @classmethod
    def json_schema_str(cls, indent: int = 2) -> str:
        """Return the JSON Schema as a pretty-printed string."""
        return json.dumps(cls.json_schema(), indent=indent)


# ─── CoverageEntry ────────────────────────────────────────────────────────────

class CoverageEntry(BaseModel):
    """
    Links an ATT&CK technique to the set of detections that cover it.

    Produced by the coverage matrix builder; one entry per technique.
    """

    model_config = ConfigDict(populate_by_name=True)

    technique_id: str = Field(..., pattern=r"^T\d{4}$")
    technique_name: str | None = None
    tactic: str
    sub_technique_id: str | None = Field(None, pattern=r"^T\d{4}\.\d{3}$")
    detection_ids: list[str] = Field(
        default_factory=list,
        description="IDs of CanonicalDetection records that map to this technique",
    )
    coverage_score: Annotated[float, Field(ge=0.0, le=1.0)] = Field(
        default=0.0,
        description=(
            "Fractional coverage score: "
            "0 = no detections, 1 = fully validated detections present"
        ),
    )
    detection_maturity_avg: Annotated[float, Field(ge=0.0, le=5.0)] = Field(
        default=0.0,
        description="Mean detection_maturity_score across all detections for this technique",
    )
    validated_count: int = Field(
        default=0,
        description="Number of detections with validation_status == PASSED",
    )
    data_sources_present: list[str] = Field(
        default_factory=list,
        description="Data components available in the current deployment that feed these detections",
    )
    notes: str = ""

    @property
    def is_covered(self) -> bool:
        return len(self.detection_ids) > 0

    @property
    def is_validated(self) -> bool:
        return self.validated_count > 0


# ─── Gap ─────────────────────────────────────────────────────────────────────

class Gap(BaseModel):
    """
    Represents missing detection coverage for an ATT&CK technique.

    Produced by GapAnalyzer; ordered by priority_score descending.
    """

    model_config = ConfigDict(populate_by_name=True)

    technique_id: str = Field(..., pattern=r"^T\d{4}$")
    technique_name: str | None = None
    tactic: str
    sub_technique_id: str | None = Field(None, pattern=r"^T\d{4}\.\d{3}$")
    severity: str = Field(
        ...,
        description="Gap severity: high | medium | low — derived from threat-intel frequency",
    )
    recommended_detections: list[str] = Field(
        default_factory=list,
        description=(
            "Sigma rule titles / IDs from the public rules corpus recommended to close this gap"
        ),
    )
    effort_estimate: str = Field(
        default="medium",
        description="Implementation effort to close the gap: low | medium | high",
    )
    data_sources_needed: list[str] = Field(
        default_factory=list,
        description=(
            "ATT&CK data sources / log types required before a detection can be written"
        ),
    )
    related_cves: list[str] = Field(
        default_factory=list,
        description="CVE IDs actively exploiting this technique (from threat intel)",
    )
    priority_score: Annotated[float, Field(ge=0.0, le=10.0)] = Field(
        default=5.0,
        description=(
            "Composite priority: threat_frequency × severity_weight / effort_weight. "
            "Higher = close first."
        ),
    )
    notes: str = ""


# ─── ValidationResult ────────────────────────────────────────────────────────

class ValidationResult(BaseModel):
    """
    Captures test execution outcome for a single detection against one backend.

    Produced by all three validator modes: ART, synthetic, and static linter.
    """

    model_config = ConfigDict(populate_by_name=True)

    detection_id: str
    detection_name: str = ""
    backend: str = Field(..., description="SIEM backend name, e.g. opensearch, splunk")
    test_type: TestType
    passed: bool

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = Field(default=0.0, ge=0.0)

    technique_ids: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique IDs exercised in this test run",
    )

    # Alert-level outcome flags
    alert_found: bool = Field(
        default=False,
        description="True if the backend generated an alert during the test window",
    )
    false_negative: bool = Field(
        default=False,
        description="True if the attack ran but no alert was generated (detection missed it)",
    )
    false_positive_rate: float | None = Field(
        default=None,
        description="Estimated FP rate (0–1) measured over the test window, if available",
    )

    # Error and evidence
    error: str | None = Field(
        default=None,
        description="Error message if the test itself failed to execute (not a FN)",
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Raw alert / event dicts returned by the backend during the test window",
    )
    test_details: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Test-type-specific metadata: ART test number, synthetic payload hash, "
            "linter finding codes, etc."
        ),
    )
    backend_query_used: str | None = Field(
        default=None,
        description="The native query that was deployed to the backend for this test",
    )

    @property
    def result_label(self) -> str:
        if self.error:
            return "error"
        return "pass" if self.passed else "fail"

    @property
    def is_actionable_failure(self) -> bool:
        """True if the failure represents a real detection gap (not a test infrastructure error)."""
        return not self.passed and self.false_negative and self.error is None


# ─── CanonicalEvent ───────────────────────────────────────────────────────────

class CanonicalEvent(BaseModel):
    """
    Normalized event shipped between lab containers and the SIEM under test.

    Produced by victim containers (auditd, Sysmon, Falco, win-emulator) and
    consumed by the Vector shipper and the synthetic event validator.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_host: str = Field(default="", description="Hostname or container name of the event origin")
    event_type: str = Field(
        ...,
        description=(
            "Normalized event type: process_creation | network_connection | "
            "file_create | file_modify | registry_set | registry_delete | "
            "dns_query | pipe_created | login | logout | driver_load | "
            "image_load | raw_access_read | ..."
        ),
    )
    platform: Platform = Platform.LINUX

    # ── Process context ───────────────────────────────────────────────────────
    process_name: str | None = None
    process_id: int | None = None
    process_guid: str | None = None
    parent_process_name: str | None = None
    parent_process_id: int | None = None
    parent_process_guid: str | None = None
    command_line: str | None = None
    user: str | None = None
    working_directory: str | None = None
    integrity_level: str | None = Field(
        None, description="Windows integrity level: Low | Medium | High | System"
    )

    # ── Network context ───────────────────────────────────────────────────────
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(None, ge=0, le=65535)
    dst_port: int | None = Field(None, ge=0, le=65535)
    protocol: str | None = None
    dns_query: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None

    # ── File context ──────────────────────────────────────────────────────────
    file_path: str | None = None
    file_name: str | None = None
    file_hash_md5: str | None = None
    file_hash_sha256: str | None = None
    file_hash_sha1: str | None = None

    # ── Registry context (Windows) ────────────────────────────────────────────
    registry_key: str | None = None
    registry_value_name: str | None = None
    registry_value_data: str | None = None

    # ── Sysmon / Windows Event Log IDs ───────────────────────────────────────
    sysmon_event_id: int | None = Field(None, description="Sysmon event ID (1–29)")
    windows_event_id: int | None = Field(None, description="Windows Security / System Event ID")

    # ── Raw and correlation ───────────────────────────────────────────────────
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Original unmodified event fields — source of truth if normalisation is ambiguous",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique IDs associated with this event (set by scenario runner)",
    )
    scenario_id: str | None = Field(
        None,
        description="Links this event to the attack scenario that generated it",
    )
    is_synthetic: bool = Field(
        default=False,
        description="True if this event was injected by the synthetic validator rather than real telemetry",
    )


# ─── MigrationAnalysis ────────────────────────────────────────────────────────

class FieldMappingIssue(BaseModel):
    source_field: str
    target_field: str | None = None
    issue: str = Field(
        ...,
        description="Description of the mapping problem, e.g. 'no equivalent field in target schema'",
    )


class MigrationAnalysis(BaseModel):
    """
    Per-rule analysis for a SIEM-to-SIEM migration.

    Produced by ``SIEMMigrator.plan()`` for every rule in scope.
    Aggregated into a ``MigrationPlan`` by the migrator.
    """

    model_config = ConfigDict(populate_by_name=True)

    detection_id: str
    detection_name: str = ""
    source_siem: str = Field(..., description="e.g. splunk, elastic")
    target_siem: str = Field(..., description="e.g. opensearch, sentinel")
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    translatable: bool = Field(
        default=False,
        description="True if the rule can be automatically translated (even partially)",
    )
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(
        default=0.0,
        description=(
            "Translation confidence: 1.0 = semantically equivalent, "
            "0.0 = cannot translate"
        ),
    )
    translated_query: str | None = Field(
        default=None,
        description="Best-effort translated query in the target SIEM's syntax",
    )

    coverage_gaps: list[str] = Field(
        default_factory=list,
        description=(
            "Capabilities present in source query lost in translation, "
            "e.g. ['lookup tables', 'macro expansion', 'subsearch']"
        ),
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal translation warnings",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Translation errors that prevent automatic migration",
    )

    field_mapping_issues: list[FieldMappingIssue] = Field(
        default_factory=list,
        description="Field name mapping problems between source and target schemas",
    )

    manual_review_required: bool = Field(
        default=True,
        description="True if human review is needed before the translated rule is production-ready",
    )
    estimated_effort: str = Field(
        default="medium",
        description="Migration effort estimate: low | medium | high",
    )
    notes: str = ""

    @property
    def migration_grade(self) -> str:
        """
        Letter grade summarising migration quality.

        A — fully automatic, high confidence, no gaps
        B — automatic with minor warnings
        C — partial translation, coverage gaps present
        D — low confidence, significant manual work needed
        F — cannot translate
        """
        if not self.translatable:
            return "F"
        if self.confidence >= 0.90 and not self.coverage_gaps and not self.errors:
            return "A"
        if self.confidence >= 0.75 and not self.errors:
            return "B"
        if self.confidence >= 0.50:
            return "C"
        return "D"


# ─── Backward-compatible legacy model ────────────────────────────────────────

class DetectionRule(BaseModel):
    """
    Legacy simplified model kept for backward compatibility.

    New code should use ``CanonicalDetection``.
    """

    id: str
    title: str
    description: str = ""
    author: str = ""
    source_format: DetectionFormat = DetectionFormat.UNKNOWN
    severity: LegacySeverity = LegacySeverity.MEDIUM
    tags: list[str] = Field(default_factory=list)
    mitre: list[Any] = Field(default_factory=list)
    query: str = ""
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)
    created_at: datetime | None = None
    modified_at: datetime | None = None
    enabled: bool = True
    false_positive_notes: list[str] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, v: Any) -> Any:
        # Normalise legacy aliases ("medium" → stays "medium", "med" → "medium")
        _aliases: dict[str, str] = {"med": "medium"}
        return _aliases.get(str(v).lower(), v) if v is not None else "medium"

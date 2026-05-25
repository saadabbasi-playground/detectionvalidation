"""
Unit tests for CanonicalDetection and companion models.

Ten tests covering:
  1.  Sigma            — process creation detection with full ATT&CK mapping
  2.  Splunk SPL       — CIM-modelled authentication detection with deployment history
  3.  KQL (Sentinel)  — Azure AD risky sign-in with CVE references
  4.  YARA            — file-based malware detection with hash references
  5.  Elastic EQL     — sequence (parent → child) process detection
  6.  Snort           — network-based exploit detection with CVE
  7.  Suricata        — JA3 fingerprint + DNS C2 detection
  8.  CoverageEntry / Gap — coverage matrix and gap prioritisation models
  9.  ValidationResult    — ART pass / synthetic fail / linter error outcomes
  10. MigrationAnalysis + CanonicalEvent — SIEM migration grading & event schema
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from detection_validator.normalizer.schema import (
    ASTNode,
    CanonicalDetection,
    CanonicalEvent,
    CoverageEntry,
    CVEReference,
    DeploymentRecord,
    DeploymentStatus,
    DetectionFormat,
    DetectionLogic,
    DetectionTestType,
    FieldMappingIssue,
    Gap,
    LogSource,
    MATURITY_RUBRIC,
    MigrationAnalysis,
    MitreTechnique,
    Platform,
    Severity,
    ValidationResult,
    ValidationStatus,
    VERSION,
)
from detection_validator.normalizer.migrations import migrate, CURRENT_VERSION
from detection_validator.normalizer.migrations.v1_0 import validate_shape


# ─── Shared helpers ───────────────────────────────────────────────────────────

_UTC = timezone.utc

def _dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso).replace(tzinfo=_UTC)


def _minimal(name: str, raw_query: str, fmt: DetectionFormat) -> CanonicalDetection:
    return CanonicalDetection(
        name=name,
        source_format=fmt,
        detection_logic=DetectionLogic(raw=raw_query),
    )


# ═════════════════════════════════════════════════════════════════════════════
# Test 1 — Sigma: PowerShell encoded-command execution (T1059.001)
# ═════════════════════════════════════════════════════════════════════════════

class TestSigmaDetection:
    PAYLOAD: dict = {
        "id": "aabbccdd-1111-2222-3333-444455556666",
        "name": "PowerShell Encoded Command Execution",
        "description": (
            "Detects PowerShell invoked with -EncodedCommand, a common obfuscation "
            "technique for living-off-the-land attacks."
        ),
        "author": ["Alice Red", "Bob Blue"],
        "version": "2.1.0",
        "created_at": "2024-01-15T10:00:00",
        "modified_at": "2024-06-01T08:30:00",
        "severity": "high",
        "source_format": "sigma",
        "platforms": ["windows"],
        "tags": [
            "attack.execution",
            "attack.t1059.001",
            "attack.defense_evasion",
            "attack.execution",  # duplicate — should be deduped
        ],
        "detection_logic": {
            "raw": (
                "process.name: powershell.exe AND "
                "process.args|contains: '-EncodedCommand'"
            ),
            "language": "sigma",
            "normalized_conditions": [
                "process name is powershell.exe",
                "command line contains -EncodedCommand",
            ],
            "field_references": ["process.name", "process.args"],
        },
        "log_sources": [
            {"product": "windows", "category": "process_creation", "service": "sysmon"},
        ],
        "mitre_techniques": [
            {
                "technique_id": "T1059",
                "sub_technique_id": "T1059.001",
                "tactic": "execution",
                "confidence": 0.97,
                "name": "Command and Scripting Interpreter: PowerShell",
            }
        ],
        "cve_references": [],
        "data_components": ["Process Creation"],
        "false_positive_notes": [
            "Legitimate admin scripts — filter by parent process and user context",
        ],
        "cim_models": ["Endpoint"],
        "validation_status": "passed",
        "last_validated": "2024-06-01T08:00:00",
        "detection_maturity_score": 4,
        "portability_score": 90.0,
        "siem_native": {
            "splunk": (
                'index=windows sourcetype=sysmon EventCode=1 '
                'Image="*\\\\powershell.exe" CommandLine="*-EncodedCommand*"'
            ),
            "opensearch": (
                '{"query":{"bool":{"must":[{"match":{"process.name":"powershell.exe"}},'
                '{"wildcard":{"process.args":"*-EncodedCommand*"}}]}}}'
            ),
        },
        "deployment_history": [],
    }

    def test_round_trip(self) -> None:
        det = CanonicalDetection.model_validate(self.PAYLOAD)
        assert det.id == "aabbccdd-1111-2222-3333-444455556666"
        assert det.source_format == DetectionFormat.SIGMA
        assert det.severity == Severity.HIGH

    def test_duplicate_tags_deduped(self) -> None:
        det = CanonicalDetection.model_validate(self.PAYLOAD)
        assert det.tags.count("attack.execution") == 1

    def test_mitre_mapping(self) -> None:
        det = CanonicalDetection.model_validate(self.PAYLOAD)
        assert len(det.mitre_techniques) == 1
        t = det.mitre_techniques[0]
        assert t.full_id == "T1059.001"
        assert t.tactic == "execution"
        assert t.confidence == pytest.approx(0.97)

    def test_primary_technique(self) -> None:
        det = CanonicalDetection.model_validate(self.PAYLOAD)
        assert det.primary_technique is not None
        assert det.primary_technique.technique_id == "T1059"

    def test_siem_native_keys(self) -> None:
        det = CanonicalDetection.model_validate(self.PAYLOAD)
        assert "splunk" in det.siem_native
        assert "opensearch" in det.siem_native

    def test_maturity_label(self) -> None:
        det = CanonicalDetection.model_validate(self.PAYLOAD)
        assert det.detection_maturity_score == 4
        assert det.maturity_label == MATURITY_RUBRIC[4]


# ═════════════════════════════════════════════════════════════════════════════
# Test 2 — Splunk SPL: Brute-force login detection with CIM + deployment record
# ═════════════════════════════════════════════════════════════════════════════

class TestSplunkSPLDetection:
    def _make(self) -> CanonicalDetection:
        return CanonicalDetection(
            name="Brute Force Login Attempts",
            description="Detects rapid successive authentication failures from a single source.",
            author="splunk-security-research",
            severity=Severity.HIGH,
            source_format=DetectionFormat.SPLUNK_SPL,
            platforms=[Platform.WINDOWS, Platform.LINUX],
            detection_logic=DetectionLogic(
                raw=(
                    "index=main sourcetype=WinEventLog:Security EventCode=4625 "
                    "| stats count by src_ip, user "
                    "| where count > 20"
                ),
                language="splunk-spl",
                normalized_conditions=["≥20 auth failures from same source IP within window"],
                field_references=["src_ip", "user", "EventCode"],
            ),
            log_sources=[
                LogSource(product="windows", category="authentication", service="security"),
            ],
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1110",
                    sub_technique_id="T1110.001",
                    tactic="credential-access",
                    confidence=0.95,
                    name="Brute Force: Password Guessing",
                )
            ],
            data_components=["Authentication"],
            cim_models=["Authentication", "Endpoint"],
            validation_status=ValidationStatus.PASSED,
            detection_maturity_score=4,
            portability_score=75.0,
            siem_native={
                "splunk": (
                    "index=main sourcetype=WinEventLog:Security EventCode=4625 "
                    "| stats count by src_ip, user | where count > 20"
                ),
            },
            deployment_history=[
                DeploymentRecord(
                    backend="splunk",
                    deployed_at=_dt("2024-05-01T12:00:00"),
                    rule_version="1.0.0",
                    status=DeploymentStatus.DEPLOYED,
                    deployed_by="ci-pipeline",
                    backend_rule_id="savedsearch-brute-force-001",
                ),
            ],
        )

    def test_cim_models_present(self) -> None:
        det = self._make()
        assert "Authentication" in det.cim_models
        assert "Endpoint" in det.cim_models

    def test_deployment_history(self) -> None:
        det = self._make()
        assert len(det.deployment_history) == 1
        rec = det.deployment_history[0]
        assert rec.backend == "splunk"
        assert rec.status == DeploymentStatus.DEPLOYED
        assert rec.backend_rule_id == "savedsearch-brute-force-001"

    def test_latest_deployment(self) -> None:
        det = self._make()
        latest = det.latest_deployment
        assert latest is not None
        assert latest.deployed_by == "ci-pipeline"

    def test_portability_score_range(self) -> None:
        det = self._make()
        assert 0.0 <= det.portability_score <= 100.0


# ═════════════════════════════════════════════════════════════════════════════
# Test 3 — KQL (Microsoft Sentinel): Risky sign-in with CVE + Azure platform
# ═════════════════════════════════════════════════════════════════════════════

class TestKQLDetection:
    def _make(self) -> CanonicalDetection:
        return CanonicalDetection(
            name="Azure AD Sign-In from Impossible Travel",
            description=(
                "Detects sign-ins from two geographic locations that cannot "
                "be reached within the observed time delta."
            ),
            author="azure-sentinel-team",
            severity=Severity.HIGH,
            source_format=DetectionFormat.KQL,
            platforms=[Platform.CLOUD],
            detection_logic=DetectionLogic(
                raw=(
                    "SigninLogs\n"
                    "| where ResultType == 0\n"
                    "| summarize Locations = make_set(Location), "
                    "  Count = count() by UserPrincipalName, bin(TimeGenerated, 1h)\n"
                    "| where array_length(Locations) > 1"
                ),
                language="kql",
                normalized_conditions=[
                    "Successful sign-ins from more than one location in one hour",
                ],
                field_references=["ResultType", "Location", "UserPrincipalName", "TimeGenerated"],
            ),
            log_sources=[
                LogSource(product="azure", category="authentication", service="sign-in-logs"),
            ],
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1078",
                    sub_technique_id="T1078.004",
                    tactic="defense-evasion",
                    confidence=0.80,
                    name="Valid Accounts: Cloud Accounts",
                )
            ],
            cve_references=[
                CVEReference(cve_id="CVE-2022-30190", confidence=0.60, cvss_score=7.8),
            ],
            data_components=["Logon Session Creation"],
            cim_models=[],
            validation_status=ValidationStatus.NEEDS_REVIEW,
            detection_maturity_score=3,
            portability_score=40.0,  # KQL is largely Sentinel-specific
            siem_native={"sentinel": "SigninLogs | where ResultType == 0 ..."},
        )

    def test_cve_reference(self) -> None:
        det = self._make()
        assert len(det.cve_references) == 1
        cve = det.cve_references[0]
        assert cve.cve_id == "CVE-2022-30190"
        assert cve.cvss_score == pytest.approx(7.8)

    def test_cloud_platform(self) -> None:
        det = self._make()
        assert Platform.CLOUD in det.platforms

    def test_needs_review_status(self) -> None:
        det = self._make()
        assert det.validation_status == ValidationStatus.NEEDS_REVIEW
        assert not det.is_validated

    def test_invalid_cve_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CVEReference(cve_id="CVE-NOTAVALID", confidence=1.0)


# ═════════════════════════════════════════════════════════════════════════════
# Test 4 — YARA: Cobalt Strike beacon signature (file-based)
# ═════════════════════════════════════════════════════════════════════════════

class TestYARADetection:
    RULE = (
        'rule CobaltStrike_Beacon {\n'
        '    meta:\n'
        '        description = "Detects Cobalt Strike Beacon DLL"\n'
        '        author = "threat-research"\n'
        '    strings:\n'
        '        $mz = { 4D 5A }\n'
        '        $cs1 = { FC E8 89 00 00 00 60 89 E5 31 D2 }\n'
        '    condition:\n'
        '        $mz at 0 and $cs1\n'
        '}'
    )

    def test_yara_detection_built(self) -> None:
        det = CanonicalDetection(
            name="CobaltStrike Beacon DLL",
            description="YARA signature matching Cobalt Strike Beacon shellcode stub.",
            severity=Severity.CRITICAL,
            source_format=DetectionFormat.YARA,
            platforms=[Platform.WINDOWS, Platform.LINUX],
            detection_logic=DetectionLogic(
                raw=self.RULE,
                language="yara",
                field_references=["$mz", "$cs1"],
            ),
            log_sources=[LogSource(category="file", product="endpoint")],
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1055",
                    tactic="defense-evasion",
                    confidence=0.92,
                    name="Process Injection",
                )
            ],
            data_components=["File Creation"],
            validation_status=ValidationStatus.PASSED,
            detection_maturity_score=5,
            portability_score=20.0,  # YARA doesn't translate to most SIEMs
        )
        assert det.severity == Severity.CRITICAL
        assert det.source_format == DetectionFormat.YARA
        assert det.detection_maturity_score == 5
        assert det.maturity_label == MATURITY_RUBRIC[5]

    def test_portability_is_low_for_yara(self) -> None:
        det = _minimal("YARA rule", self.RULE, DetectionFormat.YARA)
        assert det.portability_score == 0.0  # default


# ═════════════════════════════════════════════════════════════════════════════
# Test 5 — Elastic EQL: Parent–child sequence (lolbin execution)
# ═════════════════════════════════════════════════════════════════════════════

class TestElasticEQLDetection:
    EQL = (
        "sequence by host.id, process.parent.entity_id\n"
        "  [process where event.type == 'start' and process.name == 'winword.exe']\n"
        "  [process where event.type == 'start' and process.name in "
        "   ('cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe')]"
    )

    def test_eql_sequence_detection(self) -> None:
        det = CanonicalDetection(
            name="Office Application Spawning Shell",
            description="Detects Microsoft Office spawning a shell process (common macro abuse).",
            severity=Severity.HIGH,
            source_format=DetectionFormat.ELASTIC_EQL,
            platforms=[Platform.WINDOWS],
            detection_logic=DetectionLogic(
                raw=self.EQL,
                language="eql",
                ast=ASTNode(
                    node_type="sequence",
                    children=[
                        ASTNode(
                            node_type="condition",
                            field_name="process.name",
                            operator="eq",
                            value="winword.exe",
                        ),
                        ASTNode(
                            node_type="condition",
                            field_name="process.name",
                            operator="eq",
                            value=["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
                        ),
                    ],
                ),
                normalized_conditions=[
                    "winword.exe starts",
                    "followed by cmd.exe / powershell.exe / wscript.exe / cscript.exe",
                ],
                field_references=["process.name", "host.id", "process.parent.entity_id"],
            ),
            log_sources=[
                LogSource(product="windows", category="process_creation"),
                LogSource(product="elastic", service="endpoint"),
            ],
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1059",
                    sub_technique_id="T1059.001",
                    tactic="execution",
                    confidence=0.88,
                ),
                MitreTechnique(
                    technique_id="T1566",
                    sub_technique_id="T1566.001",
                    tactic="initial-access",
                    confidence=0.70,
                    name="Phishing: Spearphishing Attachment",
                ),
            ],
            data_components=["Process Creation"],
            cim_models=["Endpoint"],
            validation_status=ValidationStatus.PASSED,
            detection_maturity_score=4,
            portability_score=55.0,
        )
        assert det.source_format == DetectionFormat.ELASTIC_EQL
        # AST round-trips through model
        assert det.detection_logic.ast is not None
        assert det.detection_logic.ast.node_type == "sequence"
        assert len(det.detection_logic.ast.children) == 2
        # Multiple techniques — primary is highest confidence
        assert det.primary_technique is not None
        assert det.primary_technique.technique_id == "T1059"
        assert len(det.technique_ids) == 2


# ═════════════════════════════════════════════════════════════════════════════
# Test 6 — Snort: CVE-linked exploit detection (network rule)
# ═════════════════════════════════════════════════════════════════════════════

class TestSnortDetection:
    SNORT_RULE = (
        'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS '
        '(msg:"ET WEB_SERVER Log4Shell Exploit Attempt"; '
        'flow:established,to_server; '
        'content:"${jndi:"; nocase; '
        'classtype:attempted-admin; sid:2034647; rev:2;)'
    )

    def test_snort_with_cve(self) -> None:
        det = CanonicalDetection(
            name="Log4Shell JNDI Exploit Attempt (Snort)",
            description=(
                "Snort/Suricata rule detecting JNDI lookup strings in HTTP traffic "
                "associated with CVE-2021-44228."
            ),
            severity=Severity.CRITICAL,
            source_format=DetectionFormat.SNORT,
            platforms=[Platform.NETWORK, Platform.LINUX],
            detection_logic=DetectionLogic(
                raw=self.SNORT_RULE,
                language="snort",
                normalized_conditions=['HTTP body contains "${jndi:" (case-insensitive)'],
                field_references=["http.request.body", "destination.port"],
            ),
            log_sources=[LogSource(product="network", category="http", service="ids")],
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1190",
                    tactic="initial-access",
                    confidence=0.99,
                    name="Exploit Public-Facing Application",
                )
            ],
            cve_references=[
                CVEReference(
                    cve_id="CVE-2021-44228",
                    confidence=0.99,
                    cvss_score=10.0,
                    description="Apache Log4j2 JNDI injection (Log4Shell)",
                )
            ],
            data_components=["Network Traffic Content"],
            validation_status=ValidationStatus.PASSED,
            detection_maturity_score=5,
            portability_score=30.0,
        )
        assert det.cve_references[0].cve_id == "CVE-2021-44228"
        assert det.cve_references[0].cvss_score == pytest.approx(10.0)
        assert det.severity == Severity.CRITICAL
        assert det.detection_maturity_score == 5


# ═════════════════════════════════════════════════════════════════════════════
# Test 7 — Suricata: JA3 fingerprint + DNS C2 beacon detection
# ═════════════════════════════════════════════════════════════════════════════

class TestSuricataDetection:
    SURICATA_RULE = (
        'alert dns $HOME_NET any -> any any '
        '(msg:"DV Cobalt Strike default C2 DNS beacon"; '
        'dns.query; content:".stager."; nocase; '
        'metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit; '
        'sid:9000001; rev:1;)'
    )

    def test_suricata_dns_beacon(self) -> None:
        det = CanonicalDetection(
            name="Cobalt Strike Default DNS Beacon",
            severity=Severity.CRITICAL,
            source_format=DetectionFormat.SURICATA,
            platforms=[Platform.NETWORK, Platform.WINDOWS],
            detection_logic=DetectionLogic(
                raw=self.SURICATA_RULE,
                language="suricata",
                normalized_conditions=["DNS query contains .stager. (case-insensitive)"],
                field_references=["dns.query"],
            ),
            log_sources=[LogSource(product="network", category="dns")],
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1071",
                    sub_technique_id="T1071.004",
                    tactic="command-and-control",
                    confidence=0.85,
                    name="Application Layer Protocol: DNS",
                )
            ],
            data_components=["Network Traffic Flow", "DNS Resolution"],
            validation_status=ValidationStatus.UNTESTED,
            detection_maturity_score=2,
        )
        assert det.source_format == DetectionFormat.SURICATA
        assert det.mitre_techniques[0].tactic == "command-and-control"
        assert not det.is_validated

    def test_invalid_technique_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MitreTechnique(technique_id="NOT-VALID", tactic="execution", confidence=1.0)

    def test_invalid_sub_technique_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MitreTechnique(
                technique_id="T1071",
                sub_technique_id="T1071.9999",  # too many digits
                tactic="command-and-control",
                confidence=0.9,
            )


# ═════════════════════════════════════════════════════════════════════════════
# Test 8 — CoverageEntry & Gap: coverage matrix and prioritised gaps
# ═════════════════════════════════════════════════════════════════════════════

class TestCoverageAndGap:
    def _entry(self, detection_ids: list[str], validated: int = 0) -> CoverageEntry:
        return CoverageEntry(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            sub_technique_id="T1059.001",
            detection_ids=detection_ids,
            coverage_score=len(detection_ids) * 0.25,
            detection_maturity_avg=3.5,
            validated_count=validated,
            data_sources_present=["Process Creation"],
        )

    def test_covered_entry(self) -> None:
        entry = self._entry(["det-001", "det-002"], validated=1)
        assert entry.is_covered
        assert entry.is_validated
        assert entry.coverage_score == pytest.approx(0.5)

    def test_uncovered_entry(self) -> None:
        entry = self._entry([])
        assert not entry.is_covered
        assert not entry.is_validated

    def test_gap_model(self) -> None:
        gap = Gap(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="credential-access",
            severity="high",
            recommended_detections=[
                "proc_dump_lsass.yml",
                "mimikatz_execution.yml",
            ],
            effort_estimate="medium",
            data_sources_needed=["Process Creation", "Windows Event Log 4656"],
            related_cves=["CVE-2017-0144"],
            priority_score=8.5,
            notes="High-frequency technique in ransomware campaigns.",
        )
        assert gap.technique_id == "T1003"
        assert gap.priority_score == pytest.approx(8.5)
        assert "mimikatz_execution.yml" in gap.recommended_detections

    def test_gap_priority_score_clamped(self) -> None:
        with pytest.raises(ValidationError):
            Gap(
                technique_id="T1003",
                tactic="credential-access",
                severity="high",
                priority_score=11.0,  # > 10.0 — should fail
            )

    def test_coverage_score_must_be_fraction(self) -> None:
        with pytest.raises(ValidationError):
            CoverageEntry(
                technique_id="T1059",
                tactic="execution",
                coverage_score=1.5,  # > 1.0 — invalid
            )


# ═════════════════════════════════════════════════════════════════════════════
# Test 9 — ValidationResult: ART pass, synthetic fail, linter error
# ═════════════════════════════════════════════════════════════════════════════

class TestValidationResult:
    def test_art_pass(self) -> None:
        result = ValidationResult(
            detection_id="det-001",
            detection_name="PowerShell Encoded Command",
            backend="opensearch",
            test_type=DetectionTestType.ATOMIC_RED_TEAM,
            passed=True,
            duration_seconds=47.3,
            technique_ids=["T1059.001"],
            alert_found=True,
            false_negative=False,
            evidence=[{"_id": "ev001", "message": "powershell.exe -EncodedCommand ..."}],
            test_details={"art_test_number": 1, "art_technique": "T1059.001"},
        )
        assert result.passed
        assert result.result_label == "pass"
        assert not result.is_actionable_failure
        assert result.alert_found

    def test_synthetic_false_negative(self) -> None:
        result = ValidationResult(
            detection_id="det-002",
            backend="splunk",
            test_type=DetectionTestType.SYNTHETIC,
            passed=False,
            alert_found=False,
            false_negative=True,
            duration_seconds=5.0,
            technique_ids=["T1055"],
            test_details={"payload_hash": "sha256:abc123", "events_injected": 3},
        )
        assert not result.passed
        assert result.result_label == "fail"
        assert result.is_actionable_failure  # FN + no infra error = real gap

    def test_linter_error_result(self) -> None:
        result = ValidationResult(
            detection_id="det-003",
            backend="sentinel",
            test_type=DetectionTestType.LINTER,
            passed=False,
            error="KQL syntax error: unexpected token '|'",
            test_details={"findings": ["E001", "W003"]},
        )
        assert result.result_label == "error"
        assert not result.is_actionable_failure  # error ≠ FN

    def test_false_positive_rate_optional(self) -> None:
        r = ValidationResult(
            detection_id="x",
            backend="wazuh",
            test_type=DetectionTestType.SYNTHETIC,
            passed=True,
        )
        assert r.false_positive_rate is None

    def test_duration_must_be_non_negative(self) -> None:
        with pytest.raises(ValidationError):
            ValidationResult(
                detection_id="x",
                backend="elastic",
                test_type=DetectionTestType.LINTER,
                passed=True,
                duration_seconds=-1.0,
            )


# ═════════════════════════════════════════════════════════════════════════════
# Test 10 — MigrationAnalysis & CanonicalEvent
# ═════════════════════════════════════════════════════════════════════════════

class TestMigrationAndEvent:
    def test_migration_grade_a(self) -> None:
        analysis = MigrationAnalysis(
            detection_id="det-001",
            source_siem="elastic",
            target_siem="opensearch",
            translatable=True,
            confidence=0.95,
            translated_query='{\"query\":{\"match\":{\"event.code\":\"4625\"}}}',
            coverage_gaps=[],
            manual_review_required=False,
            estimated_effort="low",
        )
        assert analysis.migration_grade == "A"

    def test_migration_grade_f_not_translatable(self) -> None:
        analysis = MigrationAnalysis(
            detection_id="det-002",
            source_siem="splunk",
            target_siem="chronicle",
            translatable=False,
            confidence=0.0,
            errors=["Splunk subsearch not supported in YARA-L"],
        )
        assert analysis.migration_grade == "F"

    def test_migration_grade_b_with_warnings(self) -> None:
        analysis = MigrationAnalysis(
            detection_id="det-003",
            source_siem="splunk",
            target_siem="opensearch",
            translatable=True,
            confidence=0.78,
            translated_query="SELECT * FROM logs WHERE ...",
            warnings=["lookup table 'asset_lookup' unavailable in target"],
            coverage_gaps=[],
        )
        assert analysis.migration_grade == "B"

    def test_field_mapping_issue_model(self) -> None:
        issue = FieldMappingIssue(
            source_field="src_ip",
            target_field="source.ip",
            issue="Field renamed; update saved searches referencing old name",
        )
        assert issue.source_field == "src_ip"
        assert issue.target_field == "source.ip"

    def test_canonical_event_process_creation(self) -> None:
        event = CanonicalEvent(
            event_type="process_creation",
            platform=Platform.WINDOWS,
            source_host="victim-01",
            process_name="powershell.exe",
            process_id=4512,
            parent_process_name="winword.exe",
            command_line='powershell.exe -EncodedCommand dABoAGkAcwA=',
            user="CORP\\jsmith",
            sysmon_event_id=1,
            mitre_techniques=["T1059.001"],
            scenario_id="scenario-powershell-001",
            is_synthetic=False,
            raw={"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        )
        assert event.platform == Platform.WINDOWS
        assert event.sysmon_event_id == 1
        assert "T1059.001" in event.mitre_techniques
        assert not event.is_synthetic

    def test_canonical_event_network_connection(self) -> None:
        event = CanonicalEvent(
            event_type="network_connection",
            platform=Platform.LINUX,
            source_host="attacker-01",
            src_ip="10.0.0.5",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="udp",
            dns_query="evil.stager.c2.example.com",
            is_synthetic=True,
            mitre_techniques=["T1071.004"],
        )
        assert event.event_type == "network_connection"
        assert event.dst_port == 53
        assert event.is_synthetic

    def test_invalid_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CanonicalEvent(
                event_type="network_connection",
                dst_port=99999,  # > 65535 — invalid
            )


# ═════════════════════════════════════════════════════════════════════════════
# Schema version and JSON schema export
# ═════════════════════════════════════════════════════════════════════════════

class TestSchemaMetadata:
    def test_version_constant(self) -> None:
        assert VERSION == CURRENT_VERSION

    def test_json_schema_has_version_annotation(self) -> None:
        schema = CanonicalDetection.json_schema()
        assert schema["x-schema-version"] == VERSION
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"

    def test_json_schema_str_is_valid_json(self) -> None:
        s = CanonicalDetection.json_schema_str()
        parsed = json.loads(s)
        assert "properties" in parsed

    def test_migrate_identity_on_current_version(self) -> None:
        raw = {
            "id": "abc",
            "name": "Test Rule",
            "detection_logic": {"raw": "index=*"},
            "schema_version": "1.0",
        }
        result = migrate(raw)
        assert result["name"] == "Test Rule"

    def test_migrate_unknown_version_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown schema version"):
            migrate({"schema_version": "99.0", "name": "x", "detection_logic": {"raw": ""}})

    def test_v1_0_snapshot_validate_shape(self) -> None:
        from detection_validator.normalizer.migrations.v1_0 import validate_shape
        good = {"id": "x", "name": "y", "detection_logic": {"raw": ""}}
        bad = {"name": "y"}
        assert validate_shape(good) == []
        assert "id" not in validate_shape(good)
        missing = validate_shape(bad)
        assert "id" in missing
        assert "detection_logic" in missing

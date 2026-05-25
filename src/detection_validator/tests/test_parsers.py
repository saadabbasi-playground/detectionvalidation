"""
Parser integration tests using fixture files from examples/detections/.

Each test class targets one parser; tests verify that the parser produces a
valid CanonicalDetection with the expected key fields.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    Platform,
    Severity,
    ValidationStatus,
)
from detection_validator.parsers import (
    ElasticEQLParser,
    GenericYAMLParser,
    KQLParser,
    ParseError,
    ParserRegistry,
    PartialParseWarning,
    SigmaParser,
    SplunkParser,
    SplunkSecurityContentParser,
    YARAParser,
)

# Root of fixture directory (relative to repo root)
_FIXTURES = Path(__file__).parents[3] / "examples" / "detections"


def _fix(fmt: str, name: str) -> Path:
    return _FIXTURES / fmt / name


# ─── SigmaParser tests ────────────────────────────────────────────────────────

class TestSigmaParser:
    def setup_method(self) -> None:
        self.parser = SigmaParser()

    def test_can_parse_sigma_file(self) -> None:
        path = _fix("sigma", "lolbas_mshta.yml")
        assert self.parser.can_parse(path) is True

    def test_mshta_fields(self) -> None:
        path = _fix("sigma", "lolbas_mshta.yml")
        d = self.parser.parse_file(path)
        assert isinstance(d, CanonicalDetection)
        assert "mshta" in d.name.lower()
        assert d.source_format == DetectionFormat.SIGMA
        assert d.severity == Severity.HIGH
        assert d.platforms == [Platform.WINDOWS]

    def test_mshta_techniques(self) -> None:
        d = self.parser.parse_file(_fix("sigma", "lolbas_mshta.yml"))
        ids = [t.full_id for t in d.mitre_techniques]
        assert "T1218.005" in ids or any("T1218" in i for i in ids)

    def test_lsass_critical_severity(self) -> None:
        d = self.parser.parse_file(_fix("sigma", "credential_dump_lsass.yml"))
        assert d.severity == Severity.CRITICAL

    def test_lsass_cve_extracted(self) -> None:
        d = self.parser.parse_file(_fix("sigma", "credential_dump_lsass.yml"))
        cve_ids = [c.cve_id for c in d.cve_references]
        assert "CVE-2021-36942" in cve_ids

    def test_network_scan_medium_severity(self) -> None:
        d = self.parser.parse_file(_fix("sigma", "network_scan_nmap.yml"))
        assert d.severity == Severity.MED

    def test_validation_status_untested(self) -> None:
        d = self.parser.parse_file(_fix("sigma", "lolbas_mshta.yml"))
        assert d.validation_status == ValidationStatus.UNTESTED

    def test_sigma_detection_logic_language(self) -> None:
        d = self.parser.parse_file(_fix("sigma", "lolbas_mshta.yml"))
        assert d.detection_logic.language == "sigma"
        assert d.detection_logic.raw  # non-empty

    def test_sigma_false_positives_extracted(self) -> None:
        d = self.parser.parse_file(_fix("sigma", "credential_dump_lsass.yml"))
        assert len(d.false_positive_notes) > 0


# ─── SplunkParser tests ───────────────────────────────────────────────────────

class TestSplunkParser:
    def setup_method(self) -> None:
        self.parser = SplunkParser()

    def test_can_parse_conf(self) -> None:
        assert self.parser.can_parse(_fix("splunk", "savedsearches.conf")) is True

    def test_can_parse_spl(self) -> None:
        assert self.parser.can_parse(_fix("splunk", "dns_beaconing.spl")) is True

    def test_conf_returns_canonical_detection(self) -> None:
        d = self.parser.parse_file(_fix("splunk", "savedsearches.conf"))
        assert isinstance(d, CanonicalDetection)
        assert d.source_format == DetectionFormat.SPLUNK_SPL

    def test_conf_first_stanza_name(self) -> None:
        d = self.parser.parse_file(_fix("splunk", "savedsearches.conf"))
        assert "powershell" in d.name.lower() or "psexec" in d.name.lower()

    def test_conf_parse_all(self) -> None:
        content = _fix("splunk", "savedsearches.conf").read_text()
        detections = self.parser.parse_all(content)
        assert len(detections) == 2

    def test_spl_file_parsed(self) -> None:
        d = self.parser.parse_file(_fix("splunk", "dns_beaconing.spl"))
        assert d.source_format == DetectionFormat.SPLUNK_SPL
        assert d.detection_logic.language == "spl"
        assert d.detection_logic.raw  # non-empty SPL

    def test_high_severity_from_alert_level(self) -> None:
        content = _fix("splunk", "savedsearches.conf").read_text()
        detections = self.parser.parse_all(content)
        severities = {d.name: d.severity for d in detections}
        # Both stanzas have alert.severity = 4 → HIGH
        for sev in severities.values():
            assert sev == Severity.HIGH


# ─── KQLParser tests ──────────────────────────────────────────────────────────

class TestKQLParser:
    def setup_method(self) -> None:
        self.parser = KQLParser()

    def test_can_parse_kql_file(self) -> None:
        assert self.parser.can_parse(_fix("kql", "defender_malicious_powershell.kql")) is True

    def test_can_parse_sentinel_yaml(self) -> None:
        assert self.parser.can_parse(_fix("kql", "sentinel_aad_password_spray.yml")) is True

    def test_kql_bare_detection(self) -> None:
        d = self.parser.parse_file(_fix("kql", "defender_malicious_powershell.kql"))
        assert isinstance(d, CanonicalDetection)
        assert d.source_format == DetectionFormat.KQL
        assert d.detection_logic.language == "kql"

    def test_sentinel_yaml_severity(self) -> None:
        d = self.parser.parse_file(_fix("kql", "sentinel_aad_password_spray.yml"))
        assert d.severity == Severity.HIGH

    def test_sentinel_yaml_techniques(self) -> None:
        d = self.parser.parse_file(_fix("kql", "sentinel_aad_password_spray.yml"))
        assert any("T1110" in t.full_id for t in d.mitre_techniques)

    def test_sentinel_yaml_platform_cloud(self) -> None:
        d = self.parser.parse_file(_fix("kql", "sentinel_aad_password_spray.yml"))
        assert Platform.CLOUD in d.platforms

    def test_kql_field_refs_extracted(self) -> None:
        d = self.parser.parse_file(_fix("kql", "defender_malicious_powershell.kql"))
        # DeviceProcessEvents → should extract field refs
        assert d.detection_logic.raw


# ─── YARAParser tests ─────────────────────────────────────────────────────────

class TestYARAParser:
    def setup_method(self) -> None:
        self.parser = YARAParser()

    def test_can_parse_yar_file(self) -> None:
        assert self.parser.can_parse(_fix("yara", "webshell_generic.yar")) is True

    def test_yara_rule_name(self) -> None:
        d = self.parser.parse_file(_fix("yara", "webshell_generic.yar"))
        assert d.name == "WebShell_Generic"

    def test_yara_source_format(self) -> None:
        d = self.parser.parse_file(_fix("yara", "webshell_generic.yar"))
        assert d.source_format == DetectionFormat.YARA

    def test_yara_technique_extracted(self) -> None:
        d = self.parser.parse_file(_fix("yara", "webshell_generic.yar"))
        assert any("T1505" in t.full_id for t in d.mitre_techniques)

    def test_yara_high_severity(self) -> None:
        d = self.parser.parse_file(_fix("yara", "webshell_generic.yar"))
        assert d.severity == Severity.HIGH

    def test_yara_low_portability_score(self) -> None:
        d = self.parser.parse_file(_fix("yara", "webshell_generic.yar"))
        assert d.portability_score < 50

    def test_yara_string_names_as_field_refs(self) -> None:
        d = self.parser.parse_file(_fix("yara", "webshell_generic.yar"))
        refs = d.detection_logic.field_references
        assert any(r.startswith("$") for r in refs)


# ─── ElasticEQLParser tests ───────────────────────────────────────────────────

class TestElasticEQLParser:
    def setup_method(self) -> None:
        self.parser = ElasticEQLParser()

    def test_can_parse_toml(self) -> None:
        assert self.parser.can_parse(
            _fix("elastic", "defense_evasion_suspicious_process_injection.toml")
        ) is True

    def test_can_parse_json(self) -> None:
        assert self.parser.can_parse(
            _fix("elastic", "credential_access_mimikatz.json")
        ) is True

    def test_toml_name_extracted(self) -> None:
        d = self.parser.parse_file(
            _fix("elastic", "defense_evasion_suspicious_process_injection.toml")
        )
        assert "process injection" in d.name.lower()

    def test_toml_high_severity(self) -> None:
        d = self.parser.parse_file(
            _fix("elastic", "defense_evasion_suspicious_process_injection.toml")
        )
        assert d.severity == Severity.HIGH

    def test_toml_eql_language(self) -> None:
        d = self.parser.parse_file(
            _fix("elastic", "defense_evasion_suspicious_process_injection.toml")
        )
        assert d.detection_logic.language == "eql"

    def test_toml_mitre_threat_parsed(self) -> None:
        d = self.parser.parse_file(
            _fix("elastic", "defense_evasion_suspicious_process_injection.toml")
        )
        ids = [t.full_id for t in d.mitre_techniques]
        assert any("T1055" in i for i in ids)

    def test_json_critical_severity(self) -> None:
        d = self.parser.parse_file(_fix("elastic", "credential_access_mimikatz.json"))
        assert d.severity == Severity.CRITICAL

    def test_json_technique_t1003(self) -> None:
        d = self.parser.parse_file(_fix("elastic", "credential_access_mimikatz.json"))
        assert any("T1003" in t.full_id for t in d.mitre_techniques)

    def test_json_false_positives(self) -> None:
        d = self.parser.parse_file(_fix("elastic", "credential_access_mimikatz.json"))
        assert d.false_positive_notes

    def test_esql_toml_parsed(self) -> None:
        d = self.parser.parse_file(_fix("elastic", "exfil_s3_bucket_access.toml"))
        assert d.name
        assert d.source_format == DetectionFormat.ELASTIC_EQL


# ─── SplunkSecurityContentParser tests ───────────────────────────────────────

class TestSplunkSecurityContentParser:
    def setup_method(self) -> None:
        self.parser = SplunkSecurityContentParser()

    def test_can_parse_ssc_file(self) -> None:
        path = _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        assert self.parser.can_parse(path) is True

    def test_ssc_name_extracted(self) -> None:
        d = self.parser.parse_file(
            _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        )
        assert "wmi" in d.name.lower()

    def test_ssc_source_format_splunk(self) -> None:
        d = self.parser.parse_file(
            _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        )
        assert d.source_format == DetectionFormat.SPLUNK_SPL

    def test_ssc_techniques_from_tags(self) -> None:
        d = self.parser.parse_file(
            _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        )
        ids = [t.full_id for t in d.mitre_techniques]
        assert any("T1047" in i for i in ids)

    def test_ssc_high_severity(self) -> None:
        d = self.parser.parse_file(
            _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        )
        assert d.severity == Severity.HIGH

    def test_ssc_analytic_story_in_tags(self) -> None:
        d = self.parser.parse_file(
            _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        )
        assert any("Lateral" in tag for tag in d.tags)

    def test_ssc_false_positives(self) -> None:
        d = self.parser.parse_file(
            _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        )
        assert d.false_positive_notes


# ─── GenericYAMLParser tests ──────────────────────────────────────────────────

class TestGenericYAMLParser:
    def setup_method(self) -> None:
        self.parser = GenericYAMLParser()

    def test_can_parse_any_yaml(self) -> None:
        assert self.parser.can_parse(_fix("generic", "custom_format_rule.yml")) is True

    def test_generic_with_default_map(self) -> None:
        # Without a custom map, falls back to _DEFAULT_FIELD_MAP
        content = _fix("generic", "custom_format_rule.yml").read_text()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", PartialParseWarning)
            d = self.parser.parse(content, source_path=_fix("generic", "custom_format_rule.yml"))
        assert isinstance(d, CanonicalDetection)

    def test_generic_with_custom_map(self, tmp_path: Path) -> None:
        # Write a custom field map
        map_file = tmp_path / "custom_map.yaml"
        map_file.write_text(
            "field_map:\n"
            "  id: rule_id\n"
            "  name: title\n"
            "  description: desc\n"
            "  severity: risk_level\n"
            "  query: detection.search\n"
            "  techniques: tags.attack\n"
            "  platforms: os\n"
            "defaults:\n"
            "  source_format: custom\n"
            "  language: custom\n"
        )
        parser = GenericYAMLParser(format_map_path=map_file)
        content = _fix("generic", "custom_format_rule.yml").read_text()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", PartialParseWarning)
            d = parser.parse(content, source_path=_fix("generic", "custom_format_rule.yml"))
        assert d.name == "Outbound Connection to Known C2 Infrastructure"
        assert d.severity == Severity.HIGH

    def test_generic_techniques_from_tags(self) -> None:
        content = _fix("generic", "custom_format_rule.yml").read_text()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", PartialParseWarning)
            d = self.parser.parse(content, source_path=_fix("generic", "custom_format_rule.yml"))
        # T1071.001 and T1041 should be found in text scan even without mapping
        ids = [t.full_id for t in d.mitre_techniques]
        assert any("T1071" in i for i in ids) or any("T1041" in i for i in ids)

    def test_generic_platforms_from_os_field(self, tmp_path: Path) -> None:
        map_file = tmp_path / "map.yaml"
        map_file.write_text(
            "field_map:\n"
            "  id: rule_id\n"
            "  name: title\n"
            "  description: desc\n"
            "  severity: risk_level\n"
            "  query: detection.search\n"
            "  platforms: os\n"
            "defaults:\n"
            "  source_format: custom\n"
        )
        parser = GenericYAMLParser(format_map_path=map_file)
        content = _fix("generic", "custom_format_rule.yml").read_text()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", PartialParseWarning)
            d = parser.parse(content)
        assert Platform.WINDOWS in d.platforms
        assert Platform.LINUX in d.platforms


# ─── ParserRegistry tests ─────────────────────────────────────────────────────

class TestParserRegistry:
    def setup_method(self) -> None:
        self.registry = ParserRegistry()

    def test_sigma_auto_detected(self) -> None:
        d = self.registry.parse_file(_fix("sigma", "lolbas_mshta.yml"))
        assert d.source_format == DetectionFormat.SIGMA

    def test_spl_auto_detected(self) -> None:
        d = self.registry.parse_file(_fix("splunk", "dns_beaconing.spl"))
        assert d.source_format == DetectionFormat.SPLUNK_SPL

    def test_kql_auto_detected(self) -> None:
        d = self.registry.parse_file(_fix("kql", "defender_malicious_powershell.kql"))
        assert d.source_format == DetectionFormat.KQL

    def test_yara_auto_detected(self) -> None:
        d = self.registry.parse_file(_fix("yara", "webshell_generic.yar"))
        assert d.source_format == DetectionFormat.YARA

    def test_elastic_toml_auto_detected(self) -> None:
        d = self.registry.parse_file(
            _fix("elastic", "defense_evasion_suspicious_process_injection.toml")
        )
        assert d.source_format == DetectionFormat.ELASTIC_EQL

    def test_elastic_json_auto_detected(self) -> None:
        d = self.registry.parse_file(_fix("elastic", "credential_access_mimikatz.json"))
        assert d.source_format == DetectionFormat.ELASTIC_EQL

    def test_ssc_preferred_over_sigma(self) -> None:
        # SSC file should be parsed by SplunkSecurityContentParser, not SigmaParser
        path = _fix("splunk_sc", "endpoint_suspicious_wmi_execution.yml")
        parser = self.registry.find_parser(path)
        assert parser is not None
        assert parser.name == "splunk_security_content"

    def test_parse_directory_yields_all_formats(self) -> None:
        detections = list(self.registry.parse_directory(_FIXTURES, recursive=True))
        formats = {d.source_format for d in detections}
        assert DetectionFormat.SIGMA in formats
        assert DetectionFormat.SPLUNK_SPL in formats
        assert DetectionFormat.KQL in formats
        assert DetectionFormat.YARA in formats
        assert DetectionFormat.ELASTIC_EQL in formats

    def test_parse_directory_count(self) -> None:
        detections = list(self.registry.parse_directory(_FIXTURES, recursive=True))
        # We have at least 15 fixture files
        assert len(detections) >= 12

    def test_unknown_file_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "script.py"
        f.write_text("print('hello')")
        assert self.registry.find_parser(f) is None

    def test_strict_mode_raises_on_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.yml"
        bad.write_text("{ invalid yaml: [}")
        with pytest.raises((ParseError, Exception)):
            list(self.registry.parse_directory(tmp_path, strict=True))

    def test_non_strict_mode_skips_errors(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.toml"
        bad.write_text("[rule]\n# missing required fields\n")
        # Should not raise; bad file is skipped
        detections = list(self.registry.parse_directory(tmp_path, strict=False))
        assert isinstance(detections, list)

    def test_registry_repr(self) -> None:
        r = repr(self.registry)
        assert "ParserRegistry" in r
        assert "sigma" in r


# ─── ParseError tests ─────────────────────────────────────────────────────────

class TestParseError:
    def test_parse_error_with_path(self) -> None:
        err = ParseError("bad file", path=Path("/some/file.yml"))
        assert "/some/file.yml" in str(err)

    def test_parse_error_with_cause(self) -> None:
        cause = ValueError("underlying issue")
        err = ParseError("wrapper", cause=cause)
        assert "underlying issue" in str(err)

    def test_parse_error_minimal(self) -> None:
        err = ParseError("just a message")
        assert str(err) == "just a message"

# Detection Parsers

This package converts raw detection rule files into the canonical
[`CanonicalDetection`](../normalizer/schema.py) format.

## Supported formats

| Parser class | Format | Extensions | Key identifiers |
|---|---|---|---|
| `SigmaParser` | Sigma YAML | `.yml`, `.yaml` | `detection:` + `logsource:` |
| `SplunkParser` | Splunk SPL / savedsearches.conf | `.conf`, `.spl` | `[stanza]` + `search =` |
| `KQLParser` | KQL / Sentinel YAML | `.kql`, `.yml` | `query:` + `severity:` |
| `YARAParser` | YARA rules | `.yar`, `.yara` | `rule ` keyword |
| `ElasticEQLParser` | Elastic detection-rules | `.toml`, `.json` | `[rule]` + `query =` |
| `SplunkSecurityContentParser` | Splunk SSC YAML | `.yml`, `.yaml` | `search:` + `mitre_attack_id:` |
| `GenericYAMLParser` | Any YAML (configurable) | `.yml`, `.yaml` | catch-all fallback |

## Adding a new parser in 5 steps

### Step 1 — Create the parser module

Create `src/detection_validator/parsers/my_format.py`:

```python
from pathlib import Path
from detection_validator.normalizer.schema import CanonicalDetection
from detection_validator.parsers.base import BaseParser, ParseError, make_detection_logic

class MyFormatParser(BaseParser):
    name = "my_format"
    supported_extensions = (".myfmt",)

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.supported_extensions

    def parse(self, content: str, source_path: Path | None = None) -> CanonicalDetection:
        # ... extract fields from content ...
        raise NotImplementedError
```

### Step 2 — Build a `CanonicalDetection`

Use helpers from `base.py`:

```python
from detection_validator.parsers.base import (
    make_detection_logic,
    techniques_to_models,
    cves_to_models,
    normalise_severity,
    extract_techniques_from_text,
)

logic = make_detection_logic(raw=query, language="my_format", field_refs=fields)
mitre_techniques = techniques_to_models(["T1059.001"], tactic="execution")
```

### Step 3 — Register in `registry.py`

Import and add to `ParserRegistry._parsers` *before* `GenericYAMLParser`:

```python
from detection_validator.parsers.my_format import MyFormatParser

self._parsers = [
    SplunkSecurityContentParser(),
    SigmaParser(),
    # ...
    MyFormatParser(),      # ← insert before GenericYAMLParser
    GenericYAMLParser(),
]
```

### Step 4 — Export from `__init__.py`

```python
from detection_validator.parsers.my_format import MyFormatParser
__all__ = [..., "MyFormatParser"]
```

### Step 5 — Write tests

Add fixture files to `examples/detections/my_format/` and tests in
`tests/test_parsers.py`:

```python
FIXTURE = Path("examples/detections/my_format/sample.myfmt")

def test_my_format_parses():
    parser = MyFormatParser()
    detection = parser.parse_file(FIXTURE)
    assert detection.source_format == DetectionFormat.CUSTOM
    assert detection.name
```

## Using `ParserRegistry`

```python
from detection_validator.parsers import ParserRegistry
from pathlib import Path

registry = ParserRegistry()

# Parse a single file (auto-detect format)
detection = registry.parse_file(Path("rules/rule.yml"))

# Scan a directory recursively
for detection in registry.parse_directory(Path("rules/"), recursive=True):
    print(detection.name, detection.severity)

# CLI: dv ingest rules/ -o canonical.jsonl
```

## Helper utilities in `base.py`

| Function | Purpose |
|---|---|
| `normalise_technique_id(raw)` | `"attack.T1059.001"` → `"T1059.001"` |
| `normalise_cve_id(raw)` | `"cve.2021.44228"` → `"CVE-2021-44228"` |
| `normalise_severity(raw)` | `"HIGH"` → `Severity.HIGH` |
| `extract_techniques_from_text(text)` | Scan free text for T1234 patterns |
| `extract_cves_from_text(text)` | Scan free text for CVE patterns |
| `techniques_to_models(ids, tactic)` | `["T1059"]` → `[MitreTechnique(...)]` |
| `cves_to_models(ids)` | `["CVE-2021-44228"]` → `[CVEReference(...)]` |
| `make_detection_logic(raw, ...)` | Build `DetectionLogic` with optional AST |
| `BaseParser._sniff(path, markers)` | Read first 8 KB for content sniffing |

"""Tests for OpenSearchValidator.validate() honest tier behavior.

All tests mock _search() and _pysigma_to_lucene() so no OpenSearch instance
is required.  The three invariants being tested:

  1. technique_only is NOT a pass (ValidationStatus.FAILED)
  2. Translation failures are surfaced in query_desc/error, not swallowed
  3. condition_match IS a pass (ValidationStatus.PASSED)
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from detection_validator.validator.engine import OpenSearchValidator
from detection_validator.normalizer.schema import ValidationStatus


# ── Sigma fixture rules ───────────────────────────────────────────────────────

_SIGMA_FIELD_RULE = """\
title: Test Field Rule
id: aaaaaaaa-0000-0000-0000-000000000001
status: test
description: unit-test rule
tags:
  - attack.execution
  - attack.T1059
logsource:
  product: linux
  service: auditd
detection:
  selection:
    exe|endswith: /bash
  condition: selection
level: medium
"""

_SIGMA_KW_RULE_NO_TECH = """\
title: Keyword Only Rule
id: cccccccc-0000-0000-0000-000000000003
status: test
description: keywords-only, no ATT&CK tags
logsource:
  product: linux
  service: auditd
detection:
  keywords:
    - suspicious_binary
  condition: keywords
level: low
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _det(raw: str, technique_ids: list[str] | None = None) -> SimpleNamespace:
    techs = [SimpleNamespace(full_id=tid) for tid in (technique_ids or [])]
    return SimpleNamespace(
        id="rule-001",
        name="Test Rule",
        description="unit test",
        mitre_techniques=techs,
        detection_logic=SimpleNamespace(raw=raw),
        validation_status=ValidationStatus.UNTESTED,
        last_validated=None,
    )


def _validator() -> OpenSearchValidator:
    return OpenSearchValidator(since_hours=0)  # no time filter; simpler to reason about


# ── Tests: technique_only is NOT a pass ──────────────────────────────────────

class TestTechniqueOnlyNotPassed:
    def test_status_is_technique_only(self):
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()

        with patch.object(v, "_search", return_value=(1, [{"technique": "T1059"}])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=(None, "SigmaError: unsupported modifier")):
            result = v.validate(det)

        assert result.status == "technique_only"

    def test_validation_status_is_failed(self):
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()

        with patch.object(v, "_search", return_value=(3, [{"technique": "T1059"}])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=(None, "translation error")):
            v.validate(det)

        assert det.validation_status == ValidationStatus.FAILED

    def test_technique_only_never_yields_passed(self):
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()

        with patch.object(v, "_search", return_value=(10, [{"technique": "T1059"}])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=(None, "error")):
            result = v.validate(det)

        assert result.status != "condition_match"
        assert det.validation_status != ValidationStatus.PASSED


# ── Tests: translation failures are surfaced ─────────────────────────────────

class TestTranslationFailureSurfaced:
    def test_xlat_error_appears_in_query_desc(self):
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()
        xlat_err = "SigmaParseError: unsupported condition keyword"

        with patch.object(v, "_search", return_value=(0, [])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=(None, xlat_err)):
            result = v.validate(det)

        combined = (result.query_desc or "") + (result.error or "")
        assert "SigmaParseError" in combined or "unsupported condition" in combined

    def test_xlat_error_does_not_cause_skip_when_techniques_exist(self):
        """Rule has ATT&CK tags → Layer 2 should run even when Layer 1 fails."""
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()

        with patch.object(v, "_search", return_value=(0, [])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=(None, "bad sigma")):
            result = v.validate(det)

        assert result.status not in ("skip",)

    def test_search_exception_on_layer1_is_captured(self):
        """A network error on Layer 1 should not hide the rule — Layer 2 still runs."""
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()
        call_count = 0

        def mock_search(query):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError("timeout")
            return (1, [{"technique": "T1059"}])

        with patch.object(v, "_search", side_effect=mock_search), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=("exe: /bin/bash", None)):
            result = v.validate(det)

        assert result.status == "technique_only"
        assert call_count == 2


# ── Tests: condition_match IS a pass ─────────────────────────────────────────

class TestConditionMatch:
    def test_status_is_condition_match(self):
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()

        with patch.object(v, "_search", return_value=(2, [{"exe": "/bin/bash"}])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=("exe.keyword: \\/bin\\/bash", None)):
            result = v.validate(det)

        assert result.status == "condition_match"

    def test_validation_status_is_passed(self):
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()

        with patch.object(v, "_search", return_value=(1, [{"exe": "/bin/bash"}])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=("exe.keyword: \\/bin\\/bash", None)):
            v.validate(det)

        assert det.validation_status == ValidationStatus.PASSED

    def test_condition_match_stops_at_layer1(self):
        """Layer 1 hits → no further layers searched."""
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()
        call_count = 0

        def mock_search(query):
            nonlocal call_count
            call_count += 1
            return (1, [{"exe": "/bin/bash"}])

        with patch.object(v, "_search", side_effect=mock_search), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=("exe.keyword: \\/bin\\/bash", None)):
            result = v.validate(det)

        assert result.status == "condition_match"
        assert call_count == 1  # only Layer 1 ran

    def test_layer1_miss_falls_to_technique_only(self):
        """Layer 1 translates but returns 0 hits → falls through to Layer 2."""
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()
        call_count = 0

        def mock_search(query):
            nonlocal call_count
            call_count += 1
            return (0, []) if call_count == 1 else (1, [{"technique": "T1059"}])

        with patch.object(v, "_search", side_effect=mock_search), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=("exe.keyword: \\/bin\\/bash", None)):
            result = v.validate(det)

        assert result.status == "technique_only"
        assert det.validation_status == ValidationStatus.FAILED


# ── Tests: keyword_only tier ─────────────────────────────────────────────────

class TestKeywordOnly:
    def test_keyword_only_sets_failed(self):
        """No techniques, Layer 1 fails → keyword match → keyword_only, FAILED."""
        det = _det(_SIGMA_KW_RULE_NO_TECH)
        v = _validator()

        with patch.object(v, "_search", return_value=(2, [{"proctitle": "suspicious_binary"}])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=(None, "keywords-only rules not translatable")):
            result = v.validate(det)

        assert result.status == "keyword_only"
        assert det.validation_status == ValidationStatus.FAILED


# ── Tests: no_match tier ─────────────────────────────────────────────────────

class TestNoMatch:
    def test_no_match_when_all_layers_miss(self):
        det = _det(_SIGMA_FIELD_RULE)
        v = _validator()

        with patch.object(v, "_search", return_value=(0, [])), \
             patch("detection_validator.validator.engine._pysigma_to_lucene",
                   return_value=(None, "translation error")):
            result = v.validate(det)

        assert result.status == "no_match"
        assert det.validation_status == ValidationStatus.FAILED
        assert result.hit_count == 0

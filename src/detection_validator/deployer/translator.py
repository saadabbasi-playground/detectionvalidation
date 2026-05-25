"""Rule translator — converts canonical DetectionRule to SIEM-native syntax via pySigma."""

from __future__ import annotations

from typing import Any


class RuleTranslator:
    """Translate DetectionRule objects to SIEM-native query formats."""

    BACKEND_MAP = {
        "splunk": "pysigma_backend_splunk",
        "opensearch": "pysigma_backend_opensearch",
        "elastic": "pysigma_backend_elasticsearch",
        "sentinel": "pysigma_backend_kusto",
    }

    def translate(self, rule: Any, target_siem: str) -> str:
        """Translate *rule* to the *target_siem* query format."""
        raise NotImplementedError

    def translate_batch(self, rules: list, target_siem: str) -> dict[str, str]:
        """Translate multiple rules; return ``{rule_id: query}``."""
        raise NotImplementedError

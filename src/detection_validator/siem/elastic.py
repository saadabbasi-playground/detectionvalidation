"""Elasticsearch / Elastic Security adapter stub."""

from __future__ import annotations

from typing import Any

from detection_validator.siem.base import SIEMBackend


class ElasticBackend(SIEMBackend):
    name = "elastic"

    def __init__(self, host: str = "localhost", port: int = 9200,
                 api_key: str = "") -> None:
        self.host = host
        self.port = port
        self.api_key = api_key
        self._client = None

    def connect(self) -> None:
        raise NotImplementedError

    def health_check(self) -> bool:
        raise NotImplementedError

    def deploy_rule(self, rule: Any) -> str:
        raise NotImplementedError

    def delete_rule(self, rule_id: str) -> None:
        raise NotImplementedError

    def query(self, query_string: str, time_range: str = "last 1h") -> list[dict]:
        raise NotImplementedError

    def search_for_alerts(self, rule_id: str, time_range: str = "last 1h") -> list[dict]:
        raise NotImplementedError

    def translate_rule(self, rule: Any) -> str:
        raise NotImplementedError

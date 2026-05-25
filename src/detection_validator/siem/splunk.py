"""Splunk SIEM adapter stub."""

from __future__ import annotations

from typing import Any

from detection_validator.siem.base import SIEMBackend


class SplunkBackend(SIEMBackend):
    """Splunk Enterprise / Splunk Cloud adapter using the Splunk SDK."""

    name = "splunk"

    def __init__(self, host: str = "localhost", port: int = 8089,
                 username: str = "admin", password: str = "") -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._service = None

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

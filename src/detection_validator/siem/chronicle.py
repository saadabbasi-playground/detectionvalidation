"""Google Chronicle (SecOps) adapter stub."""

from __future__ import annotations

from typing import Any

from detection_validator.siem.base import SIEMBackend


class ChronicleBackend(SIEMBackend):
    name = "chronicle"

    def __init__(self, customer_id: str = "", region: str = "us",
                 credentials_file: str = "") -> None:
        self.customer_id = customer_id
        self.region = region
        self.credentials_file = credentials_file

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

"""Microsoft Sentinel adapter stub."""

from __future__ import annotations

from typing import Any

from detection_validator.siem.base import SIEMBackend


class SentinelBackend(SIEMBackend):
    name = "sentinel"

    def __init__(self, workspace_id: str = "", primary_key: str = "",
                 tenant_id: str = "", client_id: str = "", client_secret: str = "") -> None:
        self.workspace_id = workspace_id
        self.primary_key = primary_key
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

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

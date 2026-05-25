"""Rule lifecycle management — create, update, disable, delete, audit."""

from __future__ import annotations

from enum import StrEnum


class RuleState(StrEnum):
    DRAFT = "draft"
    DEPLOYED = "deployed"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class RuleLifecycleManager:
    """Track and manage the deployment state of detection rules."""

    def deploy(self, rule_id: str, siem_backend) -> None:
        raise NotImplementedError

    def disable(self, rule_id: str, siem_backend) -> None:
        raise NotImplementedError

    def delete(self, rule_id: str, siem_backend) -> None:
        raise NotImplementedError

    def get_state(self, rule_id: str) -> RuleState:
        raise NotImplementedError

    def audit_log(self, rule_id: str) -> list[dict]:
        raise NotImplementedError

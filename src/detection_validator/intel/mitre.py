"""MITRE ATT&CK intel — thin wrapper that delegates to AttackKnowledgeBase."""

from __future__ import annotations

from pathlib import Path

from detection_validator.mappers.attack_mapper import (
    AttackKnowledgeBase,
    _DEFAULT_CACHE_DIR,
)

CACHE_DIR = _DEFAULT_CACHE_DIR
ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


class MitreIntel:
    """
    Local cache of the MITRE ATT&CK enterprise matrix.

    Delegates to :class:`AttackKnowledgeBase` for all real work.
    """

    def __init__(
        self,
        cache_dir: Path = CACHE_DIR,
        domain: str = "enterprise-attack",
        ttl_days: int = 7,
    ) -> None:
        self._kb = AttackKnowledgeBase(
            domain=domain,
            cache_dir=cache_dir,
            ttl_days=ttl_days,
        )

    def refresh(self, force: bool = False) -> None:
        """Download the ATT&CK bundle if stale or *force* is True."""
        self._kb.ensure_loaded(force_refresh=force)

    def get_technique(self, technique_id: str) -> dict | None:
        t = self._kb.get_technique(technique_id)
        if t is None:
            return None
        return {
            "id": t.technique_id,
            "name": t.name,
            "description": t.description,
            "tactic": t.tactic,
            "deprecated": t.deprecated,
        }

    def all_techniques(self) -> list[dict]:
        self._kb.ensure_loaded()
        return [
            {"id": t.technique_id, "name": t.name, "tactic": t.tactic}
            for t in self._kb.get_all_techniques()
        ]

    def all_tactics(self) -> list[str]:
        self._kb.ensure_loaded()
        return [
            t.get("x-mitre-shortname", t.get("name", ""))
            for t in self._kb.get_tactics()
        ]

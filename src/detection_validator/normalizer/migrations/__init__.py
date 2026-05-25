"""
Schema migration framework for CanonicalDetection.

Each ``v{major}_{minor}.py`` module in this package is a snapshot of the
schema at that version and a migration callable that upgrades a raw dict
from the previous version.

Usage
-----
    from detection_validator.normalizer.migrations import migrate

    raw_dict = load_from_storage(rule_id)          # may be any past version
    upgraded = migrate(raw_dict)                    # always returns current version
    detection = CanonicalDetection.model_validate(upgraded)

Adding a new version
--------------------
1. Bump ``VERSION`` in ``normalizer/schema.py``.
2. Create ``migrations/v{major}_{minor}.py`` with:
   - ``SCHEMA_VERSION = "X.Y"``
   - ``def upgrade(data: dict) -> dict`` — transforms from (X.Y - 1) to X.Y
3. Register the module in ``_MIGRATIONS`` below.
"""

from __future__ import annotations

from typing import Any

from detection_validator.normalizer.migrations import v1_0

# Ordered migration chain: [(from_version, module), ...]
# Each module's ``upgrade()`` transforms data from the previous version.
_MIGRATIONS: list[tuple[str, Any]] = [
    ("1.0", v1_0),
]

# Map version string → module (for introspection / testing)
VERSIONS: dict[str, Any] = {ver: mod for ver, mod in _MIGRATIONS}
CURRENT_VERSION: str = _MIGRATIONS[-1][0]


def _version_of(data: dict[str, Any]) -> str:
    """Sniff the schema version from a raw dict; default to '1.0' if absent."""
    return str(data.get("schema_version", data.get("x-schema-version", "1.0")))


def migrate(data: dict[str, Any]) -> dict[str, Any]:
    """
    Upgrade *data* from its stored schema version to the current version.

    Returns a new dict (the original is not mutated).
    Raises ``ValueError`` for unknown versions.
    """
    data = dict(data)
    src_version = _version_of(data)

    if src_version not in VERSIONS:
        raise ValueError(
            f"Unknown schema version {src_version!r}. "
            f"Known versions: {list(VERSIONS)}"
        )

    # Walk the migration chain starting from the stored version
    applying = False
    for ver, mod in _MIGRATIONS:
        if ver == src_version:
            applying = True
        if applying and ver != src_version:
            data = mod.upgrade(data)

    return data

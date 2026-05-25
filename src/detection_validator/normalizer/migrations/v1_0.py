"""
Schema snapshot and migration for CanonicalDetection v1.0 (initial version).

This module serves two purposes:
1. Documents the exact field set shipped in v1.0 (the snapshot below).
2. Provides ``upgrade()`` as the identity function because 1.0 is the baseline —
   future modules (v1_1, v2_0, …) will contain real transformations.

When adding v1.1
----------------
Create ``migrations/v1_1.py`` with an ``upgrade(data)`` that handles the delta
from 1.0 → 1.1, and register it in ``migrations/__init__._MIGRATIONS``.
"""

from __future__ import annotations

from typing import Any

SCHEMA_VERSION: str = "1.0"

# Canonical field list for v1.0 — keep in sync with CanonicalDetection.
# Used by tools that need to know which fields existed at a given version.
FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "name",
        "description",
        "author",
        "version",
        "created_at",
        "modified_at",
        "severity",
        "source_format",
        "platforms",
        "tags",
        "detection_logic",
        "log_sources",
        "mitre_techniques",
        "cve_references",
        "data_components",
        "false_positive_notes",
        "cim_models",
        "validation_status",
        "last_validated",
        "detection_maturity_score",
        "portability_score",
        "siem_native",
        "deployment_history",
    }
)

# Required fields in v1.0 — any dict missing these is malformed.
REQUIRED: frozenset[str] = frozenset({"id", "name", "detection_logic"})


def upgrade(data: dict[str, Any]) -> dict[str, Any]:
    """
    Upgrade from the version immediately preceding 1.0.

    1.0 is the baseline — nothing to transform.
    This function exists to satisfy the migration chain contract.
    """
    return data


def validate_shape(data: dict[str, Any]) -> list[str]:
    """
    Check that *data* has all required v1.0 fields.

    Returns a list of missing field names (empty = valid).
    """
    return [f for f in REQUIRED if f not in data]

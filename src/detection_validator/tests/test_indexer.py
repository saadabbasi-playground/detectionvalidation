"""Tests for the telemetry index naming convention and canonical constants.

The key invariant: every index produced by the telemetry subsystem
(index_name_for) must be covered by AGENT_INDEX_PATTERN so that
``dv validate`` finds events from BOTH the Vagrant→Vector live pipeline
AND pre-recorded telemetry captures without extra configuration.
"""
from __future__ import annotations

from fnmatch import fnmatch

import pytest

from detection_validator.telemetry.indexer import (
    AGENT_INDEX_PATTERN,
    AGENT_SOURCE_TAG,
    index_name_for,
)


class TestIndexNameFor:
    def test_replay_name(self):
        assert index_name_for("T1003.001", "replay") == "dv-telemetry-replay-t1003-001"

    def test_live_name(self):
        assert index_name_for("T1059.004", "live") == "dv-telemetry-live-t1059-004"

    def test_default_fidelity_is_replay(self):
        assert index_name_for("T1059.001") == "dv-telemetry-replay-t1059-001"

    def test_dot_replaced_with_hyphen(self):
        assert index_name_for("T1003.001", "replay") == "dv-telemetry-replay-t1003-001"

    def test_uppercase_normalised(self):
        assert index_name_for("T1059.004", "live") == "dv-telemetry-live-t1059-004"

    def test_no_leading_trailing_hyphens(self):
        name = index_name_for("T1059.001", "replay")
        assert not name.startswith("-")
        assert not name.endswith("-")


class TestConventionAlignment:
    """Attack-write index must be covered by the validate-read index pattern.

    This is the acceptance test for the unified convention:
      - dv telemetry capture writes to index_name_for(technique, fidelity)
      - dv validate reads from AGENT_INDEX_PATTERN
    Both must agree so that captured events are visible to validate.
    """

    def test_replay_write_index_covered_by_validate_read_pattern(self):
        write_idx = index_name_for("T1003.001", "replay")
        assert fnmatch(write_idx, AGENT_INDEX_PATTERN), (
            f"index_name_for produced {write_idx!r} which is NOT covered by "
            f"AGENT_INDEX_PATTERN={AGENT_INDEX_PATTERN!r}. "
            "Validate would miss events from telemetry capture."
        )

    def test_live_write_index_covered_by_validate_read_pattern(self):
        write_idx = index_name_for("T1059.004", "live")
        assert fnmatch(write_idx, AGENT_INDEX_PATTERN), (
            f"index_name_for produced {write_idx!r} which is NOT covered by "
            f"AGENT_INDEX_PATTERN={AGENT_INDEX_PATTERN!r}. "
            "Validate would miss live-local events."
        )

    def test_agent_source_tag_is_documented_constant(self):
        assert AGENT_SOURCE_TAG == "auditd-agent"

    def test_agent_index_pattern_is_wildcard(self):
        assert AGENT_INDEX_PATTERN.endswith("*"), (
            "AGENT_INDEX_PATTERN must be a wildcard so it covers both "
            "Vector-written date indices and telemetry subsystem indices."
        )

    @pytest.mark.parametrize("technique,fidelity", [
        ("T1003.001", "replay"),
        ("T1059.004", "replay"),
        ("T1078.003", "live"),
        ("T1053.005", "live"),
        ("T1548.002", "replay"),
    ])
    def test_all_techniques_covered(self, technique: str, fidelity: str):
        """Spot-check that diverse technique IDs all fall under the read pattern."""
        write_idx = index_name_for(technique, fidelity)
        assert fnmatch(write_idx, AGENT_INDEX_PATTERN)

"""Bulk-index a TelemetryBatch into an OpenSearch index.

Index naming convention
-----------------------
All DetectionValidator indices share the ``dv-telemetry-`` prefix so that the
wildcard ``dv-telemetry-*`` (AGENT_INDEX_PATTERN) covers:

  • Date-based indices written by the Vagrant→Vector live pipeline, e.g.
    ``dv-telemetry-2024.06.01`` (naming controlled by Vector config).

  • Per-technique indices written by the telemetry subsystem, e.g.
    ``dv-telemetry-replay-t1003-001`` (naming controlled by index_name_for).

This means ``dv validate`` (which queries AGENT_INDEX_PATTERN) sees events
from both the live attack pipeline and pre-recorded replay captures without
any additional configuration.

Source field convention
-----------------------
Events from the Vagrant victim-agent are tagged with the field
``source = AGENT_SOURCE_TAG`` ("auditd-agent") by the victim-agent process
before Vector ships them to OpenSearch.  Code that needs to filter
agent-originated events (e.g. ``dv attack --watch``) must import
AGENT_SOURCE_TAG rather than hard-coding the string.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection_validator.telemetry.base import TelemetryBatch


# ── Canonical constants ───────────────────────────────────────────────────────

# Value of the ``source`` field stamped on events by the victim-agent / Vector.
AGENT_SOURCE_TAG: str = "auditd-agent"

# Wildcard index pattern that matches all detectval-managed indices, including
# both Vagrant→Vector date-based indices AND telemetry-subsystem technique indices.
AGENT_INDEX_PATTERN: str = "dv-telemetry-*"


def index_name_for(technique_id: str, fidelity: str = "replay") -> str:
    """Return the OpenSearch index name for a technique and fidelity.

    Convention: all indices produced by the telemetry subsystem are prefixed
    with ``dv-telemetry-`` so they are covered by AGENT_INDEX_PATTERN.

    Examples:
      T1003.001, "replay" → dv-telemetry-replay-t1003-001
      T1059.004, "live"   → dv-telemetry-live-t1059-004
    """
    tid = technique_id.lower().replace(".", "-")
    return f"dv-telemetry-{fidelity}-{tid}"


def _event_to_doc(ev) -> dict:
    """Convert a TelemetryEvent to a flat OpenSearch document."""
    doc = {
        "technique_id": ev.technique_id,
        "source_fidelity": ev.source_fidelity,
        "@timestamp": ev.timestamp.isoformat(),
        "Image": ev.Image,
        "CommandLine": ev.CommandLine,
        "ParentImage": ev.ParentImage,
        "ParentCommandLine": ev.ParentCommandLine,
        "ProcessId": ev.ProcessId,
        "User": ev.User,
        "EventID": ev.EventID,
        "Channel": ev.Channel,
        "Computer": ev.Computer,
    }
    # Merge extra fields; don't let them overwrite mandatory fields
    for k, v in (ev.extra or {}).items():
        doc.setdefault(k, v)
    # Drop nulls — OpenSearch accepts them but they clutter mappings
    return {k: v for k, v in doc.items() if v is not None}


def bulk_index(batch: "TelemetryBatch", os_url: str = "http://localhost:9200") -> tuple[int, list[str]]:
    """Bulk-index *batch* into OpenSearch.

    Returns ``(indexed_count, errors)`` where ``errors`` is a list of
    per-document error strings (empty on full success).

    Raises ``IndexError`` with a friendly message if the server is not
    reachable so callers can print it and continue.
    """
    try:
        from opensearchpy import OpenSearch, helpers, RequestError
    except ImportError as exc:
        raise ImportError("opensearch-py is required for indexing: pip install opensearch-py") from exc

    host, port = _parse_url(os_url)
    client = OpenSearch(
        hosts=[{"host": host, "port": port}],
        use_ssl=False,
        verify_certs=False,
        http_compress=True,
        timeout=30,
    )

    # Verify reachability before wasting time on bulk prep
    try:
        client.cluster.health(request_timeout=5)
    except Exception as exc:
        raise IndexError(
            f"OpenSearch not reachable at {os_url}: {exc}\n"
            "  Start the local stack: dv siem up"
        ) from exc

    idx = index_name_for(batch.technique_id, batch.fidelity)

    # Create index with a single shard if it doesn't exist
    if not client.indices.exists(index=idx):
        client.indices.create(
            index=idx,
            body={
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "technique_id": {"type": "keyword"},
                        "source_fidelity": {"type": "keyword"},
                        "Image": {"type": "keyword"},
                        "CommandLine": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                        "ParentImage": {"type": "keyword"},
                        "EventID": {"type": "integer"},
                        "ProcessId": {"type": "integer"},
                    }
                },
            },
        )

    actions = [
        {"_index": idx, "_source": _event_to_doc(ev)}
        for ev in batch.events
    ]

    success, failed = helpers.bulk(client, actions, raise_on_error=False, stats_only=False)
    errors = []
    if isinstance(failed, list):
        for item in failed:
            if isinstance(item, dict):
                err = item.get("index", {}).get("error", {})
                errors.append(str(err))
    return success, errors


def _parse_url(url: str) -> tuple[str, int]:
    """Extract (host, port) from a base URL like http://localhost:9200."""
    url = url.rstrip("/")
    # Strip scheme
    if "://" in url:
        url = url.split("://", 1)[1]
    if ":" in url:
        host, port_s = url.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            pass
    return url, 9200

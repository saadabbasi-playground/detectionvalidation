"""Bulk-index a TelemetryBatch into an OpenSearch index.

The index name follows the convention ``telemetry-replay-{technique}`` where
the technique ID is lowercased and dots are replaced with hyphens, e.g.
T1003.001 → telemetry-replay-t1003-001.

The caller is responsible for providing the OpenSearch base URL. If the server
is not reachable this module raises ``IndexError`` with a friendly message so
the CLI can degrade gracefully rather than showing a traceback.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection_validator.telemetry.base import TelemetryBatch


def index_name_for(technique_id: str) -> str:
    return f"telemetry-replay-{technique_id.lower().replace('.', '-')}"


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

    idx = index_name_for(batch.technique_id)

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

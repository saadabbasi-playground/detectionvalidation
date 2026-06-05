"""Fully offline ReplaySource backed by OTRF Security-Datasets.

Workflow for ``ensure(technique_id, platform)``:
  1. If the caller provided a ``file_path``, load events from that file.
  2. Otherwise, discover matching datasets in the OTRF Security-Datasets GitHub
     repo by verifying the actual directory layout via the GitHub API at runtime.
  3. Download the first matching dataset and cache it under ``data/otrf/``.
  4. Normalise every event to the ECS/Sysmon-aligned TelemetryEvent schema.
  5. Return a TelemetryBatch — the caller (CLI) bulk-indexes it into OpenSearch.

All network I/O is isolated to ``_OTRFCatalog``.  ReplaySource itself is
testable with a fake catalog injected via the constructor.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from detection_validator.telemetry.base import (
    NotAvailable,
    SourceDescription,
    TelemetryBatch,
    TelemetrySource,
)
from detection_validator.telemetry.normalizer import normalize_events

# ── OTRF repo constants ───────────────────────────────────────────────────────

_GITHUB_API = "https://api.github.com/repos/OTRF/Security-Datasets"
_RAW_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/main"

# Default cache lives in data/otrf/ at the repo root (3 levels above this file)
_DEFAULT_CACHE = Path(__file__).parents[3] / "data" / "otrf"

# Technique ID normalisations used for path searching
# T1003.001 → ["t1003.001", "t1003_001", "t1003-001", "t1003001"]
def _technique_variants(tid: str) -> list[str]:
    base = tid.lower()
    return [
        base,
        base.replace(".", "_"),
        base.replace(".", "-"),
        base.replace(".", ""),
    ]


# ── Catalog: discovers available OTRF datasets ────────────────────────────────


class _OTRFCatalog:
    """Discovers OTRF dataset paths via the GitHub git-tree API.

    The catalog is a list of dicts with at minimum:
      {"path": "datasets/atomic/windows/…/foo.json", "url": "<blob_url>"}

    The JSON catalog is cached for 24 hours under ``cache_dir/_catalog.json``.
    """

    _CATALOG_TTL = 86_400  # 24 hours

    def __init__(self, cache_dir: Path) -> None:
        self._cache_dir = cache_dir
        self._catalog_path = cache_dir / "_catalog.json"

    def entries(self) -> list[dict]:
        """Return the full catalog, fetching from GitHub if stale."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        if self._catalog_path.exists():
            age = time.time() - self._catalog_path.stat().st_mtime
            if age < self._CATALOG_TTL:
                return json.loads(self._catalog_path.read_text(encoding="utf-8"))
        catalog = self._fetch()
        self._catalog_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
        return catalog

    def _fetch(self) -> list[dict]:
        """Fetch the git tree from the OTRF repo and return JSON-able entries."""
        # We query datasets/ only — much smaller tree than the entire repo
        try:
            # First get the SHA for the datasets/ tree
            req = urllib.request.Request(
                f"{_GITHUB_API}/contents/datasets",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "dv-telemetry/1"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                top = json.loads(resp.read())

            # Find the 'atomic' subfolder sha
            datasets_sha = None
            for item in top if isinstance(top, list) else []:
                if item.get("name") == "atomic" and item.get("type") == "dir":
                    datasets_sha = item.get("sha")
                    break

            if not datasets_sha:
                # Fall back to a recursive tree of the whole repo (may be truncated)
                return self._fetch_full_tree()

            # Recursively expand datasets/atomic tree
            url = f"{_GITHUB_API}/git/trees/{datasets_sha}?recursive=1"
            req2 = urllib.request.Request(
                url,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "dv-telemetry/1"},
            )
            with urllib.request.urlopen(req2, timeout=30) as resp2:
                data = json.loads(resp2.read())

            entries = []
            prefix = "datasets/atomic"
            for item in data.get("tree", []):
                if item.get("type") != "blob":
                    continue
                path = f"{prefix}/{item['path']}"
                entries.append({"path": path, "sha": item.get("sha", "")})
            return entries

        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise NotAvailable(
                    "GitHub API rate limit hit. Set GITHUB_TOKEN env var to increase limits, "
                    "or use --file to supply a local dataset."
                )
            raise NotAvailable(f"GitHub API error {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            raise NotAvailable(
                f"Cannot reach GitHub API: {exc.reason}. "
                "Check network connectivity or use --file."
            )

    def _fetch_full_tree(self) -> list[dict]:
        """Fallback: fetch the full repo tree (may be truncated by GitHub)."""
        url = f"{_GITHUB_API}/git/trees/HEAD?recursive=1"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "dv-telemetry/1"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return [
            {"path": item["path"], "sha": item.get("sha", "")}
            for item in data.get("tree", [])
            if item.get("type") == "blob"
            and "datasets" in item.get("path", "")
        ]

    def find(self, technique_id: str, platform: str) -> list[dict]:
        """Return catalog entries matching *technique_id* and *platform*."""
        variants = _technique_variants(technique_id)
        plat = platform.lower()
        results = []
        for entry in self.entries():
            path = entry.get("path", "").lower()
            # Must be a parseable data file
            if not (path.endswith(".json") or path.endswith(".jsonl")):
                continue
            # Must be in the right platform subtree
            if plat not in path:
                continue
            # Must contain the technique ID in some form
            if any(v in path for v in variants):
                results.append(entry)
        return results


# ── Downloader ────────────────────────────────────────────────────────────────


def _download_raw(path: str) -> bytes:
    """Download a raw file from the OTRF repo."""
    url = f"{_RAW_BASE}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "dv-telemetry/1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise NotAvailable(f"Download failed for {path}: HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise NotAvailable(f"Download failed for {path}: {exc.reason}")


def _parse_raw_bytes(data: bytes, path: str) -> list[dict]:
    """Parse raw bytes as JSON array, JSONL, or a zip containing either."""
    if path.endswith(".zip"):
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.endswith((".json", ".jsonl")):
                    return _parse_raw_bytes(zf.read(name), name)
        return []
    text = data.decode("utf-8", errors="replace")
    # Try JSON array first
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            # Some OTRF files wrap events in a key
            for key in ("events", "data", "hits"):
                if isinstance(parsed.get(key), list):
                    return parsed[key]
            return [parsed]
    except json.JSONDecodeError:
        pass
    # Try JSONL
    events = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                pass
    return events


# ── Full ReplaySource implementation ─────────────────────────────────────────


class ReplaySource(TelemetrySource):
    """Offline replay source backed by OTRF Security-Datasets or a local file.

    Parameters
    ----------
    file_path:
        If provided, events are loaded directly from this local JSON/JSONL file.
        No network access is performed.
    cache_dir:
        Directory for the OTRF catalog cache and downloaded datasets.
        Defaults to ``data/otrf/`` in the repo root.
    catalog:
        Inject a pre-built ``_OTRFCatalog`` for testing.
    """

    def __init__(
        self,
        file_path: Path | str | None = None,
        cache_dir: Path | None = None,
        catalog: _OTRFCatalog | None = None,
    ) -> None:
        self._file_path = Path(file_path) if file_path else None
        self._cache_dir = cache_dir or _DEFAULT_CACHE
        self._catalog = catalog or _OTRFCatalog(self._cache_dir)

    def describe(self) -> SourceDescription:
        return SourceDescription(
            name="replay",
            fidelity="replay",
            supported_platforms=["windows", "linux", "macos"],
        )

    def ensure(self, technique_id: str, platform: str = "windows") -> TelemetryBatch:
        """Fetch, normalise, and return a TelemetryBatch for *technique_id*.

        If ``file_path`` was provided at construction, load from that file.
        Otherwise, discover and download from OTRF Security-Datasets, caching
        the result under ``data/otrf/``.

        Raises ``NotAvailable`` when no dataset can be found or parsed.
        """
        if self._file_path:
            raw_events, label = self._load_local(self._file_path)
        else:
            raw_events, label = self._fetch_otrf(technique_id, platform)

        events = normalize_events(raw_events, technique_id)
        if not events:
            raise NotAvailable(
                f"Dataset '{label}' exists for {technique_id} but contains "
                "no parseable events after normalization."
            )

        return TelemetryBatch(
            technique_id=technique_id,
            source_name=f"otrf:{label}",
            fidelity="replay",
            events=events,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _load_local(self, path: Path) -> tuple[list[dict], str]:
        if not path.exists():
            raise NotAvailable(f"--file not found: {path}")
        data = path.read_bytes()
        events = _parse_raw_bytes(data, str(path))
        if not events:
            raise NotAvailable(f"No events parsed from {path}")
        return events, path.name

    def _fetch_otrf(self, technique_id: str, platform: str) -> tuple[list[dict], str]:
        """Find a dataset in the OTRF catalog and return (events, label)."""
        matches = self._catalog.find(technique_id, platform)
        if not matches:
            raise NotAvailable(
                f"No OTRF Security-Dataset found for technique={technique_id} "
                f"platform={platform}.\n"
                "  Browse datasets: https://github.com/OTRF/Security-Datasets/tree/main/datasets\n"
                "  Or supply your own: dv telemetry capture --technique ... --file events.json"
            )

        # Prefer smaller files (less download time on a laptop); pick first found
        entry = matches[0]
        repo_path = entry["path"]
        label = Path(repo_path).name

        # Check local cache
        cache_file = self._cache_dir / technique_id / label
        if not cache_file.exists():
            raw = _download_raw(repo_path)
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_bytes(raw)
        else:
            raw = cache_file.read_bytes()

        events = _parse_raw_bytes(raw, repo_path)
        if not events:
            raise NotAvailable(f"Downloaded dataset '{label}' contained no parseable events.")

        return events, label

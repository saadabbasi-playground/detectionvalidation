"""Abstract base class for CVE intelligence source fetchers."""

from __future__ import annotations

import gzip
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CVEFetchError(Exception):
    """Raised when a source fetch fails unrecoverably."""


class CVEFetcher(ABC):
    """
    Protocol for a CVE intelligence source.

    Concrete implementations live in this package; each maps to a ``fetcher``
    name in ``configs/cve_sources.yaml``.
    """

    #: Unique name matching the ``fetcher`` field in cve_sources.yaml
    name: str = "base"

    def __init__(self, cache_dir: Path, config: dict[str, Any]) -> None:
        self.cache_dir = cache_dir
        self.config = config
        self.ttl_days: int = int(config.get("ttl_days", 1))

    # ── Cache helpers ─────────────────────────────────────────────────────────

    def _cache_path(self, filename: str) -> Path:
        return self.cache_dir / filename

    def _meta_path(self, filename: str) -> Path:
        return self.cache_dir / (filename + ".meta")

    def is_cache_valid(self, filename: str) -> bool:
        cache = self._cache_path(filename)
        meta = self._meta_path(filename)
        if not cache.exists() or not meta.exists():
            return False
        try:
            m = json.loads(meta.read_text())
            saved = datetime.fromisoformat(m["saved_at"])
            return datetime.now(tz=timezone.utc) - saved < timedelta(days=self.ttl_days)
        except Exception:
            return False

    def load_cache(self, filename: str) -> dict[str, Any]:
        path = self._cache_path(filename)
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        return json.loads(path.read_text(encoding="utf-8"))

    def save_cache(self, filename: str, data: dict[str, Any]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_path(filename)
        if path.suffix == ".gz":
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                json.dump(data, fh)
        else:
            path.write_text(json.dumps(data), encoding="utf-8")
        self._meta_path(filename).write_text(
            json.dumps({"saved_at": datetime.now(tz=timezone.utc).isoformat(),
                        "source": self.name}),
            encoding="utf-8",
        )

    # ── Abstract interface ────────────────────────────────────────────────────

    def fetch_catalog(self) -> dict[str, Any]:
        """Download and return a full catalog (KEV, CTID).  Override if supported."""
        raise NotImplementedError(f"{self.name} does not support fetch_catalog()")

    def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch metadata for a single CVE.  Override if supported."""
        raise NotImplementedError(f"{self.name} does not support fetch_cve()")

    def fetch_batch(self, cve_ids: list[str]) -> dict[str, Any]:
        """Fetch metadata for multiple CVEs at once.  Override for batch sources."""
        result: dict[str, Any] = {}
        for cve_id in cve_ids:
            try:
                data = self.fetch_cve(cve_id)
                if data:
                    result[cve_id] = data
            except Exception as exc:
                logger.warning("%s: fetch failed for %s: %s", self.name, cve_id, exc)
        return result

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

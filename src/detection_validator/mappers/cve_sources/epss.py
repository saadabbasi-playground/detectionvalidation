"""EPSS (Exploit Prediction Scoring System) fetcher from api.first.org."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import requests

from detection_validator.mappers.cve_sources.base import CVEFetcher, CVEFetchError

logger = logging.getLogger(__name__)

_CACHE_FILE = "epss_scores.json"
_EPSS_API = "https://api.first.org/data/v1/epss"


class EPSSFetcher(CVEFetcher):
    """Fetch EPSS exploitation probability scores (0-1) from FIRST.org."""

    name = "epss"

    def __init__(self, cache_dir: Path, config: dict[str, Any]) -> None:
        super().__init__(cache_dir, config)
        self._base_url = config.get("base_url", _EPSS_API)
        self._timeout = int(config.get("timeout", 30))
        self._batch_size = int(config.get("batch_size", 100))

    def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        return self.fetch_batch([cve_id]).get(cve_id)

    def fetch_batch(self, cve_ids: list[str]) -> dict[str, Any]:
        """Fetch EPSS scores; uses per-CVE cache, downloads only missing entries."""
        store = self._load_store()
        missing = [c for c in cve_ids if c not in store]

        # Download in batches
        for i in range(0, len(missing), self._batch_size):
            chunk = missing[i: i + self._batch_size]
            batch_result = self._fetch_chunk(chunk)
            store.update(batch_result)

        if missing:
            self.save_cache(_CACHE_FILE, store)

        return {c: store[c] for c in cve_ids if c in store}

    def _fetch_chunk(self, cve_ids: list[str]) -> dict[str, Any]:
        params = {"cve": ",".join(cve_ids)}
        try:
            resp = requests.get(self._base_url, params=params, timeout=self._timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise CVEFetchError(f"EPSS request failed: {exc}") from exc

        data = resp.json()
        result: dict[str, Any] = {}
        for entry in data.get("data") or []:
            cve_id = entry.get("cve", "").upper()
            if cve_id:
                result[cve_id] = {
                    "epss": float(entry.get("epss", 0.0)),
                    "percentile": float(entry.get("percentile", 0.0)),
                    "date": entry.get("date", ""),
                }
        return result

    def _load_store(self) -> dict[str, Any]:
        if self.is_cache_valid(_CACHE_FILE):
            try:
                return self.load_cache(_CACHE_FILE)
            except Exception:
                pass
        return {}

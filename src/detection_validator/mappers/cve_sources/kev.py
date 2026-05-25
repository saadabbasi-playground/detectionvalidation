"""CISA Known Exploited Vulnerabilities (KEV) catalog fetcher."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import requests

from detection_validator.mappers.cve_sources.base import CVEFetcher, CVEFetchError

logger = logging.getLogger(__name__)

_CACHE_FILE = "kev_catalog.json.gz"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVFetcher(CVEFetcher):
    """Download the full CISA KEV catalog and index it by CVE ID."""

    name = "kev"

    def __init__(self, cache_dir: Path, config: dict[str, Any]) -> None:
        super().__init__(cache_dir, config)
        self._url = config.get("url", _KEV_URL)
        self._timeout = int(config.get("timeout", 30))

    def fetch_catalog(self) -> dict[str, Any]:
        """
        Return dict mapping CVE ID → KEV entry.

        Loads from cache if still fresh; downloads otherwise.
        """
        if self.is_cache_valid(_CACHE_FILE):
            try:
                return self.load_cache(_CACHE_FILE)
            except Exception:
                pass

        logger.info("Downloading CISA KEV catalog from %s", self._url)
        try:
            resp = requests.get(self._url, timeout=self._timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise CVEFetchError(f"KEV download failed: {exc}") from exc

        raw = resp.json()
        catalog: dict[str, Any] = {}
        for entry in raw.get("vulnerabilities") or []:
            cve_id = entry.get("cveID", "")
            if cve_id:
                catalog[cve_id] = {
                    "cve_id": cve_id,
                    "vendor": entry.get("vendorProject", ""),
                    "product": entry.get("product", ""),
                    "name": entry.get("vulnerabilityName", ""),
                    "date_added": entry.get("dateAdded", ""),
                    "due_date": entry.get("dueDate", ""),
                    "short_description": entry.get("shortDescription", ""),
                    "required_action": entry.get("requiredAction", ""),
                    "notes": entry.get("notes", ""),
                }

        self.save_cache(_CACHE_FILE, catalog)
        logger.info("KEV catalog: %d entries cached", len(catalog))
        return catalog

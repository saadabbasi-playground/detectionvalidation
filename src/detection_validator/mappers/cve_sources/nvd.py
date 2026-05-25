"""NVD CVE 2.0 API fetcher — CVSS, CWE, CPE affected products."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

import requests

from detection_validator.mappers.cve_sources.base import CVEFetcher, CVEFetchError

logger = logging.getLogger(__name__)

_CACHE_FILE = "nvd_cves.json.gz"
_NVD_API_V2 = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_nvd_cve(cve_obj: dict[str, Any]) -> dict[str, Any]:
    """Normalise one NVD v2 CVE object into our internal format."""
    cve_id = cve_obj.get("id", "")

    # Description (English preferred)
    descriptions = cve_obj.get("descriptions") or []
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS — prefer v3.1 > v3.0 > v2
    metrics = cve_obj.get("metrics") or {}
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    severity: str | None = None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0] if entries else None)
        if primary:
            data = primary.get("cvssData") or {}
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")
            cvss_version = data.get("version")
            severity = (
                data.get("baseSeverity")
                or primary.get("baseSeverity")
                or ""
            ).upper() or None
            break

    # CWEs
    weaknesses = cve_obj.get("weaknesses") or []
    cwes: list[str] = []
    for w in weaknesses:
        for d in w.get("description") or []:
            val = d.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)

    # CPE strings
    cpes: list[str] = []
    for cfg in cve_obj.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                c = match.get("criteria", "")
                if c and c not in cpes:
                    cpes.append(c)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
        "severity": severity,
        "cwes": cwes,
        "cpes": cpes,
        "published": cve_obj.get("published"),
        "modified": cve_obj.get("lastModified"),
    }


class NVDFetcher(CVEFetcher):
    """Fetch CVE metadata from the NVD CVE 2.0 API."""

    name = "nvd"

    def __init__(self, cache_dir: Path, config: dict[str, Any]) -> None:
        super().__init__(cache_dir, config)
        self._base_url = config.get("base_url", _NVD_API_V2)
        self._timeout = int(config.get("timeout", 30))
        self._rate_sleep = float(config.get("rate_limit_sleep", 0.6))
        self._api_key = config.get("api_key") or os.environ.get("NVDAPIKEY")

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self._api_key:
            h["apiKey"] = self._api_key
            self._rate_sleep = 0.1  # NVD allows 50 req/30s with key
        return h

    def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        url = self._base_url
        params = {"cveId": cve_id}
        time.sleep(self._rate_sleep)
        try:
            resp = requests.get(url, params=params, headers=self._headers(),
                                timeout=self._timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise CVEFetchError(f"NVD request failed for {cve_id}: {exc}") from exc

        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return None
        return _parse_nvd_cve(vulns[0]["cve"])

    def fetch_batch(self, cve_ids: list[str]) -> dict[str, Any]:
        """Fetch multiple CVEs, using the cached store for known ones."""
        cache = self._load_store()
        missing = [c for c in cve_ids if c not in cache]
        for cve_id in missing:
            try:
                result = self.fetch_cve(cve_id)
                if result:
                    cache[cve_id] = result
            except CVEFetchError as exc:
                logger.warning("NVD fetch error: %s", exc)
        if missing:
            self.save_cache(_CACHE_FILE, cache)
        return {c: cache[c] for c in cve_ids if c in cache}

    def _load_store(self) -> dict[str, Any]:
        if self.is_cache_valid(_CACHE_FILE):
            try:
                return self.load_cache(_CACHE_FILE)
            except Exception:
                pass
        return {}

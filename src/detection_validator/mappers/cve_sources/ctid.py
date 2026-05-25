"""CTID ATT&CK-to-CVE mapping fetcher.

Supports CSV (primary) and JSON (fallback) from the CTID GitHub repository.

Expected CSV columns (flexible, matched by header name):
  CVE, Technique, Tactic, Score, Reference
  OR  cve_id, technique_id, tactic, ...

Expected JSON format:
  { "CVE-YYYY-NNNNN": ["T1234", "T1234.567"], ... }
  OR  [ { "cve": "...", "technique": "...", "tactic": "..." }, ... ]
"""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path
from typing import Any

import requests

from detection_validator.mappers.cve_sources.base import CVEFetcher, CVEFetchError

logger = logging.getLogger(__name__)

_CACHE_FILE = "ctid_mappings.json.gz"

# Column name aliases — CVE column
_CVE_COLS = {"cve", "cve_id", "cve id"}
# All technique columns present in the CTID CSV (primary, secondary, exploitation)
_TECH_COLS = {
    "technique", "technique_id", "attack technique", "attack_technique", "techniques",
    "primary impact", "secondary impact", "exploitation technique", "uncategorized",
}


def _col_indices(header: list[str], candidates: set[str]) -> list[int]:
    return [i for i, h in enumerate(header) if h.strip().lower() in candidates]


def _col_index(header: list[str], candidates: set[str]) -> int | None:
    indices = _col_indices(header, candidates)
    return indices[0] if indices else None


def _extract_techniques(cell: str) -> list[str]:
    """Split a cell that may contain T-codes separated by commas or semicolons."""
    parts = cell.replace(";", ",").split(",")
    return [p.strip() for p in parts if p.strip().upper().startswith("T")]


def _parse_csv(text: str) -> dict[str, list[str]]:
    """Parse CTID CSV → {CVE_ID: [technique_id, ...]}."""
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return {}

    header = [c.strip().lower() for c in rows[0]]
    cve_idx = _col_index(header, _CVE_COLS)
    tech_indices = _col_indices(header, _TECH_COLS)

    if cve_idx is None or not tech_indices:
        logger.warning("CTID CSV: could not find CVE/technique columns in header: %s", header)
        return {}

    result: dict[str, list[str]] = {}
    for row in rows[1:]:
        if len(row) <= cve_idx:
            continue
        cve_id = row[cve_idx].strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        for idx in tech_indices:
            if idx >= len(row):
                continue
            for t in _extract_techniques(row[idx]):
                if t not in result.get(cve_id, []):
                    result.setdefault(cve_id, []).append(t)
    return result


def _parse_json(data: Any) -> dict[str, list[str]]:
    """Parse CTID JSON → {CVE_ID: [technique_id, ...]}."""
    result: dict[str, list[str]] = {}
    if isinstance(data, dict):
        # { "CVE-2021-44228": ["T1190", "T1059"], ... }
        for cve_id, techs in data.items():
            if not cve_id.upper().startswith("CVE-"):
                continue
            t_list = techs if isinstance(techs, list) else [str(techs)]
            result[cve_id.upper()] = [str(t).strip() for t in t_list if t]
    elif isinstance(data, list):
        # [ { "cve": "...", "technique": "..." }, ... ]
        for entry in data:
            if not isinstance(entry, dict):
                continue
            cve_id = (entry.get("cve") or entry.get("cve_id") or "").upper()
            tech = str(entry.get("technique") or entry.get("technique_id") or "").strip()
            if cve_id.startswith("CVE-") and tech:
                result.setdefault(cve_id, []).append(tech)
    return result


class CTIDFetcher(CVEFetcher):
    """Fetch ATT&CK-to-CVE mappings from the CTID GitHub project."""

    name = "ctid"

    def __init__(self, cache_dir: Path, config: dict[str, Any]) -> None:
        super().__init__(cache_dir, config)
        self._url = config.get("url", "")
        self._fallback_url = config.get("fallback_url", "")
        self._timeout = int(config.get("timeout", 30))

    def fetch_catalog(self) -> dict[str, Any]:
        if self.is_cache_valid(_CACHE_FILE):
            try:
                return self.load_cache(_CACHE_FILE)
            except Exception:
                pass

        urls = [u for u in [self._url, self._fallback_url] if u]
        last_exc: Exception | None = None

        for url in urls:
            logger.info("Fetching CTID mappings from %s", url)
            try:
                resp = requests.get(url, timeout=self._timeout)
                resp.raise_for_status()
                text = resp.text.lstrip("﻿")  # strip UTF-8 BOM if present

                if url.endswith(".csv") or "csv" in resp.headers.get("content-type", ""):
                    mappings = _parse_csv(text)
                else:
                    mappings = _parse_json(resp.json())

                catalog: dict[str, Any] = {
                    cve_id: {"techniques": techs}
                    for cve_id, techs in mappings.items()
                }
                self.save_cache(_CACHE_FILE, catalog)
                logger.info("CTID: %d CVE→technique mappings cached", len(catalog))
                return catalog

            except Exception as exc:
                last_exc = exc
                logger.warning("CTID fetch from %s failed: %s", url, exc)
                continue

        if last_exc:
            raise CVEFetchError(f"All CTID fetch attempts failed: {last_exc}") from last_exc
        return {}

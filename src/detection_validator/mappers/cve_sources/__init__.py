"""CVE source registry — loads fetchers declared in configs/cve_sources.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from detection_validator.mappers.cve_sources.base import CVEFetchError, CVEFetcher
from detection_validator.mappers.cve_sources.ctid import CTIDFetcher
from detection_validator.mappers.cve_sources.epss import EPSSFetcher
from detection_validator.mappers.cve_sources.kev import KEVFetcher
from detection_validator.mappers.cve_sources.nvd import NVDFetcher

_REGISTRY: dict[str, type[CVEFetcher]] = {
    "nvd": NVDFetcher,
    "kev": KEVFetcher,
    "ctid": CTIDFetcher,
    "epss": EPSSFetcher,
}


def build_fetchers(config_path: Path, cache_dir: Path) -> dict[str, CVEFetcher]:
    """Load cve_sources.yaml and instantiate every enabled fetcher."""
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    sources: dict[str, Any] = (raw or {}).get("sources", {})
    fetchers: dict[str, CVEFetcher] = {}
    for name, source_cfg in sources.items():
        if not source_cfg.get("enabled", True):
            continue
        fetcher_key = source_cfg.get("fetcher", name)
        cls = _REGISTRY.get(fetcher_key)
        if cls is None:
            continue
        fetchers[name] = cls(cache_dir=cache_dir, config=source_cfg)
    return fetchers


def register_fetcher(name: str, cls: type[CVEFetcher]) -> None:
    """Register a custom fetcher class so build_fetchers can discover it."""
    _REGISTRY[name] = cls


__all__ = [
    "build_fetchers",
    "register_fetcher",
    "CVEFetcher",
    "CVEFetchError",
]

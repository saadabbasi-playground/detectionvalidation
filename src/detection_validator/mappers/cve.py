"""CVE / NVD mapper stub — enriches detections with vulnerability data."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CVEInfo:
    id: str
    description: str
    cvss_v3_score: float | None
    cvss_v3_severity: str | None
    published: str | None
    affected_products: list[str]


class CVEMapper:
    """Enrich detection rules with CVE/CVSS metadata from the NVD intel cache."""

    def get(self, cve_id: str) -> CVEInfo | None:
        """Return CVE metadata or None if not in cache."""
        raise NotImplementedError

    def search(self, keyword: str) -> list[CVEInfo]:
        """Full-text search across cached CVE descriptions."""
        raise NotImplementedError

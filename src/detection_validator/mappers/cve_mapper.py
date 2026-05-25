"""CVE correlation — maps CVEs to ATT&CK techniques, then checks detection coverage.

Pipeline
--------
1. ``CVEKnowledgeBase.get(cve_id)``
   Merges NVD metadata, CISA KEV membership, CTID technique mappings, and
   EPSS exploitation-probability scores into a single ``CVERecord``.

2. ``CVEToTechniqueMapper.map_cve(cve_id)``
   Produces ``TechniqueMapping`` objects via three ordered passes:
     a. CTID   — direct ATT&CK-to-CVE mappings (highest confidence)
     b. CWE    — ``configs/cwe_technique_map.yaml`` heuristic inference
     c. LLM    — optional Anthropic gap-fill (``--llm``)
   Duplicate technique IDs are deduplicated, keeping the highest confidence.

3. ``CVECoverageAnalyzer.analyze(cve_id, detections)``
   Checks the detection corpus for technique coverage, then computes:
     residual_risk = CVSS_score × EPSS_score × (1 − coverage_ratio)

CLI
---
  dv cve-coverage --cve CVE-2021-44228 [--detections canonical.jsonl]
  dv intel update --source cve [--cve CVE-2021-44228]
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from detection_validator.mappers.cve_sources import build_fetchers
from detection_validator.mappers.cve_sources.base import CVEFetchError, CVEFetcher
from detection_validator.normalizer.schema import CanonicalDetection

try:
    import anthropic as _anthropic_lib
    from jinja2 import Environment, FileSystemLoader

    HAS_LLM = True
except ImportError:
    HAS_LLM = False

logger = logging.getLogger(__name__)

_PACKAGE_ROOT = Path(__file__).parents[1]
_DEFAULT_CACHE_DIR = _PACKAGE_ROOT / "intel" / "cve_cache"
_DEFAULT_CONFIG_DIR = Path(__file__).parents[3] / "configs"

# ─── Data models ──────────────────────────────────────────────────────────────


@dataclass
class CVERecord:
    """Merged view of a single CVE across all enabled sources."""

    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    severity: str | None = None
    cwes: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    # KEV fields
    in_kev: bool = False
    kev_date_added: str | None = None
    kev_vendor: str | None = None
    kev_product: str | None = None
    # CTID direct technique mappings
    ctid_techniques: list[str] = field(default_factory=list)
    # EPSS exploitation probability
    epss_score: float | None = None
    epss_percentile: float | None = None


@dataclass
class TechniqueMapping:
    """One CVE → ATT&CK technique mapping with provenance."""

    technique_id: str
    tactic: str
    confidence: float
    source: str      # "ctid" | "cwe" | "llm" | "ctid+cwe" | ...
    reasoning: str = ""


@dataclass
class CVETechniqueResult:
    """All technique mappings for a single CVE."""

    cve_id: str
    record: CVERecord | None
    techniques: list[TechniqueMapping]
    sources_used: list[str]
    errors: list[str] = field(default_factory=list)


@dataclass
class CVECoverageResult:
    """Detection corpus coverage analysis for one CVE."""

    cve_id: str
    cvss_score: float | None
    epss_score: float | None
    in_kev: bool
    techniques: list[TechniqueMapping]
    covered_technique_ids: list[str]
    uncovered_technique_ids: list[str]
    coverage_ratio: float
    residual_risk_score: float
    covering_detections: dict[str, list[str]]   # technique_id → [detection names]


# ─── CVEKnowledgeBase ─────────────────────────────────────────────────────────


class CVEKnowledgeBase:
    """
    Unified multi-source CVE intelligence store.

    Lazily loads KEV and CTID catalogs on first use.  Per-CVE NVD + EPSS
    lookups are cached in-memory for the lifetime of the instance.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        config_path: Path | None = None,
        fetchers: dict[str, CVEFetcher] | None = None,
    ) -> None:
        self._cache_dir = cache_dir or _DEFAULT_CACHE_DIR
        self._config_path = config_path or (_DEFAULT_CONFIG_DIR / "cve_sources.yaml")
        self._fetchers: dict[str, CVEFetcher] = fetchers or {}
        if not self._fetchers and self._config_path.exists():
            self._fetchers = build_fetchers(self._config_path, self._cache_dir)

        self._kev_catalog: dict[str, Any] | None = None
        self._ctid_catalog: dict[str, Any] | None = None
        self._record_cache: dict[str, CVERecord] = {}

    # ── Catalog lazy-loaders ──────────────────────────────────────────────────

    def _kev(self) -> dict[str, Any]:
        if self._kev_catalog is None:
            fetcher = self._fetchers.get("kev")
            if fetcher:
                try:
                    self._kev_catalog = fetcher.fetch_catalog()
                except CVEFetchError as exc:
                    logger.warning("KEV fetch failed: %s", exc)
                    self._kev_catalog = {}
            else:
                self._kev_catalog = {}
        return self._kev_catalog

    def _ctid(self) -> dict[str, Any]:
        if self._ctid_catalog is None:
            fetcher = self._fetchers.get("ctid")
            if fetcher:
                try:
                    self._ctid_catalog = fetcher.fetch_catalog()
                except CVEFetchError as exc:
                    logger.warning("CTID fetch failed: %s", exc)
                    self._ctid_catalog = {}
            else:
                self._ctid_catalog = {}
        return self._ctid_catalog

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, cve_id: str) -> CVERecord | None:
        """Return a merged CVERecord, or None if no source has data for this CVE."""
        cve_id = cve_id.upper()
        if cve_id in self._record_cache:
            return self._record_cache[cve_id]
        record = self._merge(cve_id)
        if record:
            self._record_cache[cve_id] = record
        return record

    def get_batch(self, cve_ids: list[str]) -> dict[str, CVERecord]:
        """Return a dict of merged CVERecords for all requested IDs."""
        cve_ids = [c.upper() for c in cve_ids]
        missing = [c for c in cve_ids if c not in self._record_cache]

        # Batch-fetch EPSS for all missing CVEs in one API call
        epss_data: dict[str, Any] = {}
        epss_fetcher = self._fetchers.get("epss")
        if epss_fetcher and missing:
            try:
                epss_data = epss_fetcher.fetch_batch(missing)
            except CVEFetchError as exc:
                logger.warning("EPSS batch fetch failed: %s", exc)

        for cve_id in missing:
            record = self._merge(cve_id, epss_entry=epss_data.get(cve_id))
            if record:
                self._record_cache[cve_id] = record

        return {c: self._record_cache[c] for c in cve_ids if c in self._record_cache}

    def update(self, cve_ids: list[str] | None = None, force: bool = False) -> None:
        """
        Refresh intelligence caches.

        If *cve_ids* is given, refresh only those CVEs (NVD + EPSS).
        Otherwise, refresh catalog sources (KEV + CTID) and clear the in-memory
        record cache so subsequent gets re-merge from fresh catalogs.
        """
        kev_fetcher = self._fetchers.get("kev")
        ctid_fetcher = self._fetchers.get("ctid")
        nvd_fetcher = self._fetchers.get("nvd")
        epss_fetcher = self._fetchers.get("epss")

        if cve_ids:
            ids = [c.upper() for c in cve_ids]
            if nvd_fetcher:
                try:
                    nvd_fetcher.fetch_batch(ids)
                except CVEFetchError as exc:
                    logger.warning("NVD update failed: %s", exc)
            if epss_fetcher:
                try:
                    epss_fetcher.fetch_batch(ids)
                except CVEFetchError as exc:
                    logger.warning("EPSS update failed: %s", exc)
            # Invalidate in-memory cache for these IDs
            for c in ids:
                self._record_cache.pop(c, None)
        else:
            # Refresh full catalogs
            if kev_fetcher:
                try:
                    self._kev_catalog = kev_fetcher.fetch_catalog()
                    logger.info("KEV: %d entries refreshed", len(self._kev_catalog))
                except CVEFetchError as exc:
                    logger.warning("KEV update failed: %s", exc)
            if ctid_fetcher:
                try:
                    self._ctid_catalog = ctid_fetcher.fetch_catalog()
                    logger.info("CTID: %d entries refreshed", len(self._ctid_catalog))
                except CVEFetchError as exc:
                    logger.warning("CTID update failed: %s", exc)
            # Clear merged record cache so everything is re-derived
            self._record_cache.clear()

    # ── Internal merge ────────────────────────────────────────────────────────

    def _merge(
        self, cve_id: str, epss_entry: dict[str, Any] | None = None
    ) -> CVERecord | None:
        record = CVERecord(cve_id=cve_id)
        found_any = False

        # NVD
        nvd_fetcher = self._fetchers.get("nvd")
        if nvd_fetcher:
            try:
                nvd = nvd_fetcher.fetch_cve(cve_id)
            except CVEFetchError as exc:
                logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
                nvd = None
            if nvd:
                found_any = True
                record.description = nvd.get("description", "")
                record.cvss_score = nvd.get("cvss_score")
                record.cvss_vector = nvd.get("cvss_vector")
                record.cvss_version = nvd.get("cvss_version")
                record.severity = nvd.get("severity")
                record.cwes = nvd.get("cwes", [])
                record.cpes = nvd.get("cpes", [])
                record.published = nvd.get("published")
                record.modified = nvd.get("modified")

        # KEV
        kev_entry = self._kev().get(cve_id)
        if kev_entry:
            found_any = True
            record.in_kev = True
            record.kev_date_added = kev_entry.get("date_added")
            record.kev_vendor = kev_entry.get("vendor")
            record.kev_product = kev_entry.get("product")

        # CTID
        ctid_entry = self._ctid().get(cve_id)
        if ctid_entry:
            found_any = True
            record.ctid_techniques = ctid_entry.get("techniques", [])

        # EPSS (use pre-fetched batch result if available)
        if epss_entry is None:
            epss_fetcher = self._fetchers.get("epss")
            if epss_fetcher:
                try:
                    batch = epss_fetcher.fetch_batch([cve_id])
                    epss_entry = batch.get(cve_id)
                except CVEFetchError as exc:
                    logger.warning("EPSS lookup failed for %s: %s", cve_id, exc)
        if epss_entry:
            found_any = True
            record.epss_score = epss_entry.get("epss")
            record.epss_percentile = epss_entry.get("percentile")

        return record if found_any else None


# ─── CVEToTechniqueMapper ─────────────────────────────────────────────────────


class CVEToTechniqueMapper:
    """
    Map a CVE to ATT&CK techniques via three ordered passes.

    Priority: CTID (explicit) > CWE inference > LLM (optional gap-fill).
    Results are deduplicated by technique ID, keeping the highest-confidence
    entry and merging source labels (e.g. "ctid+cwe").
    """

    def __init__(
        self,
        kb: CVEKnowledgeBase,
        cwe_map_path: Path | None = None,
        use_llm: bool = False,
        llm_config: dict[str, Any] | None = None,
        config_dir: Path | None = None,
    ) -> None:
        self._kb = kb
        self._use_llm = use_llm and HAS_LLM
        self._config_dir = config_dir or _DEFAULT_CONFIG_DIR

        cwe_path = cwe_map_path or (self._config_dir / "cwe_technique_map.yaml")
        self._cwe_map = self._load_cwe_map(cwe_path)

        self._llm_config = llm_config or self._load_llm_config()
        self._jinja_env: Any = None
        if self._use_llm:
            tmpl_dir = self._config_dir / "llm_prompts"
            self._jinja_env = Environment(
                loader=FileSystemLoader(str(tmpl_dir)),
                autoescape=False,
            )

        # Tactic lookup populated lazily from ATT&CK KB if available
        self._tactic_map: dict[str, str] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def map_cve(self, cve_id: str) -> CVETechniqueResult:
        """Return all technique mappings for a single CVE."""
        cve_id = cve_id.upper()
        record = self._kb.get(cve_id)
        if record is None:
            return CVETechniqueResult(
                cve_id=cve_id,
                record=None,
                techniques=[],
                sources_used=[],
                errors=[f"No data found for {cve_id}"],
            )

        techniques: list[TechniqueMapping] = []
        sources_used: list[str] = []

        ctid = self._from_ctid(record)
        if ctid:
            techniques.extend(ctid)
            sources_used.append("ctid")

        cwe = self._from_cwe(record)
        if cwe:
            techniques.extend(cwe)
            sources_used.append("cwe")

        merged = self._merge_techniques(techniques)

        if self._use_llm:
            llm = self._from_llm(record, merged)
            if llm:
                merged = self._merge_techniques(merged + llm)
                sources_used.append("llm")

        return CVETechniqueResult(
            cve_id=cve_id,
            record=record,
            techniques=merged,
            sources_used=sources_used,
        )

    def map_batch(self, cve_ids: list[str]) -> dict[str, CVETechniqueResult]:
        """Map multiple CVEs; pre-fetches batch EPSS for efficiency."""
        records = self._kb.get_batch(cve_ids)
        return {
            cve_id: self.map_cve(cve_id)
            for cve_id in [c.upper() for c in cve_ids]
        }

    # ── Source passes ─────────────────────────────────────────────────────────

    def _from_ctid(self, record: CVERecord) -> list[TechniqueMapping]:
        mappings: list[TechniqueMapping] = []
        for tid in record.ctid_techniques:
            tid = tid.strip()
            if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
                continue
            mappings.append(TechniqueMapping(
                technique_id=tid,
                tactic=self._infer_tactic(tid),
                confidence=0.90,
                source="ctid",
                reasoning=f"Direct CTID ATT&CK-to-CVE mapping for {record.cve_id}",
            ))
        return mappings

    def _from_cwe(self, record: CVERecord) -> list[TechniqueMapping]:
        mappings: list[TechniqueMapping] = []
        for cwe_id in record.cwes:
            for entry in self._cwe_map.get(cwe_id, []):
                for tid in entry["techniques"]:
                    mappings.append(TechniqueMapping(
                        technique_id=tid,
                        tactic=self._infer_tactic(tid),
                        confidence=float(entry["confidence"]),
                        source="cwe",
                        reasoning=entry.get("note", f"{cwe_id} → {tid}"),
                    ))
        return mappings

    def _from_llm(
        self,
        record: CVERecord,
        existing: list[TechniqueMapping],
    ) -> list[TechniqueMapping]:
        if not self._use_llm or self._jinja_env is None:
            return []
        try:
            tmpl = self._jinja_env.get_template("cve_enrichment.j2")
            prompt = tmpl.render(
                cve=record,
                existing_techniques=existing,
                max_techniques=self._llm_config.get("max_techniques", 5),
                min_confidence=self._llm_config.get("min_confidence", 0.60),
            )
        except Exception as exc:
            logger.warning("LLM prompt render failed: %s", exc)
            return []

        try:
            client = _anthropic_lib.Anthropic()
            resp = client.messages.create(
                model=self._llm_config.get("model", "claude-haiku-4-5-20251001"),
                max_tokens=self._llm_config.get("max_tokens", 1024),
                temperature=self._llm_config.get("temperature", 0.1),
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp.content[0].text.strip()
            # Strip markdown fences if present
            raw = re.sub(r"^```json\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)
            data = json.loads(raw)
        except Exception as exc:
            logger.warning("LLM CVE enrichment failed for %s: %s", record.cve_id, exc)
            return []

        mappings: list[TechniqueMapping] = []
        for entry in data.get("techniques", []):
            tid = str(entry.get("technique_id", "")).strip()
            if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
                continue
            mappings.append(TechniqueMapping(
                technique_id=tid,
                tactic=str(entry.get("tactic", self._infer_tactic(tid))),
                confidence=float(entry.get("confidence", 0.60)),
                source="llm",
                reasoning=str(entry.get("reasoning", "")),
            ))
        return mappings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _merge_techniques(
        self, mappings: list[TechniqueMapping]
    ) -> list[TechniqueMapping]:
        """Deduplicate by technique_id, keeping max confidence and merged source labels."""
        best: dict[str, TechniqueMapping] = {}
        for m in mappings:
            tid = m.technique_id
            if tid not in best or m.confidence > best[tid].confidence:
                best[tid] = m
            elif m.confidence == best[tid].confidence and m.source not in best[tid].source:
                # Same confidence, different source — merge source label
                existing = best[tid]
                best[tid] = TechniqueMapping(
                    technique_id=existing.technique_id,
                    tactic=existing.tactic,
                    confidence=existing.confidence,
                    source=f"{existing.source}+{m.source}",
                    reasoning=existing.reasoning,
                )
        return sorted(best.values(), key=lambda x: x.confidence, reverse=True)

    def _infer_tactic(self, technique_id: str) -> str:
        """Return tactic slug from ATT&CK KB if loaded, else a heuristic fallback."""
        if technique_id in self._tactic_map:
            return self._tactic_map[technique_id]
        base = technique_id.split(".")[0]
        # Heuristic tactic map for the most common initial-access / exploitation IDs
        _HINTS: dict[str, str] = {
            "T1190": "initial-access",
            "T1059": "execution",
            "T1055": "privilege-escalation",
            "T1068": "privilege-escalation",
            "T1078": "defense-evasion",
            "T1203": "execution",
            "T1105": "command-and-control",
            "T1505": "persistence",
            "T1083": "discovery",
            "T1213": "collection",
            "T1090": "command-and-control",
            "T1040": "credential-access",
            "T1185": "collection",
            "T1189": "initial-access",
            "T1499": "impact",
            "T1222": "defense-evasion",
            "T1552": "credential-access",
        }
        return _HINTS.get(base, "unknown")

    @staticmethod
    def _load_cwe_map(path: Path) -> dict[str, list[dict[str, Any]]]:
        """Load cwe_technique_map.yaml into {CWE-NNN: [{techniques, confidence, note}]}."""
        if not path.exists():
            logger.warning("CWE technique map not found: %s", path)
            return {}
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        result: dict[str, list[dict[str, Any]]] = {}
        for entry in (raw or {}).get("mappings", []):
            cwe_id = entry.get("cwe_id", "")
            techs = entry.get("techniques", [])
            if isinstance(techs, str):
                techs = [techs]
            result.setdefault(cwe_id, []).append({
                "techniques": techs,
                "confidence": entry.get("confidence", 0.60),
                "note": entry.get("note", ""),
            })
        return result

    def _load_llm_config(self) -> dict[str, Any]:
        path = self._config_dir / "llm.yaml"
        if path.exists():
            return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return {}


# ─── CVECoverageAnalyzer ──────────────────────────────────────────────────────


class CVECoverageAnalyzer:
    """
    Check whether the detection corpus covers the techniques associated with a CVE.

    A technique is "covered" if at least one detection maps to it (exact base
    technique match, or a sub-technique under the same parent).
    """

    def __init__(self, mapper: CVEToTechniqueMapper) -> None:
        self._mapper = mapper

    def analyze(
        self,
        cve_id: str,
        detections: list[CanonicalDetection],
    ) -> CVECoverageResult:
        """Analyse coverage for a single CVE against the provided detection corpus."""
        result = self._mapper.map_cve(cve_id)
        record = result.record

        # Build a lookup: base_technique_id → [detection names]
        detection_index: dict[str, list[str]] = {}
        for det in detections:
            for mt in det.mitre_techniques:
                base = mt.technique_id
                detection_index.setdefault(base, []).append(det.name)
                if mt.sub_technique_id:
                    sub_parent = mt.sub_technique_id.split(".")[0]
                    detection_index.setdefault(sub_parent, []).append(det.name)

        covered: list[str] = []
        uncovered: list[str] = []
        covering: dict[str, list[str]] = {}

        for tm in result.techniques:
            base = tm.technique_id.split(".")[0]
            dets = detection_index.get(base, [])
            if dets:
                covered.append(tm.technique_id)
                covering[tm.technique_id] = list(dict.fromkeys(dets))
            else:
                uncovered.append(tm.technique_id)

        total = len(result.techniques)
        coverage_ratio = len(covered) / total if total else 0.0

        cvss = record.cvss_score if record else None
        epss = record.epss_score if record else None
        in_kev = record.in_kev if record else False

        return CVECoverageResult(
            cve_id=cve_id.upper(),
            cvss_score=cvss,
            epss_score=epss,
            in_kev=in_kev,
            techniques=result.techniques,
            covered_technique_ids=covered,
            uncovered_technique_ids=uncovered,
            coverage_ratio=coverage_ratio,
            residual_risk_score=self.residual_risk(
                cvss or 0.0, epss or 0.0, coverage_ratio
            ),
            covering_detections=covering,
        )

    def analyze_corpus(
        self,
        cve_ids: list[str],
        detections: list[CanonicalDetection],
    ) -> list[CVECoverageResult]:
        """Analyze coverage for multiple CVEs, sorted by residual_risk descending."""
        results = [self.analyze(cve_id, detections) for cve_id in cve_ids]
        return sorted(results, key=lambda r: r.residual_risk_score, reverse=True)

    @staticmethod
    def residual_risk(cvss: float, epss: float, coverage_ratio: float) -> float:
        """
        Residual risk = CVSS_score × EPSS_score × (1 − coverage_ratio).

        Range: 0 – 10.  Higher = more urgent.
        """
        return round(cvss * epss * max(0.0, 1.0 - coverage_ratio), 4)

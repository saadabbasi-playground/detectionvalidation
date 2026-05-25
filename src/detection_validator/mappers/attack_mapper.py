"""
ATT&CK mapping layer — validates and infers MITRE ATT&CK technique tags.

Three mapping modes
-------------------
EXPLICIT  Techniques already tagged on the detection are validated against the
          live ATT&CK knowledge base: deprecated IDs are flagged with suggested
          replacements, missing tactic fields are filled in, and sub-technique
          parents are verified.

INFERRED  No technique tags exist.  Two heuristic passes run:
          1. Keyword match — scan detection text against
             ``configs/technique_keywords.yaml``.
          2. Data-source correlation — apply
             ``configs/datasource_technique_hints.yaml`` based on log sources
             and query keywords.
          An optional LLM pass (--llm) calls the Anthropic API with a Jinja2
          prompt template for ranked candidates with confidence scores.

HYBRID    EXPLICIT validation of any existing tags, then INFERRED gap-fill for
          techniques not yet covered by the explicit tags.

Cache
-----
STIX bundles are saved as gzip-compressed JSON under
``src/detection_validator/intel/attack_cache/`` with per-domain metadata.
Run ``dv intel update --source attack`` to force-refresh.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import auto
from pathlib import Path
from typing import Any, Iterator, Literal

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, Template

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    MitreTechnique,
)
from detection_validator.parsers.base import normalise_technique_id, techniques_to_models

try:
    import anthropic as _anthropic_lib

    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    from mitreattack.stix20 import MitreAttackData as _MitreAttackData

    HAS_MITREATTACK = True
except ImportError:
    HAS_MITREATTACK = False

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

_PACKAGE_ROOT = Path(__file__).parents[1]
_DEFAULT_CACHE_DIR = _PACKAGE_ROOT / "intel" / "attack_cache"
_DEFAULT_CONFIG_DIR = Path(__file__).parents[3] / "configs"  # repo root/configs

_ATTCK_VERSION = "19.1"
_STIX_BASE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
)
_STIX_URLS: dict[str, str] = {
    "enterprise-attack": (
        f"{_STIX_BASE}/enterprise-attack/enterprise-attack-{_ATTCK_VERSION}.json"
    ),
    "mobile-attack": (
        f"{_STIX_BASE}/mobile-attack/mobile-attack-{_ATTCK_VERSION}.json"
    ),
    "ics-attack": (
        f"{_STIX_BASE}/ics-attack/ics-attack-{_ATTCK_VERSION}.json"
    ),
}

_DEFAULT_TTL_DAYS = 7
_DOWNLOAD_TIMEOUT = 60  # seconds

# ─── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class AttackTechnique:
    """Lightweight representation of one ATT&CK technique/sub-technique."""

    technique_id: str  # e.g. T1059 or T1059.001
    name: str
    description: str
    tactic: str  # first (primary) tactic slug, e.g. "execution"
    all_tactics: list[str]
    is_subtechnique: bool
    parent_id: str | None  # e.g. T1059 when this is T1059.001
    deprecated: bool
    revoked: bool
    stix_id: str  # e.g. attack-pattern--xxxx


@dataclass
class TechniqueMatch:
    """One inferred or validated technique binding."""

    technique_id: str
    tactic: str
    confidence: float
    source: Literal["explicit", "keyword", "datasource", "llm"]
    reasoning: str = ""
    deprecated: bool = False
    replacement: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class MappingResult:
    """Result of running AttackMapper.map_detection()."""

    detection_id: str
    mode: str
    validated: list[TechniqueMatch] = field(default_factory=list)   # explicit pass
    inferred: list[TechniqueMatch] = field(default_factory=list)    # inferred pass
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    processing_time_ms: float = 0.0

    @property
    def all_techniques(self) -> list[TechniqueMatch]:
        """Deduplicated union of validated + inferred, validated first."""
        seen: dict[str, TechniqueMatch] = {}
        for m in self.validated + self.inferred:
            if m.technique_id not in seen:
                seen[m.technique_id] = m
        return list(seen.values())

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)


# ─── STIX parsing helpers ─────────────────────────────────────────────────────

def _extract_attack_id(obj: dict[str, Any]) -> str | None:
    """Return the ATT&CK external ID (T1234 / TA0001 / M1040) or None."""
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _tactic_slug(phase_name: str) -> str:
    return phase_name.lower().replace(" ", "-")


def _technique_tactics(obj: dict[str, Any]) -> list[str]:
    return [
        _tactic_slug(kc["phase_name"])
        for kc in obj.get("kill_chain_phases") or []
        if kc.get("kill_chain_name") == "mitre-attack"
    ]


def _is_deprecated(obj: dict[str, Any]) -> bool:
    return bool(obj.get("x-mitre-deprecated")) or bool(obj.get("revoked"))


def _parse_stix_bundle(bundle: dict[str, Any]) -> tuple[
    dict[str, AttackTechnique],       # id → technique
    dict[str, str],                   # stix_id → attack_id
    dict[str, str],                   # deprecated attack_id → replacement attack_id
    dict[str, list[str]],             # technique attack_id → mitigation attack_ids
    dict[str, list[dict]],            # technique attack_id → group dicts
    dict[str, list[dict]],            # technique attack_id → software dicts
    dict[str, list[str]],             # technique attack_id → procedure descriptions
    list[dict],                       # tactics
    list[dict],                       # data components
    list[dict],                       # data sources
]:
    objects: list[dict] = bundle.get("objects") or []

    # Build stix_id → attack_id map for all objects first
    stix_to_attack: dict[str, str] = {}
    for obj in objects:
        aid = _extract_attack_id(obj)
        if aid:
            stix_to_attack[obj["id"]] = aid

    techniques: dict[str, AttackTechnique] = {}
    tactics: list[dict] = []
    data_components: list[dict] = []
    data_sources: list[dict] = []
    mitigations_raw: dict[str, dict] = {}   # stix_id → COA object
    groups_raw: dict[str, dict] = {}        # stix_id → group object
    software_raw: dict[str, dict] = {}      # stix_id → software object
    revoked_by: dict[str, str] = {}         # deprecated stix_id → replacement stix_id
    mitigates: dict[str, list[str]] = {}    # technique stix_id → [COA stix_ids]
    group_uses: dict[str, list[str]] = {}   # technique stix_id → [group stix_ids]
    soft_uses: dict[str, list[str]] = {}    # technique stix_id → [software stix_ids]
    procedure_examples: dict[str, list[str]] = {}  # technique attack_id → [descriptions]

    # Pass 1: collect objects by type
    for obj in objects:
        t = obj.get("type", "")
        if t == "attack-pattern":
            aid = _extract_attack_id(obj)
            if not aid or not aid.startswith("T"):
                continue
            tactics_list = _technique_tactics(obj)
            is_sub = bool(obj.get("x-mitre-is-subtechnique"))
            parent_id: str | None = None
            if is_sub and "." in aid:
                parent_id = aid.split(".")[0]
            techniques[aid] = AttackTechnique(
                technique_id=aid,
                name=obj.get("name", ""),
                description=(obj.get("description") or "")[:500],
                tactic=tactics_list[0] if tactics_list else "unknown",
                all_tactics=tactics_list,
                is_subtechnique=is_sub,
                parent_id=parent_id,
                deprecated=_is_deprecated(obj),
                revoked=bool(obj.get("revoked")),
                stix_id=obj["id"],
            )
        elif t == "x-mitre-tactic":
            tactics.append(obj)
        elif t == "x-mitre-data-component":
            data_components.append(obj)
        elif t == "x-mitre-data-source":
            data_sources.append(obj)
        elif t == "course-of-action":
            mitigations_raw[obj["id"]] = obj
        elif t == "intrusion-set":
            groups_raw[obj["id"]] = obj
        elif t in ("malware", "tool"):
            software_raw[obj["id"]] = obj

    # Pass 2: process relationships
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type", "")
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        desc = obj.get("description", "")

        if rel_type == "revoked-by":
            revoked_by[src] = tgt

        elif rel_type == "mitigates" and src in mitigations_raw:
            mitigates.setdefault(tgt, []).append(src)

        elif rel_type == "uses":
            if src in groups_raw:
                group_uses.setdefault(tgt, []).append(src)
                if tgt in stix_to_attack and desc:
                    procedure_examples.setdefault(stix_to_attack[tgt], []).append(desc)
            elif src in software_raw:
                soft_uses.setdefault(tgt, []).append(src)
                if tgt in stix_to_attack and desc:
                    procedure_examples.setdefault(stix_to_attack[tgt], []).append(desc)

    # Build deprecated-technique → replacement mapping (attack IDs)
    deprecated_map: dict[str, str] = {}
    for dep_stix, repl_stix in revoked_by.items():
        dep_aid = stix_to_attack.get(dep_stix)
        repl_aid = stix_to_attack.get(repl_stix)
        if dep_aid and repl_aid:
            deprecated_map[dep_aid] = repl_aid

    # Translate stix_id-keyed relationship dicts to attack_id-keyed
    def _resolve_objects(stix_id_map: dict[str, list[str]], raw_dict: dict) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {}
        for tech_stix, related_stix_ids in stix_id_map.items():
            aid = stix_to_attack.get(tech_stix)
            if not aid:
                continue
            result[aid] = [raw_dict[sid] for sid in related_stix_ids if sid in raw_dict]
        return result

    mitigations_out = _resolve_objects(mitigates, mitigations_raw)
    groups_out = _resolve_objects(group_uses, groups_raw)
    software_out = _resolve_objects(soft_uses, software_raw)

    return (
        techniques,
        stix_to_attack,
        deprecated_map,
        mitigations_out,
        groups_out,
        software_out,
        procedure_examples,
        tactics,
        data_components,
        data_sources,
    )


# ─── AttackKnowledgeBase ──────────────────────────────────────────────────────

class AttackKnowledgeBase:
    """
    Queryable ATT&CK knowledge base backed by a locally cached STIX bundle.

    Parameters
    ----------
    domain:
        One of ``enterprise-attack``, ``mobile-attack``, ``ics-attack``.
    cache_dir:
        Directory for cached STIX bundles.  Defaults to
        ``src/detection_validator/intel/attack_cache/``.
    ttl_days:
        How many days before the cache is considered stale.
    """

    def __init__(
        self,
        domain: str = "enterprise-attack",
        cache_dir: Path | None = None,
        ttl_days: int = _DEFAULT_TTL_DAYS,
    ) -> None:
        if domain not in _STIX_URLS:
            raise ValueError(f"Unknown domain {domain!r}; choose from {list(_STIX_URLS)}")
        self.domain = domain
        self.cache_dir = (cache_dir or _DEFAULT_CACHE_DIR).resolve()
        self.ttl_days = ttl_days

        self._techniques: dict[str, AttackTechnique] = {}
        self._stix_to_attack: dict[str, str] = {}
        self._deprecated_map: dict[str, str] = {}
        self._mitigations: dict[str, list[dict]] = {}
        self._groups: dict[str, list[dict]] = {}
        self._software: dict[str, list[dict]] = {}
        self._procedure_examples: dict[str, list[str]] = {}
        self._tactics: list[dict] = []
        self._data_components: list[dict] = []
        self._data_sources: list[dict] = []
        self._loaded = False

    # ── File paths ────────────────────────────────────────────────────────────

    @property
    def _bundle_path(self) -> Path:
        return self.cache_dir / f"{self.domain}.json.gz"

    @property
    def _meta_path(self) -> Path:
        return self.cache_dir / f"{self.domain}.meta.json"

    # ── Cache management ──────────────────────────────────────────────────────

    def _is_cache_valid(self) -> bool:
        if not self._bundle_path.exists() or not self._meta_path.exists():
            return False
        try:
            meta = json.loads(self._meta_path.read_text())
            downloaded_at = datetime.fromisoformat(meta["downloaded_at"])
            age = datetime.now(tz=timezone.utc) - downloaded_at
            return age < timedelta(days=self.ttl_days)
        except Exception:
            return False

    def _download(self) -> dict[str, Any]:
        url = _STIX_URLS[self.domain]
        logger.info("Downloading ATT&CK bundle: %s", url)
        resp = requests.get(url, timeout=_DOWNLOAD_TIMEOUT, stream=True)
        resp.raise_for_status()
        return resp.json()

    def _save_cache(self, bundle: dict[str, Any]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        with gzip.open(self._bundle_path, "wt", encoding="utf-8") as fh:
            json.dump(bundle, fh)
        meta = {
            "domain": self.domain,
            "downloaded_at": datetime.now(tz=timezone.utc).isoformat(),
            "object_count": len(bundle.get("objects") or []),
        }
        self._meta_path.write_text(json.dumps(meta, indent=2))
        logger.info("Cached ATT&CK bundle: %s (%d objects)", self.domain, meta["object_count"])

    def _load_cache(self) -> dict[str, Any]:
        with gzip.open(self._bundle_path, "rt", encoding="utf-8") as fh:
            return json.load(fh)

    def _load_bundle(self, bundle: dict[str, Any]) -> None:
        (
            self._techniques,
            self._stix_to_attack,
            self._deprecated_map,
            self._mitigations,
            self._groups,
            self._software,
            self._procedure_examples,
            self._tactics,
            self._data_components,
            self._data_sources,
        ) = _parse_stix_bundle(bundle)
        self._loaded = True
        logger.debug(
            "Indexed %d techniques, %d tactics [%s]",
            len(self._techniques), len(self._tactics), self.domain,
        )

    def ensure_loaded(self, force_refresh: bool = False) -> None:
        """Load from cache (downloading if necessary)."""
        if self._loaded and not force_refresh:
            return
        if force_refresh or not self._is_cache_valid():
            bundle = self._download()
            self._save_cache(bundle)
        else:
            bundle = self._load_cache()
        self._load_bundle(bundle)

    def load_from_bundle(self, bundle: dict[str, Any]) -> None:
        """Bypass cache and load directly from an in-memory STIX bundle dict."""
        self._load_bundle(bundle)

    # ── Query interface ───────────────────────────────────────────────────────

    def get_technique(self, technique_id: str) -> AttackTechnique | None:
        """Return the technique for *technique_id* (e.g. ``T1059`` or ``T1059.001``)."""
        canon = normalise_technique_id(technique_id) if not technique_id.startswith("T") else technique_id
        return self._techniques.get(canon or technique_id)

    def get_all_techniques(
        self,
        include_deprecated: bool = False,
        include_subtechniques: bool = True,
    ) -> list[AttackTechnique]:
        techs = list(self._techniques.values())
        if not include_deprecated:
            techs = [t for t in techs if not t.deprecated and not t.revoked]
        if not include_subtechniques:
            techs = [t for t in techs if not t.is_subtechnique]
        return techs

    def get_tactics(self) -> list[dict]:
        return list(self._tactics)

    def get_data_components(self) -> list[dict]:
        return list(self._data_components)

    def get_data_sources(self) -> list[dict]:
        return list(self._data_sources)

    def get_mitigations(self, technique_id: str) -> list[dict]:
        canon = self._canonicalize(technique_id)
        return list(self._mitigations.get(canon, []))

    def get_groups_using(self, technique_id: str) -> list[dict]:
        canon = self._canonicalize(technique_id)
        return list(self._groups.get(canon, []))

    def get_software_using(self, technique_id: str) -> list[dict]:
        canon = self._canonicalize(technique_id)
        return list(self._software.get(canon, []))

    def get_procedure_examples(self, technique_id: str) -> list[str]:
        canon = self._canonicalize(technique_id)
        return list(self._procedure_examples.get(canon, []))

    def is_deprecated(self, technique_id: str) -> bool:
        t = self.get_technique(technique_id)
        return t is not None and (t.deprecated or t.revoked)

    def get_replacement(self, deprecated_id: str) -> str | None:
        canon = self._canonicalize(deprecated_id)
        return self._deprecated_map.get(canon)

    def _canonicalize(self, tid: str) -> str:
        return normalise_technique_id(tid) or tid

    def tactic_for_technique(self, technique_id: str) -> str:
        t = self.get_technique(technique_id)
        return t.tactic if t else "unknown"

    def parent_exists(self, sub_technique_id: str) -> bool:
        """Return True if the parent technique of a sub-technique is present in the KB."""
        if "." not in sub_technique_id:
            return True  # base technique — no parent check needed
        parent = sub_technique_id.split(".")[0]
        return parent in self._techniques

    def __repr__(self) -> str:
        return (
            f"<AttackKnowledgeBase domain={self.domain!r} "
            f"loaded={self._loaded} techniques={len(self._techniques)}>"
        )


# ─── Singleton registry ───────────────────────────────────────────────────────

_KB_REGISTRY: dict[str, AttackKnowledgeBase] = {}


def get_knowledge_base(
    domain: str = "enterprise-attack",
    cache_dir: Path | None = None,
    ttl_days: int = _DEFAULT_TTL_DAYS,
) -> AttackKnowledgeBase:
    """Return (and lazily initialize) a per-domain KB singleton."""
    key = f"{domain}:{cache_dir}"
    if key not in _KB_REGISTRY:
        _KB_REGISTRY[key] = AttackKnowledgeBase(domain, cache_dir, ttl_days)
    return _KB_REGISTRY[key]


# ─── Keyword heuristics ───────────────────────────────────────────────────────

@dataclass
class _KeywordEntry:
    keyword: str
    techniques: list[str]
    is_regex: bool
    confidence: float
    pattern: re.Pattern | None = None

    def __post_init__(self) -> None:
        if self.is_regex:
            self.pattern = re.compile(self.keyword, re.IGNORECASE)


def _load_keyword_entries(config_dir: Path | None = None) -> list[_KeywordEntry]:
    config_dir = config_dir or _DEFAULT_CONFIG_DIR
    path = config_dir / "technique_keywords.yaml"
    if not path.exists():
        logger.warning("technique_keywords.yaml not found at %s", path)
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        logger.warning("Failed to load technique_keywords.yaml: %s", exc)
        return []

    entries: list[_KeywordEntry] = []
    for raw in data.get("entries") or []:
        kw = raw.get("keyword", "")
        techs_raw = raw.get("techniques", [])
        techs = [techs_raw] if isinstance(techs_raw, str) else list(techs_raw)
        entries.append(_KeywordEntry(
            keyword=kw,
            techniques=techs,
            is_regex=bool(raw.get("regex", False)),
            confidence=float(raw.get("confidence", 0.65)),
        ))
    return entries


@dataclass
class _DatasourceHint:
    log_sources: list[str]
    keywords: list[str]
    techniques: list[str]
    confidence: float


def _load_datasource_hints(config_dir: Path | None = None) -> list[_DatasourceHint]:
    config_dir = config_dir or _DEFAULT_CONFIG_DIR
    path = config_dir / "datasource_technique_hints.yaml"
    if not path.exists():
        logger.warning("datasource_technique_hints.yaml not found at %s", path)
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        logger.warning("Failed to load datasource_technique_hints.yaml: %s", exc)
        return []

    return [
        _DatasourceHint(
            log_sources=[str(ls).lower() for ls in (h.get("log_sources") or [])],
            keywords=[str(k).lower() for k in (h.get("keywords") or [])],
            techniques=h.get("techniques") or [],
            confidence=float(h.get("confidence", 0.60)),
        )
        for h in (data.get("hints") or [])
    ]


# ─── LLM inference ────────────────────────────────────────────────────────────

def _load_llm_config(config_dir: Path | None = None) -> dict[str, Any]:
    config_dir = config_dir or _DEFAULT_CONFIG_DIR
    path = config_dir / "llm.yaml"
    if not path.exists():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _render_prompt(
    detection: CanonicalDetection,
    candidate_summary: list[TechniqueMatch],
    config: dict[str, Any],
    config_dir: Path | None = None,
) -> str:
    config_dir = config_dir or _DEFAULT_CONFIG_DIR
    template_path_raw: str = config.get("prompt_template", "configs/llm_prompts/technique_inference.j2")

    # Resolve template path relative to the repo root or config_dir
    template_path = Path(template_path_raw)
    if not template_path.is_absolute():
        # Try repo root first
        candidates = [
            Path.cwd() / template_path,
            config_dir.parent / template_path,
            config_dir / "llm_prompts" / "technique_inference.j2",
        ]
        for c in candidates:
            if c.exists():
                template_path = c
                break

    if not template_path.exists():
        raise FileNotFoundError(f"LLM prompt template not found: {template_path_raw}")

    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=False,
    )
    tmpl = env.get_template(template_path.name)
    return tmpl.render(
        detection=detection,
        candidate_summary=candidate_summary,
        max_candidates=config.get("max_candidates", 5),
        min_confidence=config.get("min_confidence", 0.30),
    )


def _call_llm(
    prompt: str,
    config: dict[str, Any],
) -> list[TechniqueMatch]:
    if not HAS_ANTHROPIC:
        raise ImportError(
            "LLM mode requires the 'anthropic' package: pip install anthropic"
        )
    client = _anthropic_lib.Anthropic()
    model = config.get("model", "claude-haiku-4-5-20251001")
    max_tokens = int(config.get("max_tokens", 1024))
    temperature = float(config.get("temperature", 0.1))
    timeout = float(config.get("timeout_s", 30))

    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
        timeout=timeout,
    )
    raw_text = response.content[0].text if response.content else ""

    # Extract JSON — the model might wrap it in markdown code fences
    json_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if not json_match:
        logger.warning("LLM returned no parseable JSON: %s", raw_text[:200])
        return []
    try:
        parsed = json.loads(json_match.group())
    except json.JSONDecodeError as exc:
        logger.warning("LLM JSON parse error: %s", exc)
        return []

    min_confidence = float(config.get("min_confidence", 0.30))
    max_candidates = int(config.get("max_candidates", 5))
    results: list[TechniqueMatch] = []
    for c in (parsed.get("candidates") or [])[:max_candidates]:
        conf = float(c.get("confidence", 0.0))
        if conf < min_confidence:
            continue
        tid = (c.get("technique_id") or "").strip()
        canon = normalise_technique_id(tid)
        if not canon:
            continue
        results.append(TechniqueMatch(
            technique_id=canon,
            tactic=str(c.get("tactic", "unknown")),
            confidence=conf,
            source="llm",
            reasoning=str(c.get("reasoning", "")),
        ))
    return results


# ─── Mapping mode ─────────────────────────────────────────────────────────────

class MappingMode:
    EXPLICIT = "explicit"
    INFERRED = "inferred"
    HYBRID = "hybrid"


# ─── AttackMapper ─────────────────────────────────────────────────────────────

class AttackMapper:
    """
    Maps ``CanonicalDetection`` objects to MITRE ATT&CK techniques.

    Parameters
    ----------
    kb:
        Pre-loaded ``AttackKnowledgeBase``.  If omitted, the enterprise-attack
        singleton is used (auto-downloaded on first use).
    config_dir:
        Override directory for YAML config files.
    use_llm:
        Enable LLM-based inference (requires ``anthropic`` package and
        ``ANTHROPIC_API_KEY`` env var).
    """

    def __init__(
        self,
        kb: AttackKnowledgeBase | None = None,
        config_dir: Path | None = None,
        use_llm: bool = False,
    ) -> None:
        self._kb = kb
        self._config_dir = config_dir or _DEFAULT_CONFIG_DIR
        self._use_llm = use_llm
        self._keywords: list[_KeywordEntry] | None = None
        self._ds_hints: list[_DatasourceHint] | None = None
        self._llm_config: dict[str, Any] | None = None

    @property
    def kb(self) -> AttackKnowledgeBase:
        if self._kb is None:
            self._kb = get_knowledge_base()
            self._kb.ensure_loaded()
        return self._kb

    @property
    def keywords(self) -> list[_KeywordEntry]:
        if self._keywords is None:
            self._keywords = _load_keyword_entries(self._config_dir)
        return self._keywords

    @property
    def ds_hints(self) -> list[_DatasourceHint]:
        if self._ds_hints is None:
            self._ds_hints = _load_datasource_hints(self._config_dir)
        return self._ds_hints

    @property
    def llm_config(self) -> dict[str, Any]:
        if self._llm_config is None:
            self._llm_config = _load_llm_config(self._config_dir)
        return self._llm_config

    # ── Public interface ──────────────────────────────────────────────────────

    def map_detection(
        self,
        detection: CanonicalDetection,
        mode: str = MappingMode.HYBRID,
    ) -> MappingResult:
        """
        Run the mapping pipeline and return a ``MappingResult``.

        Does NOT mutate *detection*; call :meth:`apply` to write results back.
        """
        t0 = time.monotonic()
        result = MappingResult(detection_id=detection.id, mode=mode)

        if mode in (MappingMode.EXPLICIT, MappingMode.HYBRID):
            self._run_explicit(detection, result)

        if mode == MappingMode.INFERRED or (
            mode == MappingMode.HYBRID and not detection.mitre_techniques
        ):
            self._run_inferred(detection, result)
        elif mode == MappingMode.HYBRID and detection.mitre_techniques:
            # HYBRID: also infer for any aspects not covered by explicit tags
            existing_ids = {m.technique_id for m in result.validated}
            self._run_inferred(detection, result, exclude_ids=existing_ids)

        result.processing_time_ms = (time.monotonic() - t0) * 1000
        return result

    def apply(
        self,
        detection: CanonicalDetection,
        result: MappingResult,
        min_confidence: float = 0.50,
    ) -> CanonicalDetection:
        """
        Return a *new* ``CanonicalDetection`` with technique tags from *result*.

        Only techniques with confidence >= *min_confidence* are applied.
        Existing technique tags are replaced (not merged) by the validated set.
        """
        accepted = [m for m in result.all_techniques if m.confidence >= min_confidence]
        if not accepted:
            return detection

        new_techniques = [
            MitreTechnique(
                technique_id=m.technique_id.split(".")[0],
                sub_technique_id=m.technique_id if "." in m.technique_id else None,
                tactic=m.tactic,
                confidence=round(m.confidence, 3),
            )
            for m in accepted
        ]
        return detection.model_copy(update={"mitre_techniques": new_techniques})

    # ── EXPLICIT pass ─────────────────────────────────────────────────────────

    def _run_explicit(
        self,
        detection: CanonicalDetection,
        result: MappingResult,
    ) -> None:
        for mt in detection.mitre_techniques:
            tid = mt.sub_technique_id or mt.technique_id
            canon = normalise_technique_id(tid)
            if not canon:
                result.errors.append(f"Invalid technique ID: {tid!r}")
                continue

            tech = self.kb.get_technique(canon)

            if tech is None:
                result.errors.append(f"{canon} not found in ATT&CK {self.kb.domain}")
                continue

            match = TechniqueMatch(
                technique_id=canon,
                tactic=mt.tactic if mt.tactic and mt.tactic != "unknown" else tech.tactic,
                confidence=mt.confidence,
                source="explicit",
            )

            if tech.deprecated or tech.revoked:
                match.deprecated = True
                replacement = self.kb.get_replacement(canon)
                match.replacement = replacement
                w = f"{canon} is deprecated/revoked"
                if replacement:
                    w += f"; suggested replacement: {replacement}"
                match.warnings.append(w)
                result.warnings.append(w)

            # Fill missing tactic
            if mt.tactic in ("unknown", "") and not tech.deprecated:
                match.tactic = tech.tactic
                result.warnings.append(
                    f"Filled missing tactic for {canon}: {tech.tactic}"
                )

            # Sub-technique parent check
            if "." in canon and not self.kb.parent_exists(canon):
                w = f"Parent technique {canon.split('.')[0]} not found for {canon}"
                match.warnings.append(w)
                result.warnings.append(w)

            result.validated.append(match)

    # ── INFERRED pass ─────────────────────────────────────────────────────────

    def _run_inferred(
        self,
        detection: CanonicalDetection,
        result: MappingResult,
        exclude_ids: set[str] | None = None,
    ) -> None:
        exclude_ids = exclude_ids or set()

        # Build search corpus
        logic_raw = detection.detection_logic.raw or ""
        corpus = " ".join([
            detection.name,
            detection.description,
            logic_raw,
        ]).lower()

        seen: dict[str, TechniqueMatch] = {}

        # 1. Keyword heuristics
        for entry in self.keywords:
            if entry.is_regex and entry.pattern:
                matched = bool(entry.pattern.search(corpus))
            else:
                matched = entry.keyword.lower() in corpus
            if not matched:
                continue
            for tid in entry.techniques:
                canon = normalise_technique_id(tid)
                if not canon or canon in exclude_ids:
                    continue
                tech = self.kb.get_technique(canon)
                if tech is None or tech.deprecated or tech.revoked:
                    continue
                if canon not in seen or seen[canon].confidence < entry.confidence:
                    seen[canon] = TechniqueMatch(
                        technique_id=canon,
                        tactic=tech.tactic,
                        confidence=entry.confidence,
                        source="keyword",
                        reasoning=f"Matched keyword: {entry.keyword!r}",
                    )

        # 2. Data-source correlation
        # Collect all log source identifiers from this detection
        log_source_ids: set[str] = set()
        for ls in detection.log_sources:
            for val in [ls.product, ls.category, ls.service]:
                if val:
                    log_source_ids.add(val.lower())

        for hint in self.ds_hints:
            # Check if any log source matches
            ls_match = any(ls in log_source_ids for ls in hint.log_sources)
            if not ls_match:
                continue
            # Check if any keyword matches the query
            kw_match = any(kw in corpus for kw in hint.keywords)
            if not kw_match:
                continue
            for tid in hint.techniques:
                canon = normalise_technique_id(tid)
                if not canon or canon in exclude_ids:
                    continue
                tech = self.kb.get_technique(canon)
                if tech is None or tech.deprecated or tech.revoked:
                    continue
                existing = seen.get(canon)
                if existing is None or existing.confidence < hint.confidence:
                    seen[canon] = TechniqueMatch(
                        technique_id=canon,
                        tactic=tech.tactic,
                        confidence=hint.confidence,
                        source="datasource",
                        reasoning=(
                            f"Log source matched {hint.log_sources!r}; "
                            f"query matched keyword in {hint.keywords!r}"
                        ),
                    )

        result.inferred.extend(seen.values())

        # 3. Optional LLM pass
        if self._use_llm:
            try:
                prompt = _render_prompt(
                    detection,
                    candidate_summary=list(seen.values()),
                    config=self.llm_config,
                    config_dir=self._config_dir,
                )
                llm_matches = _call_llm(prompt, self.llm_config)
                for m in llm_matches:
                    if m.technique_id in exclude_ids:
                        continue
                    tech = self.kb.get_technique(m.technique_id)
                    if tech and not tech.deprecated:
                        m.tactic = tech.tactic if m.tactic == "unknown" else m.tactic
                        if m.technique_id not in {x.technique_id for x in result.inferred}:
                            result.inferred.append(m)
            except Exception as exc:
                result.warnings.append(f"LLM inference failed: {exc}")
                logger.warning("LLM inference failed for %s: %s", detection.id, exc)

    # ── Batch helpers ─────────────────────────────────────────────────────────

    def map_many(
        self,
        detections: list[CanonicalDetection],
        mode: str = MappingMode.HYBRID,
    ) -> list[MappingResult]:
        return [self.map_detection(d, mode) for d in detections]

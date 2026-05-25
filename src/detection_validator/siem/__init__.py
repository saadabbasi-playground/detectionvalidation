"""
SIEM backend abstraction layer.

``SIEMBackend`` is the abstract base; each adapter implements it for a specific
SIEM product. Use ``get_backend(name)`` to obtain a configured instance.

Supported backends (stubs):
  splunk, opensearch, elastic, sentinel, chronicle, wazuh
"""

from __future__ import annotations

from detection_validator.siem.base import SIEMBackend


def get_backend(name: str, **kwargs) -> SIEMBackend:
    """Factory: return a configured SIEMBackend for *name*."""
    backends = {
        "splunk": "detection_validator.siem.splunk:SplunkBackend",
        "opensearch": "detection_validator.siem.opensearch:OpenSearchBackend",
        "elastic": "detection_validator.siem.elastic:ElasticBackend",
        "sentinel": "detection_validator.siem.sentinel:SentinelBackend",
        "chronicle": "detection_validator.siem.chronicle:ChronicleBackend",
        "wazuh": "detection_validator.siem.wazuh:WazuhBackend",
    }
    if name not in backends:
        raise ValueError(f"Unknown SIEM backend: {name!r}. Choose from: {list(backends)}")
    module_path, class_name = backends[name].rsplit(":", 1)
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    return cls(**kwargs)


__all__ = ["SIEMBackend", "get_backend"]

"""
Intel — cached threat intelligence store.

Downloads and caches:
  - MITRE ATT&CK STIX bundle
  - NVD CVE JSON feeds
  - Atomic Red Team index
  - Public detection rule repositories (Sigma, Elastic detection rules)

All data is stored under ~/.cache/detection-validator/ and refreshed on a
configurable TTL.
"""

from __future__ import annotations

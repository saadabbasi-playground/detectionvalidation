"""
Validator — detection rule validation pipeline.

Three validation modes:
  1. ``AtomicRedTeamValidator``  — fires ART tests and checks alerts appear in SIEM
  2. ``SyntheticEventValidator`` — injects crafted telemetry without needing a victim
  3. ``StaticLinter``            — offline structural / logic checks (no SIEM required)
"""

from __future__ import annotations

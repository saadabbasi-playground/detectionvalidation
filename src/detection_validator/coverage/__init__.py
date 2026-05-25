"""
Coverage — ATT&CK matrix builder, scoring, and gap analysis.

Takes a list of validated ``DetectionRule`` objects and produces a coverage
matrix aligned to MITRE ATT&CK, a numeric score, and a gap report.
"""

from __future__ import annotations

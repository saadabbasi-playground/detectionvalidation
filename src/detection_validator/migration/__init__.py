"""
Migration — SIEM-to-SIEM rule migration mode.

Analyses an existing SIEM rule set, translates to the target platform,
highlights coverage gaps introduced by format limitations, and produces
a migration report with a confidence score per rule.
"""

from __future__ import annotations

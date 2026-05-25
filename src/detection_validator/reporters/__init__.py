"""
Reporters — output adapters for validation results.

Each reporter takes ``ValidationResult`` objects and renders them in a
specific format: CLI table, HTML, JSON, SARIF (for GitHub Code Scanning),
or a Slack notification.
"""

from __future__ import annotations

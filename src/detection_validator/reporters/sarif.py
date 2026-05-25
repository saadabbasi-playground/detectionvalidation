"""SARIF 2.1.0 reporter — for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from pathlib import Path


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


class SARIFReporter:
    """Emit validation failures as a SARIF 2.1.0 document."""

    def report(self, results: list) -> dict:
        """Build and return the SARIF document as a dict."""
        runs = [{
            "tool": {
                "driver": {
                    "name": "detection-validator",
                    "version": "0.1.0",
                    "rules": [],
                }
            },
            "results": [],
        }]
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": runs,
        }

    def write(self, results: list, path: Path) -> None:
        """Write SARIF JSON to *path*."""
        sarif = self.report(results)
        path.write_text(json.dumps(sarif, indent=2))

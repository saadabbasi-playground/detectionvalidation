"""Slack reporter — posts a validation summary to a Slack channel."""

from __future__ import annotations

import requests


class SlackReporter:
    """Post validation summaries to Slack via incoming webhook."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def report(self, results: list, run_id: str = "") -> None:
        passed = sum(1 for r in results if getattr(r, "passed", False))
        failed = len(results) - passed
        text = (
            f"*Detection Validator* run `{run_id or 'latest'}`\n"
            f":white_check_mark: {passed} passed  "
            f":x: {failed} failed"
        )
        requests.post(self.webhook_url, json={"text": text}, timeout=10)

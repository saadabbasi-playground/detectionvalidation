"""Celery task definitions."""

from __future__ import annotations

from celery import Celery

celery_app = Celery("detection_validator")


@celery_app.task(name="validate_rule")
def validate_rule(rule_id: str, siem: str = "opensearch") -> dict:
    """Validate a single detection rule against the specified SIEM."""
    raise NotImplementedError


@celery_app.task(name="run_scenario")
def run_scenario(scenario_path: str, siem: str = "opensearch") -> dict:
    """Execute an attack scenario and collect validation results."""
    raise NotImplementedError


@celery_app.task(name="generate_report")
def generate_report(job_id: str, fmt: str = "json") -> str:
    """Generate a validation report for a completed job."""
    raise NotImplementedError

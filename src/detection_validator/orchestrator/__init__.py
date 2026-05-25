"""
Orchestrator — FastAPI REST API + Celery async task queue.

Exposes the validation pipeline over HTTP and manages long-running jobs
(ART test suites, batch validations) as Celery tasks.
"""

from __future__ import annotations

"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(
        title="Detection Validator API",
        description="Multi-SIEM detection validation platform REST API",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/v1/rules")
    async def list_rules() -> dict:
        """List all known detection rules."""
        return {"rules": [], "total": 0}

    @app.post("/api/v1/validate")
    async def trigger_validation(body: dict) -> dict:
        """Trigger an async validation job; returns a task ID."""
        return {"task_id": "todo", "status": "queued"}

    @app.get("/api/v1/jobs/{task_id}")
    async def job_status(task_id: str) -> dict:
        """Poll the status of a running or completed validation job."""
        return {"task_id": task_id, "status": "unknown"}

    return app


app = create_app()

"""Response models for health checks."""

from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    version: str
    environment: str


class DatabaseHealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    database: Literal["connected"] = "connected"
    latency_ms: float


class DatabaseErrorResponse(BaseModel):
    status: Literal["error"] = "error"
    database: Literal["unavailable"] = "unavailable"
    detail: str

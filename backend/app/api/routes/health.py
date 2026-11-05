"""Health endpoints for the API and its database dependency."""

import logging
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.db.engine import engine
from app.schemas.health import (
    DatabaseErrorResponse,
    DatabaseHealthResponse,
    HealthResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Confirm that the FastAPI process is running."""

    return HealthResponse(
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
    )


@router.get(
    "/health/db",
    response_model=DatabaseHealthResponse,
    responses={503: {"model": DatabaseErrorResponse}},
)
async def database_health_check() -> DatabaseHealthResponse | JSONResponse:
    """Run a tiny ``SELECT 1`` against Neon.

    Errors are deliberately generic so connection details and credentials are
    never returned to the browser.
    """

    if engine is None:
        return JSONResponse(
            status_code=503,
            content=DatabaseErrorResponse(
                detail=(
                    "Database is not configured. Add DATABASE_URL to "
                    "backend/.env and restart the API."
                )
            ).model_dump(),
        )

    started = time.perf_counter()
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - convert any driver error safely
        logger.warning("Database health check failed (%s).", type(exc).__name__)
        return JSONResponse(
            status_code=503,
            content=DatabaseErrorResponse(
                detail=(
                    "Database connection failed. Check the API log and the "
                    "Neon connection string."
                )
            ).model_dump(),
        )

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return DatabaseHealthResponse(latency_ms=elapsed_ms)

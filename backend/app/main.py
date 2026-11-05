"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.api.router import api_router
from app.core.config import settings
from app.core.exceptions import AppError
from app.db.engine import dispose_engine

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Release database connections when the API stops."""

    yield
    await dispose_engine()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="VulnSight vulnerability assessment API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforce defensive HTTP response headers on all VulnSight endpoints."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response


@app.exception_handler(AppError)
async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed.",
                "details": jsonable_encoder(exc.errors()),
            }
        },
    )


@app.exception_handler(IntegrityError)
async def integrity_error_handler(
    _: Request,
    exc: IntegrityError,
) -> JSONResponse:
    logger.warning("Database integrity error (%s).", type(exc).__name__)
    return JSONResponse(
        status_code=409,
        content={
            "error": {
                "code": "data_conflict",
                "message": (
                    "The request conflicts with existing data or a database "
                    "constraint."
                ),
                "details": None,
            }
        },
    )


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(
    _: Request,
    exc: SQLAlchemyError,
) -> JSONResponse:
    logger.exception("Database operation failed (%s).", type(exc).__name__)
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "code": "database_error",
                "message": (
                    "A database operation failed. Check the API log and try "
                    "again."
                ),
                "details": None,
            }
        },
    )


app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    """Small landing response with useful development links."""

    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": f"{settings.api_v1_prefix}/health",
        "database_health": f"{settings.api_v1_prefix}/health/db",
        "scans": f"{settings.api_v1_prefix}/scans",
    }

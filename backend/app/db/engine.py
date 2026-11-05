"""Async SQLAlchemy engine and session factory.

The engine is created only when DATABASE_URL is configured. This lets the
frontend and API start before Neon has been connected.
"""

import ssl
from collections.abc import AsyncIterator

import certifi
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.core.exceptions import ServiceUnavailableError
from app.db.url import normalize_async_database_url


def _create_engine() -> AsyncEngine | None:
    if not settings.database_url:
        return None

    database_url = normalize_async_database_url(settings.database_url)

    # Verify the Neon server certificate instead of accepting any certificate.
    ssl_context = ssl.create_default_context(cafile=certifi.where())

    return create_async_engine(
        database_url,
        connect_args={"ssl": ssl_context},
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_timeout=30,
        pool_recycle=300,
        pool_use_lifo=True,
        echo=False,
    )


engine = _create_engine()

AsyncSessionLocal = (
    async_sessionmaker(engine, expire_on_commit=False) if engine else None
)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that provides a short-lived database session.

    The session is not committed automatically. Services decide when a
    transaction is complete. If an exception escapes, the transaction is rolled
    back before the connection returns to the pool.
    """

    if AsyncSessionLocal is None:
        raise ServiceUnavailableError(
            "Database is not configured. Add DATABASE_URL to backend/.env "
            "and restart the API.",
            code="database_not_configured",
        )

    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Close pooled connections during application shutdown."""

    if engine is not None:
        await engine.dispose()

"""Tests for Neon connection-string normalization."""

from app.db.url import normalize_async_database_url


def test_empty_url_stays_empty() -> None:
    assert normalize_async_database_url("") == ""


def test_neon_url_becomes_asyncpg_url_without_libpq_options() -> None:
    raw = (
        "postgresql://vulnsight:secret@ep-example-123.us-east-2.aws.neon.tech/"
        "neondb?sslmode=require&channel_binding=require"
    )

    normalized = normalize_async_database_url(raw)

    assert normalized.startswith("postgresql+asyncpg://")
    assert "sslmode" not in normalized
    assert "channel_binding" not in normalized
    assert "ep-example-123.us-east-2.aws.neon.tech" in normalized

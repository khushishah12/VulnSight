"""Foundation smoke tests."""

import httpx
import pytest

from app.main import app

pytestmark = pytest.mark.asyncio


async def test_root_returns_links() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/")

        assert response.status_code == 200
        body = response.json()
        assert body["name"] == "VulnSight API"
        assert body["health"] == "/api/v1/health"


async def test_health_check() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/v1/health")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["service"] == "VulnSight API"
        assert body["version"] == "0.1.0"


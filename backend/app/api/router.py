"""Top-level API router."""

from fastapi import APIRouter

from app.api.routes import findings, health, recon, reports, scans

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(recon.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)

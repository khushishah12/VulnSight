"""Backfill risk_score and detection_method on existing findings."""

import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from app.db.engine import AsyncSessionLocal
from app.models.finding import Finding
from app.services.risk_engine import calculate_risk_assessment


async def backfill() -> None:
    if AsyncSessionLocal is None:
        print("AsyncSessionLocal is None!")
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Finding))
        findings = result.scalars().all()
        updated_count = 0
        for f in findings:
            if f.risk_score is None:
                assessment = calculate_risk_assessment(
                    severity=f.severity,
                    confidence=f.confidence,
                    owasp_category=f.owasp_category,
                )
                f.risk_score = assessment.score
                updated_count += 1
            if f.detection_method is None:
                f.detection_method = "automated_security_check"
                updated_count += 1

        if updated_count > 0:
            await session.commit()
        print(f"Checked {len(findings)} findings, updated {updated_count} fields.")


if __name__ == "__main__":
    asyncio.run(backfill())

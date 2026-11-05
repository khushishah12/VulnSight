"""Print a compact summary of the live database schema.

Usage (from ``backend``):

    .\\.venv\\Scripts\\python.exe scripts\\inspect_schema.py
"""

import asyncio

from sqlalchemy import text

from app.db.engine import AsyncSessionLocal, dispose_engine


async def main() -> None:
    if AsyncSessionLocal is None:
        raise SystemExit("DATABASE_URL is not configured.")

    async with AsyncSessionLocal() as session:
        tables = (
            await session.execute(
                text(
                    "select tablename from pg_tables "
                    "where schemaname = 'public' order by tablename"
                )
            )
        ).scalars().all()
        print(f"Tables ({len(tables)}):")
        for name in tables:
            print(f"  - {name}")

        indexes = (
            await session.execute(
                text(
                    "select count(*) from pg_indexes "
                    "where schemaname = 'public'"
                )
            )
        ).scalar_one()
        fks = (
            await session.execute(
                text(
                    "select count(*) from information_schema.table_constraints "
                    "where constraint_schema = 'public' "
                    "and constraint_type = 'FOREIGN KEY'"
                )
            )
        ).scalar_one()
        checks = (
            await session.execute(
                text(
                    "select count(*) from information_schema.table_constraints "
                    "where constraint_schema = 'public' "
                    "and constraint_type = 'CHECK'"
                )
            )
        ).scalar_one()
        print(f"Indexes: {indexes}")
        print(f"Foreign keys: {fks}")
        print(f"Check constraints: {checks}")

        single_running = (
            await session.execute(
                text(
                    "select indexdef from pg_indexes "
                    "where indexname = 'uq_scan_sessions_single_running'"
                )
            )
        ).scalar_one_or_none()
        print(f"Single-running index: {single_running}")

    await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())

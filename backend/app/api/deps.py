"""Shared FastAPI dependencies and query parameter types."""

from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_session

SessionDep = Annotated[AsyncSession, Depends(get_session)]

LimitQuery = Annotated[int, Query(ge=1, le=100)]
OffsetQuery = Annotated[int, Query(ge=0)]

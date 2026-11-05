"""Shared Pydantic base classes and response envelopes."""

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class ORMModel(BaseModel):
    """Base for response schemas that may be built from ORM objects."""

    model_config = ConfigDict(from_attributes=True)


class Page(ORMModel, Generic[T]):
    """Offset pagination envelope used by list endpoints."""

    items: list[T]
    total: int
    limit: int
    offset: int


class ErrorBody(BaseModel):
    code: str
    message: str
    details: object | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody

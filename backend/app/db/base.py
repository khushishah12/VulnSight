"""Shared SQLAlchemy declarative base.

A naming convention is defined before any tables are created so Alembic can
generate stable, readable constraint names. Changing this later would make
future migrations noisy.
"""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all VulnSight ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

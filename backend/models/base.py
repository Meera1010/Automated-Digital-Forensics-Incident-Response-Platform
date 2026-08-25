"""
ADFIR Platform — SQLAlchemy Model Base
=======================================
Provides a shared declarative base with common columns (id, created_at,
updated_at) inherited by most models.  Import ``Base`` from here when
defining new models.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, TypeDecorator, CHAR
from sqlalchemy.dialects.postgresql import UUID as PgUUID

from backend.extensions import db


class UUIDType(TypeDecorator):
    """
    Platform-independent UUID column type.
    - Uses PostgreSQL's native UUID type on Postgres.
    - Falls back to CHAR(36) on SQLite and other dialects.
    Python side: always works with uuid.UUID objects.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PgUUID(as_uuid=True))
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            # Postgres native UUID — pass uuid.UUID directly
            if isinstance(value, uuid.UUID):
                return value
            return uuid.UUID(str(value))
        else:
            # SQLite/other — store as str
            if isinstance(value, uuid.UUID):
                return str(value)
            return str(uuid.UUID(str(value)))

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            return uuid.UUID(value)
        return value


class TimestampMixin:
    """
    Mixin that adds created_at and updated_at columns to any model.
    Both are stored as timezone-aware UTC timestamps.
    """

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class UUIDPrimaryKeyMixin:
    """
    Mixin that provides a UUID v4 primary key column named ``id``.
    The UUID is generated in Python (not by the database) so it is
    available immediately after object creation, before the INSERT.
    Works on both PostgreSQL (native UUID) and SQLite (CHAR(36)).
    """

    id = Column(
        UUIDType(),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )


def generate_uuid() -> uuid.UUID:
    """Convenience function for generating a new UUID v4."""
    return uuid.uuid4()

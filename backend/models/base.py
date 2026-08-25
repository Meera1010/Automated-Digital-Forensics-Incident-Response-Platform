"""
ADFIR Platform — SQLAlchemy Model Base
=======================================
Provides a shared declarative base with common columns (id, created_at,
updated_at) inherited by most models.  Import ``Base`` from here when
defining new models.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime
from sqlalchemy.dialects.postgresql import UUID

from backend.extensions import db


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
    """

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )


def generate_uuid() -> uuid.UUID:
    """Convenience function for generating a new UUID v4."""
    return uuid.uuid4()

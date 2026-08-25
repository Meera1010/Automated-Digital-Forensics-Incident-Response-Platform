"""
ADFIR Platform — User Model
============================
Stores analyst and supervisor accounts used to authenticate with the
platform API.  Passwords are stored as bcrypt hashes — never plaintext.

Roles:
  readonly   — Dashboard view only.
  analyst    — Read + investigate + evidence download.
  supervisor — Full access including rule/playbook management and manual close.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime, Enum as SaEnum
from sqlalchemy.dialects.postgresql import UUID
import enum

from backend.extensions import db
from backend.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class UserRole(enum.Enum):
    READONLY = "readonly"
    ANALYST = "analyst"
    SUPERVISOR = "supervisor"


class User(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    """
    Platform user account.
    """

    __tablename__ = "users"

    # Display name shown in the UI and audit log.
    username = Column(String(64), unique=True, nullable=False, index=True)

    # bcrypt hash of the user's password (never store plaintext).
    password_hash = Column(String(128), nullable=False)

    # The user's access level.
    role = Column(
        SaEnum(UserRole, name="user_role_enum"),
        nullable=False,
        default=UserRole.READONLY,
    )

    # Soft-delete / account suspension without removing the audit history.
    is_active = Column(Boolean, nullable=False, default=True)

    # Track the last successful login for audit purposes.
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role.value}>"

    def to_dict(self) -> dict:
        """Return a safe public representation (no password hash)."""
        return {
            "id": str(self.id),
            "username": self.username,
            "role": self.role.value,
            "is_active": self.is_active,
            "last_login_at": (
                self.last_login_at.isoformat() if self.last_login_at else None
            ),
            "created_at": self.created_at.isoformat(),
        }

    def set_password(self, password: str) -> None:
        """Hash and set the user's password using werkzeug.security."""
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify password against stored password hash."""
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)


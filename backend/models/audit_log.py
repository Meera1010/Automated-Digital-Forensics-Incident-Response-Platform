"""
ADFIR Platform — AuditLog Model
=================================
Immutable, append-only record of every significant system and user action.
The integrity of the chain is maintained by including the SHA-256 hash of
the previous row's content in each new row (chained checksum).

Database-level protection:
  - The application DB user has INSERT + SELECT only on this table.
  - No UPDATE or DELETE is ever executed on audit_log by the application.

Verifying integrity:
  - Walk all rows in ``id`` order.
  - Recompute: SHA-256(prev_checksum + this_row_content).
  - Assert it matches the stored ``row_checksum``.
  - A mismatch at position N means row N (or N-1) was tampered with.
"""

from sqlalchemy import (
    Column,
    BigInteger,
    String,
    DateTime,
    Text,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB

from backend.extensions import db


class AuditLog(db.Model):
    """
    Append-only, chained audit trail entry.
    """

    __tablename__ = "audit_log"

    # Sequential integer PK ensures rows can be walked in insertion order.
    id = Column(BigInteger, primary_key=True, autoincrement=True)

    # UTC timestamp of the event.
    logged_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Whether this was triggered by the system or a human user.
    actor_type = Column(String(16), nullable=False)  # 'system' | 'user'

    # Module name (for system) or user UUID (for user).
    actor_id = Column(String(128), nullable=False)

    # The backend module that generated this entry.
    module = Column(String(64), nullable=False, index=True)

    # Short verb describing what happened, e.g. 'incident.state_transition'.
    action = Column(String(128), nullable=False, index=True)

    # The type of entity affected, e.g. 'incident', 'evidence_artifact'.
    target_type = Column(String(64), nullable=True)

    # UUID of the affected entity (nullable for global events).
    target_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    # Structured supplementary detail.
    detail_json = Column(JSONB, nullable=True)

    # SHA-256 hex digest of the PREVIOUS row's row_checksum.
    # The very first row stores a fixed sentinel value.
    prev_checksum = Column(String(64), nullable=False)

    # SHA-256(prev_checksum + this row's canonical content string).
    row_checksum = Column(String(64), nullable=False, unique=True)

    def __repr__(self) -> str:
        return (
            f"<AuditLog #{self.id} "
            f"actor={self.actor_id!r} "
            f"action={self.action!r}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "logged_at": self.logged_at.isoformat(),
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "module": self.module,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": str(self.target_id) if self.target_id else None,
            "detail_json": self.detail_json,
            "row_checksum": self.row_checksum,
        }

from sqlalchemy import event

@event.listens_for(AuditLog, 'before_update')
def receive_before_update(mapper, connection, target):
    raise ValueError("Audit log entries are immutable and cannot be updated.")

@event.listens_for(AuditLog, 'before_delete')
def receive_before_delete(mapper, connection, target):
    raise ValueError("Audit log entries are immutable and cannot be deleted.")

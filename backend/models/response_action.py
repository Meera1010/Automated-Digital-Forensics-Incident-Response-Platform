"""
ADFIR Platform — ResponseAction Model
========================================
Records each individual automated action executed (or attempted) by the
Response Engine for an incident.  Actions are executed in playbook order;
each is recorded independently for auditability.
"""

import enum
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy import JSON
from backend.models.base import UUIDType
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import UUIDPrimaryKeyMixin


class ActionStatus(enum.Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class ResponseAction(UUIDPrimaryKeyMixin, db.Model):
    """
    A single automated response action execution record.
    """

    __tablename__ = "response_actions"

    # The incident this action was taken for.
    incident_id = Column(
        UUIDType(),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # The playbook that prescribed this action.
    playbook_id = Column(
        UUIDType(),
        ForeignKey("response_playbooks.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # Name of the action handler, e.g. 'block_synthetic_ip'.
    action_name = Column(String(128), nullable=False)

    # The parameters passed to the action handler (from playbook YAML).
    action_params_json = Column(JSON, nullable=False, default=dict)

    # Execution outcome.
    status = Column(
        String(32),
        nullable=False,
        default=ActionStatus.PENDING.value,
        index=True,
    )

    # When the action handler was invoked.
    executed_at = Column(DateTime(timezone=True), nullable=True)

    # Human-readable summary of what happened (success or failure detail).
    result_detail = Column(Text, nullable=True)

    # How long the action took to complete, in milliseconds.
    duration_ms = Column(Integer, nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="response_actions")
    playbook = relationship("ResponsePlaybook", back_populates="response_actions")

    def __repr__(self) -> str:
        return (
            f"<ResponseAction {self.action_name!r} "
            f"status={self.status} "
            f"incident={str(self.incident_id):.8}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "playbook_id": str(self.playbook_id),
            "action_name": self.action_name,
            "action_params_json": self.action_params_json,
            "status": self.status,
            "executed_at": (
                self.executed_at.isoformat() if self.executed_at else None
            ),
            "result_detail": self.result_detail,
            "duration_ms": self.duration_ms,
        }

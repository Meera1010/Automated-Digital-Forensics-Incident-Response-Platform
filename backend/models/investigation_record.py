"""
ADFIR Platform — InvestigationRecord Model
==========================================
Records the details and progress of an incident investigation.
"""

from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import UUIDPrimaryKeyMixin, TimestampMixin


class InvestigationRecord(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    """
    A record documenting the investigation of an Incident.
    """

    __tablename__ = "investigation_records"

    # The incident this investigation documents.
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Freeform notes, findings, and analysis.
    findings = Column(Text, nullable=True)

    # Current status of the investigation (e.g. IN_PROGRESS, COMPLETED)
    status = Column(String(32), nullable=False, default="IN_PROGRESS")

    # Relationship
    incident = relationship("Incident", backref="investigation_records")

    def __repr__(self) -> str:
        return (
            f"<InvestigationRecord {self.id!s:.8} "
            f"incident={str(self.incident_id):.8}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "findings": self.findings,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

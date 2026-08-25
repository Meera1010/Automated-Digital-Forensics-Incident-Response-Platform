"""
ADFIR Platform — Incident Model
=================================
Central entity in the platform.  An Incident is opened when one or more
DetectionHits are correlated together, and progresses through a defined
state machine until it is closed.

State machine:
  NEW → INVESTIGATING → CONFIRMED → CONTAINED → RESOLVED (or FALSE_POSITIVE)

All state transitions are recorded in the audit_log.
"""

import enum
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from backend.models.base import UUIDType
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class IncidentStatus(enum.Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentSeverity(enum.Enum):
    P1 = "P1"  # Critical
    P2 = "P2"  # High
    P3 = "P3"  # Medium
    P4 = "P4"  # Low


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    """
    A security incident that has been detected, investigated, and responded to.
    """

    __tablename__ = "incidents"

    # Human-readable identifier displayed in the UI, e.g. 'INC-2025-00001'.
    incident_number = Column(
        String(32), unique=True, nullable=False, index=True
    )

    # Short auto-generated title describing the attack type and primary asset.
    title = Column(String(256), nullable=False)

    # Current position in the incident lifecycle state machine.
    status = Column(
        String(32),
        nullable=False,
        default=IncidentStatus.NEW.value,
        index=True,
    )

    # Set after the Severity Classifier runs (null until CLASSIFIED state).
    severity = Column(String(4), nullable=True, index=True)

    # Attack category matching response playbook categories.
    # e.g. 'brute_force', 'port_scan', 'data_exfiltration'.
    attack_category = Column(String(64), nullable=True, index=True)

    # The primary synthetic asset involved (soft reference to synthetic_assets).
    primary_asset_id = Column(String(64), nullable=True)

    # Auto-generated plain-language narrative of the incident.
    summary_text = Column(Text, nullable=True)

    # Timestamps for each major state transition.
    opened_at = Column(DateTime(timezone=True), nullable=True)
    classified_at = Column(DateTime(timezone=True), nullable=True)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    # The playbook assigned to this incident during the RESPONDING phase.
    assigned_playbook_id = Column(
        UUIDType(),
        ForeignKey("response_playbooks.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    detection_hits = relationship(
        "DetectionHit", back_populates="incident", lazy="dynamic"
    )
    severity_assessments = relationship(
        "SeverityAssessment", back_populates="incident", lazy="dynamic"
    )
    evidence_artifacts = relationship(
        "EvidenceArtifact", back_populates="incident", lazy="dynamic"
    )
    response_actions = relationship(
        "ResponseAction", back_populates="incident", lazy="dynamic"
    )
    reports = relationship(
        "Report", back_populates="incident", lazy="dynamic"
    )
    assigned_playbook = relationship("ResponsePlaybook")

    def __repr__(self) -> str:
        return (
            f"<Incident {self.incident_number!r} "
            f"status={self.status} severity={self.severity}>"
        )

    def to_dict(self, include_counts: bool = False) -> dict:
        data = {
            "id": str(self.id),
            "incident_number": self.incident_number,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "attack_category": self.attack_category,
            "primary_asset_id": self.primary_asset_id,
            "summary_text": self.summary_text,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "classified_at": (
                self.classified_at.isoformat() if self.classified_at else None
            ),
            "contained_at": (
                self.contained_at.isoformat() if self.contained_at else None
            ),
            "closed_at": (
                self.closed_at.isoformat() if self.closed_at else None
            ),
            "assigned_playbook_id": (
                str(self.assigned_playbook_id)
                if self.assigned_playbook_id
                else None
            ),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if include_counts:
            data["evidence_count"] = self.evidence_artifacts.count()
            data["action_count"] = self.response_actions.count()
        return data

"""
ADFIR Platform — DetectionHit Model
=====================================
Created whenever a DetectionRule fires on a RawEvent.  Each hit
represents one confirmed rule match.  Multiple hits can be correlated
into a single Incident by the Orchestrator.
"""

from sqlalchemy import Column, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import UUIDPrimaryKeyMixin


class DetectionHit(UUIDPrimaryKeyMixin, db.Model):
    """
    A rule-fired event linking a DetectionRule to a RawEvent.
    """

    __tablename__ = "detection_hits"

    # The rule that produced this hit.
    rule_id = Column(
        UUID(as_uuid=True),
        ForeignKey("detection_rules.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # The raw event that triggered the rule.
    raw_event_id = Column(
        UUID(as_uuid=True),
        ForeignKey("raw_events.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # When the rule evaluator produced this hit.
    fired_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Detailed match context: which fields matched, the threshold count, etc.
    match_detail_json = Column(JSONB, nullable=False, default=dict)

    # Set by the Orchestrator once this hit is linked to an incident.
    correlated_incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    rule = relationship("DetectionRule", back_populates="detection_hits")
    raw_event = relationship("RawEvent", back_populates="detection_hits")
    incident = relationship("Incident", back_populates="detection_hits")

    def __repr__(self) -> str:
        return (
            f"<DetectionHit {self.id!s:.8} "
            f"rule={self.rule_id!s:.8} "
            f"incident={str(self.correlated_incident_id or 'none'):.8}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "rule_id": str(self.rule_id),
            "raw_event_id": str(self.raw_event_id),
            "fired_at": self.fired_at.isoformat(),
            "match_detail_json": self.match_detail_json,
            "correlated_incident_id": (
                str(self.correlated_incident_id)
                if self.correlated_incident_id
                else None
            ),
        }

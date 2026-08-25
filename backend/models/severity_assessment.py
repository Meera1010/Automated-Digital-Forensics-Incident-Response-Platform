"""
ADFIR Platform — SeverityAssessment Model
==========================================
Records the result of the Severity Classifier for an incident.
The classifier scores five dimensions (1–10 each) and maps the weighted
composite score to a severity tier (P1–P4).

One incident may have multiple assessments if the classifier reruns
(e.g., after new evidence is collected), but only the most recent one
determines the incident's current severity field.
"""

from sqlalchemy import Column, SmallInteger, Numeric, String, DateTime, ForeignKey, Text
from sqlalchemy import JSON
from backend.models.base import UUIDType
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import UUIDPrimaryKeyMixin


class SeverityAssessment(UUIDPrimaryKeyMixin, db.Model):
    """
    Weighted severity scoring record for a classified incident.
    """

    __tablename__ = "severity_assessments"

    # The incident this assessment belongs to.
    incident_id = Column(
        UUIDType(),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # When this assessment was computed.
    assessed_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # --- Five scoring dimensions (each 0–10) ----------------------------

    # How critical is the affected synthetic asset? (from synthetic_assets.criticality * 2)
    asset_criticality_score = Column(SmallInteger, nullable=False, default=0)

    # How confident is the detection rule match? (from rule severity_weight)
    attack_confidence_score = Column(SmallInteger, nullable=False, default=0)

    # How many raw events were correlated? (logarithmic scale 0–10)
    event_volume_score = Column(SmallInteger, nullable=False, default=0)

    # Average severity_weight of the rules that fired.
    rule_severity_score = Column(SmallInteger, nullable=False, default=0)

    # Is the detection outside business hours? (0 = day, 5 = evening, 10 = night)
    time_risk_score = Column(SmallInteger, nullable=False, default=0)

    # --- Output --------------------------------------------------------

    # Weighted sum: (asset×0.3) + (confidence×0.25) + (volume×0.15) + (rule×0.20) + (time×0.10)
    composite_score = Column(Numeric(precision=5, scale=2), nullable=False, default=0)

    # The tier assigned based on composite_score thresholds.
    # P1: ≥8.0 | P2: ≥6.0 | P3: ≥3.5 | P4: <3.5
    assigned_severity = Column(String(4), nullable=False)

    # Machine-readable explanation of the scoring breakdown.
    rationale_json = Column(JSON, nullable=False, default=dict)

    # Relationship
    incident = relationship("Incident", back_populates="severity_assessments")

    def __repr__(self) -> str:
        return (
            f"<SeverityAssessment incident={str(self.incident_id):.8} "
            f"score={self.composite_score} tier={self.assigned_severity}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "assessed_at": self.assessed_at.isoformat(),
            "asset_criticality_score": self.asset_criticality_score,
            "attack_confidence_score": self.attack_confidence_score,
            "event_volume_score": self.event_volume_score,
            "rule_severity_score": self.rule_severity_score,
            "time_risk_score": self.time_risk_score,
            "composite_score": float(self.composite_score),
            "assigned_severity": self.assigned_severity,
            "rationale_json": self.rationale_json,
        }

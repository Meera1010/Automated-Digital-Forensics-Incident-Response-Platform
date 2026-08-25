"""
ADFIR Platform — ResponsePlaybook Model
=========================================
Stores the definition of an automated response playbook.  Each playbook
targets a specific (attack_category, severity_tier) combination and contains
an ordered list of safe lab actions to execute.

Playbooks are loaded from YAML files in backend/response/playbooks/ at
startup and upserted into this table.
"""

from sqlalchemy import Column, String, Boolean, Text
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class ResponsePlaybook(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    """
    A named, ordered sequence of safe automated response actions.
    """

    __tablename__ = "response_playbooks"

    # Display name, e.g. 'Brute Force Response - High Severity'.
    name = Column(String(128), nullable=False)

    # Must match Incident.attack_category values.
    attack_category = Column(String(64), nullable=False, index=True)

    # The severity tier this playbook handles: P1, P2, P3, or P4.
    severity_tier = Column(String(4), nullable=False, index=True)

    # YAML text defining the ordered list of actions and their parameters.
    actions_yaml = Column(Text, nullable=False)

    # Disable a playbook without deleting it.
    enabled = Column(Boolean, nullable=False, default=True)

    # Relationships
    incidents = relationship(
        "Incident", back_populates="assigned_playbook", lazy="dynamic"
    )
    response_actions = relationship(
        "ResponseAction", back_populates="playbook", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return (
            f"<ResponsePlaybook {self.name!r} "
            f"category={self.attack_category!r} "
            f"severity={self.severity_tier}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "attack_category": self.attack_category,
            "severity_tier": self.severity_tier,
            "actions_yaml": self.actions_yaml,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

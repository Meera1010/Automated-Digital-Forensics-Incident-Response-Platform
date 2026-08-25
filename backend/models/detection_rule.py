"""
ADFIR Platform — DetectionRule Model
======================================
Stores versioned detection rule definitions.  The rule logic (conditions)
is persisted as YAML text so it matches the on-disk YAML files loaded by
the rule_loader module.

Rule types:
  threshold       — N events matching criteria within T seconds.
  pattern_match   — Field value matches a regex or literal pattern.
  sequence        — Event A followed by event B within T seconds.
  allowlist       — Any matching event NOT present in the allowlist.
"""

import enum
from sqlalchemy import Column, String, Integer, SmallInteger, Boolean, Text, Enum as SaEnum
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class RuleType(enum.Enum):
    THRESHOLD = "threshold"
    PATTERN_MATCH = "pattern_match"
    SEQUENCE = "sequence"
    ALLOWLIST = "allowlist"


class DetectionRule(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    """
    A single detection rule evaluated against incoming RawEvent records.
    """

    __tablename__ = "detection_rules"

    # Short unique identifier matching the YAML filename, e.g. 'BRUTE_FORCE_001'.
    rule_id = Column(String(64), unique=True, nullable=False, index=True)

    # Human-readable name displayed in the UI.
    name = Column(String(128), nullable=False)

    # Detailed explanation of what this rule detects.
    description = Column(Text, nullable=True)

    # Determines which evaluator class handles this rule.
    rule_type = Column(
        SaEnum(RuleType, name="rule_type_enum"),
        nullable=False,
    )

    # Weight used by the severity classifier (1 = low, 10 = critical).
    severity_weight = Column(SmallInteger, nullable=False, default=5)

    # YAML text of the rule's condition block (mirrors the YAML file).
    conditions_yaml = Column(Text, nullable=False)

    # Whether the detection engine should evaluate this rule.
    enabled = Column(Boolean, nullable=False, default=True, index=True)

    # Incremented each time the rule definition is updated.
    version = Column(Integer, nullable=False, default=1)

    # Relationships
    detection_hits = relationship(
        "DetectionHit", back_populates="rule", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return (
            f"<DetectionRule {self.rule_id!r} "
            f"type={self.rule_type.value} v{self.version}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type.value,
            "severity_weight": self.severity_weight,
            "conditions_yaml": self.conditions_yaml,
            "enabled": self.enabled,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

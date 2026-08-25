"""
ADFIR Platform — Models Package
==================================
Exports all SQLAlchemy ORM models so Alembic can discover them via
``from backend.models import *`` in migrations/env.py.

Import order respects foreign-key dependencies:
  1. Models with no FK dependencies (User, SyntheticAsset)
  2. RawEvent (references SyntheticAsset via soft reference)
  3. DetectionRule, DetectionHit (references RawEvent)
  4. ResponsePlaybook
  5. Incident (references ResponsePlaybook)
  6. SeverityAssessment, EvidenceArtifact, ResponseAction, Report (reference Incident)
  7. AuditLog (references everything via target_id)
"""

from backend.models.base import TimestampMixin, UUIDPrimaryKeyMixin, generate_uuid
from backend.models.user import User, UserRole
from backend.models.synthetic_asset import SyntheticAsset, AssetType, AssetStatus
from backend.models.raw_event import RawEvent
from backend.models.detection_rule import DetectionRule, RuleType
from backend.models.detection_hit import DetectionHit
from backend.models.response_playbook import ResponsePlaybook
from backend.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.models.severity_assessment import SeverityAssessment
from backend.models.evidence_artifact import EvidenceArtifact, ArtifactType
from backend.models.response_action import ResponseAction, ActionStatus
from backend.models.audit_log import AuditLog
from backend.models.report import Report, ReportFormat

__all__ = [
    # Base utilities
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "generate_uuid",
    # Models
    "User",
    "UserRole",
    "SyntheticAsset",
    "AssetType",
    "AssetStatus",
    "RawEvent",
    "DetectionRule",
    "RuleType",
    "DetectionHit",
    "ResponsePlaybook",
    "Incident",
    "IncidentStatus",
    "IncidentSeverity",
    "SeverityAssessment",
    "EvidenceArtifact",
    "ArtifactType",
    "ResponseAction",
    "ActionStatus",
    "AuditLog",
    "Report",
    "ReportFormat",
]

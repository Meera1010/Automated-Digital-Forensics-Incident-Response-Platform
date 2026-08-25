import pytest
from datetime import datetime, timezone
import uuid

from backend.extensions import db
from backend.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.models.investigation_record import InvestigationRecord
from backend.models.detection_hit import DetectionHit
from backend.models.detection_rule import DetectionRule, RuleType
from backend.models.raw_event import RawEvent
from backend.models.evidence_artifact import EvidenceArtifact, ArtifactType
from backend.investigation.incident_manager import IncidentManager


def test_create_incident_from_hit(app, db_session):
    with app.app_context():
        # Setup mock data
        rule = DetectionRule(
            rule_id="TEST-001",
            name="Test Rule",
            description="Test Description",
            rule_type=RuleType.PATTERN_MATCH,
            severity_weight=8,
            conditions_yaml="test: logic"
        )
        db.session.add(rule)
        
        event = RawEvent(
            source_tag="test",
            event_type="auth_failure",
            source_ip="192.168.1.50",
            payload_json={"user": "admin"},
            checksum="testhash123",
            received_at=datetime.now(timezone.utc)
        )
        db.session.add(event)
        
        dummy_incident = Incident(
            incident_number="INC-DUMMY",
            title="Dummy",
        )
        db.session.add(dummy_incident)
        db.session.flush()

        evidence = EvidenceArtifact(
            incident_id=dummy_incident.id,
            artifact_type=ArtifactType.LOG_SLICE.value,
            original_filename="test.log",
            sha256_hash="testhash123",
            encrypted_blob=b"test",
            iv=b"testiv123456",
            encryption_key_id="test",
            collected_at=datetime.now(timezone.utc)
        )
        db.session.add(evidence)
        db.session.commit()
        
        hit = DetectionHit(
            rule_id=rule.id,
            raw_event_id=event.id,
            fired_at=datetime.now(timezone.utc),
            match_detail_json={"rule_id_str": "AUTH-001", "severity": 8}
        )
        db.session.add(hit)
        db.session.commit()
        
        # Test Incident Manager
        manager = IncidentManager()
        incident = manager.create_incident_from_hit(hit)
        
        # Verify Incident
        assert incident is not None
        assert incident.incident_number.startswith("INC-")
        assert incident.status == IncidentStatus.NEW.value
        assert incident.severity == IncidentSeverity.P2.value
        assert incident.attack_category == "Credential Access"
        assert incident.opened_at is not None
        
        # Verify Hit Linkage
        updated_hit = db.session.query(DetectionHit).get(hit.id)
        assert updated_hit.correlated_incident_id == incident.id
        
        # Verify Evidence Linkage
        updated_evidence = db.session.query(EvidenceArtifact).get(evidence.id)
        assert updated_evidence.incident_id == incident.id
        
        # Verify Investigation Record
        record = db.session.query(InvestigationRecord).filter_by(incident_id=incident.id).first()
        assert record is not None
        assert record.status == "COMPLETED"

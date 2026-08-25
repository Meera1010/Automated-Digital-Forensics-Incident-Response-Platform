import pytest
from datetime import datetime, timezone
import uuid
import json

from backend.extensions import db
from backend.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.models.raw_event import RawEvent
from backend.models.detection_hit import DetectionHit
from backend.models.evidence_artifact import EvidenceArtifact
from backend.models.investigation_record import InvestigationRecord
from backend.investigation.automated_investigator import AutomatedInvestigator
from backend.vault import vault_manager

@pytest.fixture
def mock_master_key(monkeypatch):
    monkeypatch.setattr("backend.vault.vault_manager._get_master_key", lambda: bytes.fromhex("00" * 32))

def test_automated_investigation(app, db_session, mock_master_key):
    # Setup test data
    incident = Incident(
        incident_number="INC-2026-TEST",
        title="Test Incident",
        status=IncidentStatus.NEW.value,
        severity=IncidentSeverity.P4.value,
        opened_at=datetime.now(timezone.utc)
    )
    db.session.add(incident)
    db.session.commit()
    
    # Event 1
    event1 = RawEvent(
        received_at=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        source_tag="sensor-01",
        event_type="auth_failure",
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        username="admin",
        payload_json={"message": "Failed login"},
        checksum="aaa"
    )
    
    # Event 2
    event2 = RawEvent(
        received_at=datetime(2026, 1, 1, 10, 5, 0, tzinfo=timezone.utc),
        source_tag="sensor-01",
        event_type="auth_failure",
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        username="root",
        payload_json={"message": "Failed login"},
        checksum="bbb"
    )
    db.session.add_all([event1, event2])
    db.session.commit()
    
    # Hits
    from backend.models.detection_rule import DetectionRule, RuleType
    rule = DetectionRule(
        rule_id="TEST-001",
        name="Test Rule",
        description="Test Description",
        rule_type=RuleType.PATTERN_MATCH,
        severity_weight=4,
        conditions_yaml="foo: bar",
        enabled=True
    )
    db_session.add(rule)
    db_session.commit()

    hit1 = DetectionHit(
        rule_id=rule.id,
        raw_event_id=event1.id,
        fired_at=datetime.now(timezone.utc),
        match_detail_json={"rule_id_str": "AUTH-001", "severity": 4},
        correlated_incident_id=incident.id
    )
    hit2 = DetectionHit(
        rule_id=rule.id,
        raw_event_id=event2.id,
        fired_at=datetime.now(timezone.utc),
        match_detail_json={"rule_id_str": "AUTH-002", "severity": 8},
        correlated_incident_id=incident.id
    )
    db.session.add_all([hit1, hit2])
    
    # Evidence
    payload = b"test evidence"
    evidence = vault_manager.store(payload, "log_slice", str(incident.id), "test.log", "sensor-01")
    
    # Create InvestigationRecord
    record = InvestigationRecord(
        incident_id=incident.id,
        findings="Initial findings",
        status="NEW"
    )
    db.session.add(record)
    db.session.commit()
    
    # Run Automated Investigator
    investigator = AutomatedInvestigator()
    investigator.investigate(incident)
    
    # Verify changes
    db.session.refresh(incident)
    assert incident.severity == IncidentSeverity.P2.value
    
    db.session.refresh(record)
    assert record.status == "COMPLETED"
    
    # Check findings
    findings = record.findings
    assert "Triggered Rules: AUTH-001, AUTH-002" in findings
    assert "Computed Severity: P2" in findings
    assert "192.168.1.100" in findings
    assert "admin" in findings
    assert "root" in findings
    assert "VALID" in findings
    assert "Chronological Timeline:" in findings
    
    # Event 1 should be before Event 2 in the timeline
    assert findings.find("admin") < findings.find("root")

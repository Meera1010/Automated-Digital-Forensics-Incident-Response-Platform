import sys
from backend.app import create_app
from backend.extensions import db
from datetime import datetime, timezone
import uuid
from backend.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.models.raw_event import RawEvent
from backend.models.detection_hit import DetectionHit
from backend.models.evidence_artifact import EvidenceArtifact
from backend.models.investigation_record import InvestigationRecord
from backend.investigation.automated_investigator import AutomatedInvestigator
from backend.vault import vault_manager

app = create_app("testing")

# Mock the master key
vault_manager._get_master_key = lambda: bytes.fromhex("00" * 32)

with app.app_context():
    print("Dropping tables")
    db.drop_all()
    print("Creating tables")
    db.create_all()
    print("Tables created")

    incident = Incident(
        incident_number="INC-2026-TEST",
        title="Test Incident",
        status=IncidentStatus.NEW.value,
        severity=IncidentSeverity.P4.value,
        opened_at=datetime.now(timezone.utc)
    )
    db.session.add(incident)
    db.session.commit()
    print("Added incident")
    
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
    
    db.session.add(event1)
    db.session.commit()
    print("Added event")
    
    hit1 = DetectionHit(
        rule_id=uuid.uuid4(),
        raw_event_id=event1.id,
        fired_at=datetime.now(timezone.utc),
        match_detail_json={"rule_id_str": "AUTH-001", "severity": 4},
        correlated_incident_id=incident.id
    )
    db.session.add(hit1)
    db.session.commit()
    print("Added hit")
    
    payload = b"test evidence"
    evidence = vault_manager.store(payload, "log_slice", str(incident.id), "test.log", "sensor-01")
    print("Added evidence")
    
    record = InvestigationRecord(
        incident_id=incident.id,
        findings="Initial findings",
        status="NEW"
    )
    db.session.add(record)
    db.session.commit()
    print("Added record")
    
    print("Running investigator")
    investigator = AutomatedInvestigator()
    investigator.investigate(incident)
    print("Done")

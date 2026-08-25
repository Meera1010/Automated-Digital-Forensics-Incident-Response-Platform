"""
Integration Tests: Synthetic Scenarios
Tests end-to-end incident lifecycle: Input -> Detection -> Investigation -> Classification -> Response -> Audit -> Result
"""
import pytest
from datetime import datetime, timezone, timedelta

from backend.extensions import db
from backend.models.raw_event import RawEvent
from backend.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.models.audit_log import AuditLog
from backend.models.evidence_artifact import EvidenceArtifact
from backend.models.response_action import ResponseAction, ActionStatus
from backend.models.detection_hit import DetectionHit
from backend.models.response_playbook import ResponsePlaybook

from backend.investigation.detection_engine import DetectionEngine
from backend.investigation.incident_manager import IncidentManager
from backend.investigation.automated_investigator import AutomatedInvestigator
from backend.response.engine import execute_response_for_incident
from backend.response.playbook_loader import load_playbooks_from_disk
from backend.reporting.generator import generate_report, ReportFormat


@pytest.fixture
def mock_master_key(monkeypatch):
    monkeypatch.setattr("backend.vault.vault_manager._get_master_key", lambda: bytes.fromhex("00" * 32))


@pytest.fixture
def e2e_setup(app, db_session, mock_master_key):
    """Initializes the environment for E2E tests."""
    with app.app_context():
        # Load playbooks
        load_playbooks_from_disk()
        
        # Engines
        det_engine = DetectionEngine()
        det_engine.sync_rules()
        inv_engine = AutomatedInvestigator()
        inc_manager = IncidentManager()
        
        yield app, db_session, det_engine, inc_manager, inv_engine


def create_event(event_type, source_ip="192.168.1.100", payload=None, time_offset_sec=0):
    evt_time = datetime.now(timezone.utc) + timedelta(seconds=time_offset_sec)
    return RawEvent(
        source_tag="synthetic-sensor",
        event_type=event_type,
        source_ip=source_ip,
        payload_json=payload or {},
        checksum="dummy_checksum",
        received_at=evt_time,
        processed=False
    )


def test_scenario_1_normal_login(e2e_setup):
    """Scenario 1: Normal login activity. No incident created."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    events = [
        create_event("auth_success", payload={"user": "admin"}, time_offset_sec=0),
        create_event("auth_failure", payload={"user": "admin"}, time_offset_sec=1),
        create_event("auth_success", payload={"user": "admin"}, time_offset_sec=2)
    ]
    for e in events:
        session.add(e)
    session.commit()
    
    hits = det_engine.evaluate_events(events)
    assert hits == 0
    assert Incident.query.count() == 0


def test_scenario_2_repeated_failed_logins(e2e_setup):
    """Scenario 2: Repeated failed login activity (Brute Force)."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    # 1. INPUT
    events = [create_event("auth_failure", time_offset_sec=i) for i in range(6)]
    for e in events:
        session.add(e)
    session.commit()
    
    # 2. DETECTION
    hits_count = det_engine.evaluate_events(events)
    assert hits_count > 0
    
    # 2.5 INCIDENT CREATION
    hit = DetectionHit.query.first()
    incident = inc_manager.create_incident_from_hit(hit)
    session.commit()
    assert incident is not None
    
    # 3. INVESTIGATION & CLASSIFICATION
    inv_engine.investigate(incident)
    assert incident.attack_category == "BRUTE_FORCE"
    assert incident.severity is not None
    
    # 4. RESPONSE
    actions = execute_response_for_incident(incident)
    assert len(actions) > 0
    assert actions[0].status == ActionStatus.SUCCESS.value
    
    # 5. AUDIT LOG
    audits = AuditLog.query.filter_by(target_type="Incident").all()
    assert len(audits) > 0


def test_scenario_3_suspicious_process(e2e_setup):
    """Scenario 3: Suspicious process activity (Mimikatz)."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    evt = create_event("process_execution", payload={"process_name": "mimikatz.exe", "command_line": "privilege::debug"})
    session.add(evt)
    session.commit()
    
    hits_count = det_engine.evaluate_events([evt])
    assert hits_count == 1
    
    hit = DetectionHit.query.first()
    incident = inc_manager.create_incident_from_hit(hit)
    session.commit()
    inv_engine.investigate(incident)
    assert incident.severity in [IncidentSeverity.P1.value, IncidentSeverity.P2.value]
    
    actions = execute_response_for_incident(incident)
    assert any(a.action_name == "Isolate Endpoint" for a in actions)


def test_scenario_4_suspicious_network(e2e_setup):
    """Scenario 4: Suspicious network activity (Reverse Shell on port 4444)."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    evt = create_event("network_connection", payload={"dest_port": 4444})
    session.add(evt)
    session.commit()
    
    hits_count = det_engine.evaluate_events([evt])
    assert hits_count == 1
    
    hit = DetectionHit.query.first()
    incident = inc_manager.create_incident_from_hit(hit)
    session.commit()
    assert incident is not None
    inv_engine.investigate(incident)


def test_scenario_5_file_integrity(e2e_setup):
    """Scenario 5: File integrity modification (/etc/shadow)."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    evt = create_event("file_activity", payload={"file_path": "/etc/shadow modified"})
    session.add(evt)
    session.commit()
    
    hits_count = det_engine.evaluate_events([evt])
    assert hits_count == 1
    
    hit = DetectionHit.query.first()
    incident = inc_manager.create_incident_from_hit(hit)
    session.commit()
    inv_engine.investigate(incident)
    assert incident.severity is not None


def test_scenario_6_multiple_simultaneous_alerts(e2e_setup):
    """Scenario 6: Multiple simultaneous alerts (DoS / scanner)."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    events = [create_event("network_connection", time_offset_sec=i % 10) for i in range(105)]
    for e in events:
        session.add(e)
    session.commit()
    
    hits_count = det_engine.evaluate_events(events)
    assert hits_count >= 1  # Multiple hits expected from high-frequency events
    
    hit = DetectionHit.query.first()
    incident = inc_manager.create_incident_from_hit(hit)
    session.commit()
    inv_engine.investigate(incident)
    
    # Ensure it's grouped under one incident, not 100
    assert Incident.query.count() == 1


def test_scenario_7_false_positive(e2e_setup):
    """Scenario 7: False positive scenario (Threshold not met)."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    # 4 auth failures instead of 5
    events = [create_event("auth_failure", time_offset_sec=i) for i in range(4)]
    for e in events:
        session.add(e)
    session.commit()
    
    hits_count = det_engine.evaluate_events(events)
    assert hits_count == 0
    assert Incident.query.count() == 0


def test_scenario_8_automated_containment(e2e_setup):
    """Scenario 8: Automated containment action execution."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    incident = Incident(
        incident_number="INC-CONTAIN-1",
        title="Data Exfiltration",
        status=IncidentStatus.NEW.value,
        severity=IncidentSeverity.P1.value,
        attack_category="data_exfiltration",
        opened_at=datetime.now(timezone.utc)
    )
    session.add(incident)
    session.commit()
    
    actions = execute_response_for_incident(incident)
    assert len(actions) > 0
    assert actions[0].status == ActionStatus.SUCCESS.value
    
    audit_logs = AuditLog.query.filter_by(target_type="incident").all()
    assert any("action" in log.action for log in audit_logs)


def test_scenario_9_evidence_verification(e2e_setup):
    """Scenario 9: Evidence verification failure triggers an alert."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    evt = create_event("integrity_failure", payload={"artifact_id": "1234-abcd"})
    session.add(evt)
    session.commit()
    
    hits_count = det_engine.evaluate_events([evt])
    assert hits_count == 1
    
    hit = DetectionHit.query.first()
    incident = inc_manager.create_incident_from_hit(hit)
    session.commit()
    inv_engine.investigate(incident)
    assert "integrity" in incident.title.lower() or incident.severity == IncidentSeverity.P1.value


def test_scenario_10_report_generation(e2e_setup):
    """Scenario 10: Report generation at the end of the lifecycle."""
    app, session, det_engine, inc_manager, inv_engine = e2e_setup
    
    # Mock user creation so report generator can write audit log
    from backend.models.user import User, UserRole
    user = User(username="system", is_active=True, role=UserRole.ADMIN.value)
    user.set_password("sys")
    session.add(user)
    session.commit()
    
    incident = Incident(
        incident_number="INC-REPORT-1",
        title="Malware Outbreak",
        status=IncidentStatus.RESOLVED.value,
        severity=IncidentSeverity.P2.value,
        attack_category="MALWARE",
        opened_at=datetime.now(timezone.utc),
        summary_text="Found a reverse shell"
    )
    session.add(incident)
    session.commit()
    
    report_record = generate_report(str(incident.id), format_type=ReportFormat.HTML.value)
    assert report_record is not None
    
    artifact = EvidenceArtifact.query.filter_by(incident_id=incident.id).first()
    assert artifact is not None
    assert artifact.original_filename.endswith(".html")
    assert artifact.sha256_hash is not None

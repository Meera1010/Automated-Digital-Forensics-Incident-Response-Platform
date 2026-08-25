import pytest
import os
import json
from unittest.mock import patch
from datetime import datetime, timezone
from backend.reporting.generator import generate_report
from backend.models.incident import Incident
from backend.models.investigation_record import InvestigationRecord
from backend.models.evidence_artifact import EvidenceArtifact
from backend.models.report import Report
from backend.vault import vault_manager

@pytest.fixture
def mock_master_key(monkeypatch):
    monkeypatch.setattr("backend.vault.vault_manager._get_master_key", lambda: bytes.fromhex("00" * 32))

def test_generate_report_html(db_session, mock_master_key):
    """
    Test generating an HTML forensic report for a mocked incident.
    """
    # Create incident
    incident = Incident(
        incident_number="INC-REPORT-TEST",
        title="Test Incident",
        attack_category="MALWARE",
        severity="P1"
    )
    db_session.add(incident)
    db_session.commit()

    # Create investigation
    inv = InvestigationRecord(
        incident_id=incident.id,
        findings="Test Detection\nTest investigation summary\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="COMPLETED"
    )
    db_session.add(inv)
    db_session.commit()

    # Create evidence using vault_manager
    ev = vault_manager.store(
        artifact_bytes=b"test evidence content",
        artifact_type="pcap",
        incident_id=str(incident.id),
        filename="test.pcap",
        source="test_system"
    )

    # Generate Report
    report = generate_report(incident.id, format_type="html")
    
    assert report is not None
    assert report.incident_id == incident.id
    assert report.format == "html"
    assert report.sha256_hash is not None
    
    # Verify file was written
    from backend.reporting.generator import REPORTS_DIR
    file_path = os.path.join(REPORTS_DIR, report.storage_path)
    assert os.path.exists(file_path)
    
    with open(file_path, "r") as f:
        content = f.read()
        assert "INC-REPORT-TEST" in content
        assert "Test Detection" in content
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in content

    # Verify EvidenceArtifact created
    reports_evidence = db_session.query(EvidenceArtifact).filter_by(artifact_type="forensic_report_html").first()
    assert reports_evidence is not None
    assert reports_evidence.incident_id == incident.id

def test_generate_report_json(db_session, mock_master_key):
    # Create incident
    incident = Incident(
        incident_number="INC-REPORT-JSON",
        title="Test Incident JSON",
        attack_category="PHISHING",
        severity="P2"
    )
    db_session.add(incident)
    db_session.commit()

    report = generate_report(incident.id, format_type="json")
    
    from backend.reporting.generator import REPORTS_DIR
    file_path = os.path.join(REPORTS_DIR, report.storage_path)
    assert os.path.exists(file_path)
    
    with open(file_path, "r") as f:
        data = json.load(f)
        assert data["incident"]["incident_number"] == "INC-REPORT-JSON"

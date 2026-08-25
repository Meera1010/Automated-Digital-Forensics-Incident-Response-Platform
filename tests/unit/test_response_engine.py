"""
Unit tests for the Automated Incident Response Module.
"""
import pytest
import yaml
from uuid import uuid4

from sqlalchemy import text
from backend.extensions import db
from backend.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.models.response_playbook import ResponsePlaybook
from backend.models.response_action import ResponseAction, ActionStatus
from backend.models.synthetic_asset import SyntheticAsset, AssetStatus, AssetType
from backend.models.audit_log import AuditLog
from backend.response.engine import execute_response_for_incident


def test_response_engine(app, db_session):
    """
    Test the response engine orchestration and all 5 simulated actions.
    """
    with app.app_context():
        # Create a SyntheticAsset to target
        asset = SyntheticAsset(
            id="ASSET-WS-TEST",
            name="Test Workstation",
            asset_type=AssetType.WORKSTATION,
            criticality=3,
            ip_address="10.0.0.100",
            status=AssetStatus.ACTIVE
        )
        db.session.add(asset)

        # Create an Incident
        incident = Incident(
            incident_number="INC-1234",
            title="Test Ransomware",
            summary_text="Testing automated response",
            severity=IncidentSeverity.P1.value,
            status=IncidentStatus.CONFIRMED.value,
            attack_category="RANSOMWARE"
        )
        db.session.add(incident)

        # Create a Playbook
        actions_list = [
            {"action": "isolate_endpoint", "params": {"ip_address": "10.0.0.100"}},
            {"action": "quarantine_file", "params": {"file_path": "/tmp/malware.exe", "hash": "abcd123"}},
            {"action": "disable_account", "params": {"username": "test_user"}},
            {"action": "block_ip", "params": {"ip_address": "192.168.1.50"}},
            {"action": "contain_incident", "params": {}}
        ]
        
        playbook = ResponsePlaybook(
            name="Ransomware P1 Playbook",
            attack_category="RANSOMWARE",
            severity_tier="P1",
            actions_yaml=yaml.dump(actions_list),
            enabled=True
        )
        db.session.add(playbook)
        db.session.commit()

        # Execute Response
        actions_executed = execute_response_for_incident(incident)

        # Verify 5 actions were executed
        assert len(actions_executed) == 5
        assert all(a.status == ActionStatus.SUCCESS.value for a in actions_executed)
        
        # Refresh models
        db.session.refresh(asset)
        db.session.refresh(incident)

        # 1. Verify endpoint was isolated
        assert asset.status == AssetStatus.QUARANTINED
        
        # 2. Verify incident was marked as contained
        assert incident.status == IncidentStatus.CONTAINED.value
        
        # 3. Verify ResponseAction records are in DB
        actions_in_db = ResponseAction.query.filter_by(incident_id=incident.id).all()
        assert len(actions_in_db) == 5
        action_names = [a.action_name for a in actions_in_db]
        assert "isolate_endpoint" in action_names
        assert "contain_incident" in action_names

        # 4. Verify Audit Logs were created for the actions
        audit_logs = AuditLog.query.filter_by(action="playbook.action_executed").all()
        assert len(audit_logs) == 5

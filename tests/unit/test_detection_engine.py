import pytest
import uuid
from datetime import datetime, timezone, timedelta
from backend.models.raw_event import RawEvent
from backend.models.detection_hit import DetectionHit
from backend.models.detection_rule import DetectionRule
from backend.investigation.detection_engine import DetectionEngine
from backend.extensions import db

def create_event(event_type, source_ip="192.168.1.100", payload_json=None, received_at=None):
    if payload_json is None:
        payload_json = {}
    if received_at is None:
        received_at = datetime.now(timezone.utc)
        
    return RawEvent(
        source_tag="test-sensor",
        event_type=event_type,
        source_ip=source_ip,
        payload_json=payload_json,
        checksum="dummy_checksum",
        received_at=received_at
    )

def test_repeated_failed_login_rule(app):
    with app.app_context():
        engine = DetectionEngine()
        engine.sync_rules()
        
        # Insert 4 previous failures
        now = datetime.now(timezone.utc)
        for i in range(4):
            evt = create_event("auth_failure", received_at=now - timedelta(seconds=i*10))
            db.session.add(evt)
        db.session.commit()
        
        # 5th failure should trigger rule
        evt5 = create_event("auth_failure", received_at=now)
        db.session.add(evt5)
        db.session.commit()
        
        hits = engine.evaluate_events([evt5])
        assert hits == 1
        
        hit = db.session.query(DetectionHit).first()
        assert hit is not None
        assert hit.match_detail_json["rule_id_str"] == "AUTH-001"
        assert hit.match_detail_json["severity"] == 7

def test_suspicious_process_execution_rule(app):
    with app.app_context():
        engine = DetectionEngine()
        engine.sync_rules()
        
        # Mimikatz event
        evt = create_event(
            "process_execution", 
            payload_json={"process_name": "mimikatz.exe", "command_line": "privilege::debug"}
        )
        db.session.add(evt)
        db.session.commit()
        
        hits = engine.evaluate_events([evt])
        assert hits == 1
        
        hit = db.session.query(DetectionHit).order_by(DetectionHit.fired_at.desc()).first()
        assert hit.match_detail_json["rule_id_str"] == "PROC-001"

def test_unexpected_network_activity_rule(app):
    with app.app_context():
        engine = DetectionEngine()
        engine.sync_rules()
        
        # 4444 event
        evt = create_event(
            "network_connection", 
            payload_json={"dest_port": 4444}
        )
        db.session.add(evt)
        db.session.commit()
        
        hits = engine.evaluate_events([evt])
        assert hits == 1
        
        hit = db.session.query(DetectionHit).order_by(DetectionHit.fired_at.desc()).first()
        assert hit.match_detail_json["rule_id_str"] == "NET-001"

def test_evidence_integrity_violation_rule(app):
    with app.app_context():
        engine = DetectionEngine()
        engine.sync_rules()
        
        evt = create_event("integrity_failure")
        db.session.add(evt)
        db.session.commit()
        
        hits = engine.evaluate_events([evt])
        assert hits == 1
        
        hit = db.session.query(DetectionHit).order_by(DetectionHit.fired_at.desc()).first()
        assert hit.match_detail_json["rule_id_str"] == "INT-001"

def test_abnormal_event_frequency_rule(app):
    with app.app_context():
        engine = DetectionEngine()
        engine.sync_rules()
        
        now = datetime.now(timezone.utc)
        events = []
        for i in range(101):
            evt = create_event("any_event", received_at=now - timedelta(seconds=i*0.5))
            db.session.add(evt)
            events.append(evt)
            
        db.session.commit()
        
        # Test just evaluating the last event
        hits = engine.evaluate_events([events[0]])
        assert hits == 1
        
        hit = db.session.query(DetectionHit).order_by(DetectionHit.fired_at.desc()).first()
        assert hit.match_detail_json["rule_id_str"] == "FREQ-001"

def test_suspicious_file_activity_rule(app):
    with app.app_context():
        engine = DetectionEngine()
        engine.sync_rules()
        
        evt = create_event(
            "file_activity", 
            source_ip="10.0.0.1",
            payload_json={"file_path": "/etc/shadow"}
        )
        db.session.add(evt)
        db.session.commit()
        
        hits = engine.evaluate_events([evt])
        assert hits == 1
        
        hit = db.session.query(DetectionHit).order_by(DetectionHit.fired_at.desc()).first()
        assert hit.match_detail_json["rule_id_str"] == "FILE-001"

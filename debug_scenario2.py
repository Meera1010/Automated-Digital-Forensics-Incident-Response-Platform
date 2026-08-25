from backend.app import create_app
from backend.extensions import db
from backend.models.raw_event import RawEvent
from backend.investigation.detection_engine import DetectionEngine
from backend.investigation.automated_investigator import AutomatedInvestigator
from backend.response.engine import execute_response_for_incident
from backend.response.playbook_loader import load_playbooks_from_disk
from datetime import datetime, timezone, timedelta
import traceback
import sys
import threading

def timeout_handler():
    print("Script timed out!")
    import os
    os._exit(1)

timer = threading.Timer(10.0, timeout_handler)
timer.start()

app = create_app('testing')
with app.app_context():
    try:
        db.create_all()
        print("db created")
        load_playbooks_from_disk()
        print("playbooks loaded")
        
        det_engine = DetectionEngine()
        det_engine.sync_rules()
        print("rules synced")
        
        inv_engine = AutomatedInvestigator()
        
        events = []
        for i in range(6):
            evt_time = datetime.now(timezone.utc) + timedelta(seconds=i)
            e = RawEvent(
                source_tag="synthetic-sensor",
                event_type="auth_failure",
                source_ip="192.168.1.100",
                payload_json={"user": "admin"},
                checksum="dummy_checksum",
                received_at=evt_time,
                processed=False
            )
            events.append(e)
            db.session.add(e)
            
        db.session.commit()
        print("events committed")
        
        print("Starting evaluate_events...")
        hits = det_engine.evaluate_events(events)
        print("Hits:", hits)
        
        from backend.models.incident import Incident
        incident = Incident.query.first()
        print("Incident:", incident)
        
        print("Starting investigate...")
        inv_engine.investigate(incident)
        print("Investigate done")
        
        print("Starting response...")
        actions = execute_response_for_incident(incident)
        print("Actions:", len(actions))
    except Exception as e:
        traceback.print_exc()
    finally:
        timer.cancel()

"""
Unit tests for Evidence Collection Module.
"""
import json
import uuid
import pytest
from backend.investigation.collector import EvidenceCollector, SyntheticEventSource
from backend.models.incident import Incident
from backend.extensions import db
from backend.models.evidence_artifact import EvidenceArtifact
from backend.vault import vault_manager

def test_synthetic_event_collection(app):
    with app.app_context():
        # Setup incident
        incident = Incident(
            incident_number=f"INC-{uuid.uuid4().hex[:8]}",
            title="Test Incident for Collection",
        )
        db.session.add(incident)
        db.session.commit()
        
        # Test SyntheticEventSource
        source = SyntheticEventSource(event_count=5, suspicious_freq=0.5)
        collector = EvidenceCollector(sources=[source])
        
        artifacts = collector.collect_all(str(incident.id))
        
        assert len(artifacts) == 1
        artifact = artifacts[0]
        
        # Check database persistence
        db_artifact = db.session.get(EvidenceArtifact, artifact.id)
        assert db_artifact is not None
        
        # Check source and metadata
        assert db_artifact.source == "SyntheticEventSource"
        assert db_artifact.artifact_metadata["event_count"] == 5
        assert db_artifact.artifact_metadata["is_synthetic"] is True
        
        # Check chain of custody
        assert len(db_artifact.chain_of_custody) == 1
        assert db_artifact.chain_of_custody[0]["action"] == "collected"
        assert db_artifact.chain_of_custody[0]["actor"] == "system"
        
        # Verify JSON content
        retrieved_bytes = vault_manager.retrieve(str(artifact.id))
        events = json.loads(retrieved_bytes.decode('utf-8'))
        assert len(events) == 5
        
        # Verify event content structure
        for event in events:
            assert event["payload_json"]["is_synthetic"] is True
            assert event["source_tag"].startswith("SYN-GEN")

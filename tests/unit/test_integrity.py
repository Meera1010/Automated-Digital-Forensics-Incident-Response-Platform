"""
Unit tests for Evidence Integrity Verification Module.
"""
import uuid
import pytest
from backend.models.incident import Incident
from backend.extensions import db
from backend.models.evidence_artifact import EvidenceArtifact
from backend.vault import vault_manager
from backend.utils.error_handlers import EvidenceTamperedException, ResourceNotFoundError

def test_unmodified_evidence_verification(app, db_session):
    with app.app_context():
        # Store evidence
        incident = Incident(
            incident_number=f"INC-{uuid.uuid4().hex[:8]}",
            title="Test Incident for Verification",
        )
        db.session.add(incident)
        db.session.commit()

        data = b"Some top secret evidence data for integrity check."
        artifact = vault_manager.store(
            artifact_bytes=data,
            artifact_type="memory_dump",
            incident_id=str(incident.id),
            source="test_source"
        )
        
        # Verify unmodified evidence
        is_valid = vault_manager.verify_evidence(str(artifact.id))
        assert is_valid is True

def test_modified_evidence_verification(app, db_session):
    with app.app_context():
        # Store evidence
        incident = Incident(
            incident_number=f"INC-{uuid.uuid4().hex[:8]}",
            title="Test Incident for Verification Modification",
        )
        db.session.add(incident)
        db.session.commit()

        data = b"Some top secret evidence data for integrity check."
        artifact = vault_manager.store(
            artifact_bytes=data,
            artifact_type="memory_dump",
            incident_id=str(incident.id),
            source="test_source"
        )
        
        # Tamper with the evidence blob
        db_artifact = db.session.get(EvidenceArtifact, artifact.id)
        # Flip a bit in the encrypted blob
        mutable_blob = bytearray(db_artifact.encrypted_blob)
        mutable_blob[0] = mutable_blob[0] ^ 0xFF
        db_artifact.encrypted_blob = bytes(mutable_blob)
        db.session.commit()
        
        # Verify modified evidence throws EvidenceTamperedException
        with pytest.raises(EvidenceTamperedException):
            vault_manager.verify_evidence(str(artifact.id))

def test_missing_evidence_verification(app, db_session):
    with app.app_context():
        fake_id = str(uuid.uuid4())
        
        # Verify missing evidence throws ResourceNotFoundError
        with pytest.raises(ResourceNotFoundError):
            vault_manager.verify_evidence(fake_id)

def test_invalid_evidence_verification(app, db_session):
    with app.app_context():
        invalid_id = "not-a-valid-uuid-string"
        
        # Verify invalid id throws ValueError
        with pytest.raises(ValueError):
            vault_manager.verify_evidence(invalid_id)

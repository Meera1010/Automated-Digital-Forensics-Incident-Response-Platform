"""
ADFIR Platform — EvidenceArtifact Model
=========================================
Stores an encrypted evidence artifact collected during the Investigation
phase.  Each artifact is:

  1. SHA-256 hashed before encryption (integrity baseline).
  2. Encrypted with AES-256-GCM (authenticated encryption).
  3. Stored with its IV and a reference to the key used.

Reading an artifact re-verifies the SHA-256 hash; a mismatch raises an
exception and creates an audit entry flagging potential tampering.
"""

import enum
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, LargeBinary
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import UUIDPrimaryKeyMixin


class ArtifactType(enum.Enum):
    LOG_SLICE = "log_slice"
    MEMORY_SNAPSHOT = "memory_snapshot"
    TIMELINE = "timeline"
    NETWORK_CAPTURE = "network_capture"
    CONFIGURATION = "configuration"
    INVESTIGATION_SUMMARY = "investigation_summary"
    REPORT = "report"


class EvidenceArtifact(UUIDPrimaryKeyMixin, db.Model):
    """
    An encrypted, hash-verified evidence artifact tied to an incident.
    """

    __tablename__ = "evidence_artifacts"

    # The incident this evidence belongs to.
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # When the Investigation Engine collected this artifact.
    collected_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Category of the artifact content.
    artifact_type = Column(String(64), nullable=False)

    # Original filename for display purposes.
    original_filename = Column(String(256), nullable=True)

    # SHA-256 hex digest of the UNENCRYPTED artifact bytes.
    # Computed before encryption; re-verified on every read.
    sha256_hash = Column(String(64), nullable=False)

    # AES-256-GCM ciphertext (includes the GCM authentication tag).
    encrypted_blob = Column(LargeBinary, nullable=False)

    # 96-bit (12-byte) GCM nonce/IV — unique per artifact.
    iv = Column(LargeBinary(12), nullable=False)

    # Reference to the key used for encryption (for key rotation support).
    encryption_key_id = Column(String(64), nullable=False)

    # Size (bytes) of the unencrypted artifact — stored for display.
    size_bytes = Column(Integer, nullable=False, default=0)

    # Chain-of-custody log: [{action, actor, timestamp}] — append-only in code.
    chain_of_custody = Column(JSONB, nullable=False, default=list)

    # Relationship
    incident = relationship("Incident", back_populates="evidence_artifacts")

    def __repr__(self) -> str:
        return (
            f"<EvidenceArtifact {self.id!s:.8} "
            f"type={self.artifact_type!r} "
            f"incident={str(self.incident_id):.8}>"
        )

    def to_dict(self, include_blob: bool = False) -> dict:
        data = {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "collected_at": self.collected_at.isoformat(),
            "artifact_type": self.artifact_type,
            "original_filename": self.original_filename,
            "sha256_hash": self.sha256_hash,
            "encryption_key_id": self.encryption_key_id,
            "size_bytes": self.size_bytes,
            "chain_of_custody": self.chain_of_custody or [],
        }
        # The encrypted blob is never included in API list responses.
        # It is only decrypted during an explicit download request.
        if include_blob:
            data["encrypted_blob"] = (
                self.encrypted_blob.hex() if self.encrypted_blob else None
            )
        return data

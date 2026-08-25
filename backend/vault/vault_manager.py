"""
ADFIR Platform — Evidence Vault Manager
==========================================
High-level API for storing and retrieving encrypted evidence artifacts.

store(artifact_bytes, artifact_type, incident_id) -> EvidenceArtifact
retrieve(artifact_id) -> bytes  (decrypted, hash-verified)

TODO (Phase 1): Implement store() and retrieve() using hasher + encryptor.
"""

import logging
import os
import uuid
from flask import current_app

from backend.audit.writer import write_audit
from backend.extensions import db
from backend.models.evidence_artifact import EvidenceArtifact
from backend.utils.error_handlers import EvidenceTamperedException, ResourceNotFoundError
from backend.vault.encryptor import decrypt, encrypt
from backend.vault.hasher import compute_hash, verify_hash

logger = logging.getLogger(__name__)


def _get_master_key() -> bytes:
    """Retrieve and decode the 32-byte master AES key from app config."""
    key_hex = current_app.config.get("AES_MASTER_KEY", "00" * 32)
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 32:
        raise ValueError("AES_MASTER_KEY must be a 64-character hex string (32 bytes).")
    return key_bytes


def store(
    artifact_bytes: bytes,
    artifact_type: str,
    incident_id: str | None = None,
    filename: str | None = None,
) -> EvidenceArtifact:
    """
    Hash, encrypt with AES-256-GCM, and persist an evidence artifact to disk + DB.

    Args:
        artifact_bytes: Raw bytes of the artifact to store.
        artifact_type: Type identifier (e.g. 'memory_dump', 'pcap', 'log_export').
        incident_id: Associated incident UUID string (optional).
        filename: Original file name (optional).

    Returns:
        The created EvidenceArtifact model instance.
    """
    master_key = _get_master_key()

    # 1. Compute SHA-256 digest of original plaintext bytes
    sha256 = compute_hash(artifact_bytes)

    # 2. Encrypt plaintext using AES-256-GCM
    ciphertext, iv = encrypt(artifact_bytes, master_key)

    # 3. Determine storage directory and file path
    vault_dir = current_app.config.get("EVIDENCE_VAULT_PATH", "data/evidence")
    os.makedirs(vault_dir, exist_ok=True)

    artifact_uuid = uuid.uuid4()
    file_name = filename or f"{artifact_type}_{artifact_uuid.hex[:8]}.bin"
    file_path = os.path.join(vault_dir, f"{artifact_uuid.hex}.bin")

    # 4. Write encrypted ciphertext to disk
    with open(file_path, "wb") as f:
        f.write(ciphertext)

    # 5. Create database record
    artifact = EvidenceArtifact(
        id=artifact_uuid,
        incident_id=uuid.UUID(incident_id) if incident_id else None,
        artifact_type=artifact_type,
        file_name=file_name,
        file_path=file_path,
        file_size_bytes=len(artifact_bytes),
        sha256_hash=sha256,
        encryption_iv=iv.hex(),
        storage_status="STORED",
    )

    db.session.add(artifact)
    db.session.commit()

    # 6. Audit trail log
    write_audit(
        module="vault.vault_manager",
        action="evidence.stored",
        target_type="evidence_artifact",
        target_id=str(artifact.id),
        detail={
            "artifact_type": artifact_type,
            "file_size_bytes": len(artifact_bytes),
            "sha256_hash": sha256,
            "incident_id": incident_id,
        },
    )

    logger.info("Stored evidence artifact %s (SHA-256: %s...)", artifact.id, sha256[:12])
    return artifact


def retrieve(artifact_id: str) -> bytes:
    """
    Fetch, decrypt, and verify SHA-256 integrity of an evidence artifact.

    Args:
        artifact_id: UUID string of the evidence artifact.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        ResourceNotFoundError: If artifact record or file is missing.
        EvidenceTamperedException: If computed SHA-256 hash does not match stored hash.
    """
    artifact = EvidenceArtifact.query.get(uuid.UUID(artifact_id))
    if not artifact:
        raise ResourceNotFoundError(f"Evidence artifact {artifact_id} not found.")

    if not os.path.exists(artifact.file_path):
        raise ResourceNotFoundError(f"Artifact file on disk missing: {artifact.file_path}")

    # 1. Read ciphertext from disk
    with open(artifact.file_path, "rb") as f:
        ciphertext = f.read()

    master_key = _get_master_key()
    iv_bytes = bytes.fromhex(artifact.encryption_iv)

    # 2. Decrypt ciphertext using AES-256-GCM
    plaintext = decrypt(ciphertext, master_key, iv_bytes)

    # 3. Verify SHA-256 integrity
    if not verify_hash(plaintext, artifact.sha256_hash):
        logger.error("TAMPERING DETECTED for artifact %s!", artifact_id)
        write_audit(
            module="vault.vault_manager",
            action="evidence.integrity_failure",
            target_type="evidence_artifact",
            target_id=artifact_id,
            detail={"expected_hash": artifact.sha256_hash},
        )
        raise EvidenceTamperedException(
            f"Integrity check failed for artifact {artifact_id}! "
            "Data may have been altered or corrupted."
        )

    # 4. Audit trail log
    write_audit(
        module="vault.vault_manager",
        action="evidence.retrieved",
        target_type="evidence_artifact",
        target_id=artifact_id,
        detail={"sha256_hash": artifact.sha256_hash},
    )

    return plaintext



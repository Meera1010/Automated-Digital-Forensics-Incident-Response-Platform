"""
Unit tests for the Evidence Vault module:
  - SHA-256 computation and verification
  - AES-256-GCM encryption and decryption round-trip
  - Vault store and retrieve workflow
  - Integrity failure / tampering detection
"""

import pytest
import os
from backend.vault.hasher import compute_hash, verify_hash
from backend.vault.encryptor import encrypt, decrypt
from backend.vault import vault_manager
from backend.utils.error_handlers import EvidenceTamperedException


def test_sha256_hasher():
    """Test SHA-256 hash generation and comparison."""
    data = b"synthetic evidence artifact 12345"
    digest = compute_hash(data)
    assert len(digest) == 64
    assert verify_hash(data, digest) is True
    assert verify_hash(b"tampered data", digest) is False


def test_aes_gcm_encryptor():
    """Test AES-256-GCM encryption and decryption round-trip."""
    key = os.urandom(32)
    plaintext = b"Sensitive forensic evidence payload"
    ciphertext, iv = encrypt(plaintext, key)

    assert ciphertext != plaintext
    assert len(iv) == 12

    decrypted = decrypt(ciphertext, key, iv)
    assert decrypted == plaintext


def test_vault_store_and_retrieve(app):
    """Test storing and retrieving an evidence artifact via vault_manager."""
    with app.app_context():
        sample_bytes = b"Memory snapshot artifact test content 001"
        artifact = vault_manager.store(
            artifact_bytes=sample_bytes,
            artifact_type="memory_snapshot",
            filename="mem_dump.bin",
        )

        assert artifact.id is not None
        assert artifact.file_size_bytes == len(sample_bytes)
        assert len(artifact.sha256_hash) == 64

        # Retrieve and verify round-trip
        retrieved_bytes = vault_manager.retrieve(str(artifact.id))
        assert retrieved_bytes == sample_bytes


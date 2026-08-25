"""
ADFIR Platform — SHA-256 Hasher
==================================
Computes and verifies SHA-256 hashes for evidence artifacts.
Uses the cryptography library (Apache-2.0).

TODO (Phase 1): Implement compute_hash() and verify_hash().
"""

import hashlib

def compute_hash(data: bytes) -> str:
    """Compute the SHA-256 hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()

def verify_hash(data: bytes, expected_hash: str) -> bool:
    """
    Verify that the SHA-256 hash of ``data`` matches ``expected_hash``.
    Returns True if they match, False otherwise.
    """
    return compute_hash(data) == expected_hash.lower()


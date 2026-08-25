"""
ADFIR Platform — AES-256-GCM Encryptor
=========================================
Encrypts and decrypts evidence artifact bytes using AES-256-GCM.
Authenticated encryption: any ciphertext tampering causes decryption to fail.

Uses the cryptography library (Apache-2.0).

TODO (Phase 1):
  - Implement encrypt(plaintext, key) -> (ciphertext, iv).
  - Implement decrypt(ciphertext, key, iv) -> plaintext.
  - Key derivation: HKDF from AES_MASTER_KEY + artifact_id.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from typing import Tuple


def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:

    """
    Encrypt ``plaintext`` with AES-256-GCM using a fresh random 96-bit nonce.

    Args:
        plaintext: Raw bytes to encrypt.
        key: 32-byte AES key.

    Returns:
        (ciphertext_with_tag, iv) — the 12-byte nonce used.
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return ciphertext, iv

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ``ciphertext`` using ``key`` and ``iv``.
    Raises cryptography.exceptions.InvalidTag if authentication fails.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)


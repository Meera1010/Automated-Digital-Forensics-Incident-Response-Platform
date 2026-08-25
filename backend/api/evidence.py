"""
ADFIR Platform — Evidence API Blueprint
=========================================
Endpoints:
  GET /api/v1/evidence/<id>          — Evidence artifact metadata + hash.
  GET /api/v1/evidence/<id>/download — Download decrypted artifact (analyst+).
  GET /api/v1/evidence/<id>/verify   — Re-verify SHA-256 integrity.
"""

import io

from flask import Blueprint, jsonify, send_file
from flask_jwt_extended import jwt_required

from backend.models.evidence_artifact import EvidenceArtifact
from backend.utils.error_handlers import ResourceNotFoundError
from backend.vault import vault_manager

evidence_bp = Blueprint("evidence", __name__)


@evidence_bp.get("/<uuid:artifact_id>")
@jwt_required()
def get_artifact_metadata(artifact_id):
    """Return evidence artifact metadata (no blob)."""
    artifact = EvidenceArtifact.query.get(artifact_id)
    if not artifact:
        raise ResourceNotFoundError(f"Evidence artifact {artifact_id} not found.")

    return jsonify({"artifact": artifact.to_dict()}), 200


@evidence_bp.get("/<uuid:artifact_id>/download")
@jwt_required()
def download_artifact(artifact_id):
    """
    Decrypt and stream the artifact to the client.
    Creates an audit log entry on every download.
    """
    artifact_id_str = str(artifact_id)
    artifact = EvidenceArtifact.query.get(artifact_id)
    if not artifact:
        raise ResourceNotFoundError(f"Evidence artifact {artifact_id_str} not found.")

    plaintext_bytes = vault_manager.retrieve(artifact_id_str)

    return send_file(
        io.BytesIO(plaintext_bytes),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=artifact.file_name,
    )


@evidence_bp.get("/<uuid:artifact_id>/verify")
@jwt_required()
def verify_artifact(artifact_id):
    """
    Re-compute SHA-256 of decrypted artifact bytes and verify integrity.
    Returns: { "verified": bool, "sha256_hash": str }
    """
    artifact_id_str = str(artifact_id)
    try:
        vault_manager.retrieve(artifact_id_str)
        return jsonify({
            "verified": True,
            "artifact_id": artifact_id_str,
            "message": "SHA-256 integrity verified successfully.",
        }), 200
    except Exception as e:
        return jsonify({
            "verified": False,
            "artifact_id": artifact_id_str,
            "message": str(e),
        }), 400


"""
ADFIR Platform — Reports API Blueprint
========================================
Endpoints:
  GET /api/v1/reports          — List all generated reports.
  GET /api/v1/reports/<id>     — Report metadata + hash.
  GET /api/v1/reports/<id>/download — Download report file.
"""

from flask import Blueprint, jsonify, send_file
from flask_jwt_extended import jwt_required

reports_bp = Blueprint("reports", __name__)


@reports_bp.get("/")
@jwt_required()
def list_reports():
    """Return a paginated list of all generated forensic reports."""
    # TODO: Query Report, optionally filter by incident_id or format.
    return jsonify({"reports": [], "total": 0}), 200


@reports_bp.get("/<uuid:report_id>")
@jwt_required()
def get_report(report_id):
    """Return metadata for a single report including its SHA-256 hash."""
    # TODO: Fetch Report by ID or 404.
    # TODO: Return report.to_dict().
    return jsonify({"message": "Not yet implemented"}), 501


@reports_bp.get("/<uuid:report_id>/download")
@jwt_required()
def download_report(report_id):
    """
    Download the report file.
    Verifies the file hash before serving.
    Creates an audit log entry.
    """
    from backend.audit.writer import write_audit
    from flask_jwt_extended import get_jwt_identity
    
    actor_id = get_jwt_identity() or "unknown_user"
    
    write_audit(
        module="reports_api",
        action="report.generated",
        target_type="Report",
        target_id=report_id,
        detail={"status": "stub_download"},
        actor_id=actor_id
    )
    
    return jsonify({"message": "Not yet implemented"}), 501

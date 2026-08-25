"""
ADFIR Platform — Audit Log API Blueprint
==========================================
Endpoints:
  GET /api/v1/audit         — Paginated audit log (newest first).
  GET /api/v1/audit/verify  — Verify the entire audit chain integrity.
"""

import json

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from backend.audit.writer import SENTINEL_CHECKSUM, compute_row_checksum
from backend.models.audit_log import AuditLog

audit_bp = Blueprint("audit", __name__)



@audit_bp.get("/")
@jwt_required()
def list_audit_entries():
    """
    Return a paginated audit log.
    Query params: module, action, actor_id, target_id, page, per_page
    Newest entries first.
    """
    module = request.args.get("module")
    action = request.args.get("action")
    actor_id = request.args.get("actor_id")
    target_id = request.args.get("target_id")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    query = AuditLog.query

    if module:
        query = query.filter_by(module=module)
    if action:
        query = query.filter_by(action=action)
    if actor_id:
        query = query.filter_by(actor_id=actor_id)
    if target_id:
        query = query.filter_by(target_id=target_id)

    pagination = query.order_by(AuditLog.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "audit_entries": [entry.to_dict() for entry in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": pagination.per_page,
    }), 200


@audit_bp.get("/verify")
@jwt_required()
def verify_audit_chain():
    """
    Walk the entire audit log in sequential (id) order and verify
    that each row's checksum matches its recomputed SHA-256 value.

    Returns:
      { "valid": bool, "total_rows": int, "first_broken_id": int|null }
    """
    rows = AuditLog.query.order_by(AuditLog.id.asc()).all()

    if not rows:
        return jsonify({
            "valid": True,
            "total_rows": 0,
            "first_broken_id": None,
            "message": "Audit chain is empty.",
        }), 200

    expected_prev = SENTINEL_CHECKSUM
    first_broken_id = None

    for row in rows:
        if row.prev_checksum != expected_prev:
            first_broken_id = row.id
            break

        detail_str = json.dumps(row.detail_json or {}, sort_keys=True)
        recomputed = compute_row_checksum(
            prev_checksum=row.prev_checksum,
            logged_at_iso=row.logged_at.isoformat(),
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            module=row.module,
            action=row.action,
            target_type=row.target_type,
            target_id_str=str(row.target_id) if row.target_id else None,
            detail_str=detail_str,
        )

        if recomputed != row.row_checksum:
            first_broken_id = row.id
            break

        expected_prev = row.row_checksum

    is_valid = first_broken_id is None

    return jsonify({
        "valid": is_valid,
        "total_rows": len(rows),
        "first_broken_id": first_broken_id,
    }), 200


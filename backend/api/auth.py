"""
ADFIR Platform — Authentication API Blueprint
=============================================
Endpoints:
  POST /api/v1/auth/login   — Verify credentials, issue JWT.
  POST /api/v1/auth/logout  — Acknowledge logout (client discards token).
  GET  /api/v1/auth/me      — Return current user info from JWT claims.

TODO (Phase 1):
  - Implement login with bcrypt password verification.
  - Embed role claim in JWT payload.
  - Write audit log entry on every successful and failed login.
"""

from uuid import UUID

from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required

from backend.audit.writer import write_audit
from backend.extensions import db
from backend.models.user import User, UserRole
from backend.utils.datetime_utils import utc_now
from backend.utils.error_handlers import ResourceNotFoundError

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/login")
def login():
    """
    Authenticate a user and return a signed JWT access token.
    Request body: { "username": str, "password": str }
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": {"code": 400, "message": "Username and password are required."}
        }), 400

    user = User.query.filter_by(username=username).first()

    # Fail if user not found, inactive, or password check fails
    if not user or not user.is_active or not user.check_password(password):
        write_audit(
            module="auth",
            action="auth.login_failed",
            actor_type="user",
            actor_id=username or "anonymous",
            detail={"reason": "Invalid credentials or inactive account"},
        )
        return jsonify({
            "error": {"code": 401, "message": "Invalid username or password."}
        }), 401

    # Update last login timestamp
    user.last_login_at = utc_now()
    db.session.commit()

    # Issue JWT access token
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            "role": user.role.value,
            "username": user.username,
        },
    )

    write_audit(
        module="auth",
        action="auth.login_success",
        actor_type="user",
        actor_id=str(user.id),
        detail={"username": user.username, "role": user.role.value},
    )

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "user": user.to_dict(),
    }), 200


@auth_bp.post("/logout")
@jwt_required()
def logout():
    """
    Acknowledge a logout request.
    Client discards token from storage.
    """
    user_id = get_jwt_identity()
    write_audit(
        module="auth",
        action="auth.logout",
        actor_type="user",
        actor_id=str(user_id),
    )
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.get("/me")
@jwt_required()
def me():
    """Return the authenticated user's profile information."""
    user_id = get_jwt_identity()
    try:
        user = User.query.get(UUID(user_id))
    except (ValueError, TypeError):
        user = None

    if not user or not user.is_active:
        raise ResourceNotFoundError("User account not found or inactive.")

    return jsonify(user.to_dict()), 200


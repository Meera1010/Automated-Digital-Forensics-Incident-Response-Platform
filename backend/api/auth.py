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

import re
from uuid import UUID

from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, jwt_required
from marshmallow import Schema, fields, validate, ValidationError

from backend.audit.writer import write_audit
from backend.extensions import db, token_blocklist
from backend.models.user import User, UserRole
from backend.utils.datetime_utils import utc_now
from backend.utils.decorators import roles_required
from backend.utils.error_handlers import ResourceNotFoundError

auth_bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# Input Validation Schemas (Marshmallow)
# ---------------------------------------------------------------------------

class UserRegisterSchema(Schema):
    """Input validation for user registration."""
    username = fields.String(
        required=True,
        validate=[
            validate.Length(min=3, max=32, error="Username must be between 3 and 32 characters."),
            validate.Regexp(r"^[a-zA-Z0-9_\-]+$", error="Username can only contain letters, numbers, underscores, and hyphens."),
        ],
    )
    password = fields.String(
        required=True,
        validate=[
            validate.Length(min=8, max=128, error="Password must be at least 8 characters long."),
        ],
    )
    role = fields.String(
        required=False,
        load_default="viewer",
        validate=validate.OneOf(["admin", "analyst", "viewer", "supervisor", "readonly"]),
    )


class UserLoginSchema(Schema):
    """Input validation for user login."""
    username = fields.String(required=True, validate=validate.Length(min=1))
    password = fields.String(required=True, validate=validate.Length(min=1))


register_schema = UserRegisterSchema()
login_schema = UserLoginSchema()


def validate_password_complexity(password: str) -> None:
    """Ensure password meets baseline complexity requirements (letter + digit)."""
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one letter and one number.")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@auth_bp.post("/register")
def register():
    """
    Register a new user account.
    Request body: { "username": str, "password": str, "role": "admin"|"analyst"|"viewer" }
    """
    json_data = request.get_json(silent=True) or {}

    try:
        data = register_schema.load(json_data)
        validate_password_complexity(data["password"])
    except ValidationError as err:
        return jsonify({"error": {"code": 400, "message": "Validation error", "details": err.messages}}), 400

    username = data["username"].strip()
    password = data["password"]
    role_str = data.get("role", "viewer").lower()

    # Map role string to UserRole Enum
    role_map = {
        "admin": UserRole.ADMIN,
        "supervisor": UserRole.ADMIN,
        "analyst": UserRole.ANALYST,
        "viewer": UserRole.VIEWER,
        "readonly": UserRole.VIEWER,
    }
    target_role = role_map.get(role_str, UserRole.VIEWER)

    # Check if username already exists
    existing = User.query.filter_by(username=username).first()
    if existing:
        write_audit(
            module="auth",
            action="auth.register_failed",
            actor_type="user",
            actor_id=username,
            detail={"reason": "Username already taken"},
        )
        return jsonify({
            "error": {"code": 409, "message": f"Username '{username}' is already registered."}
        }), 409

    # Create new user and hash password securely
    user = User(
        username=username,
        role=target_role,
        is_active=True,
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    write_audit(
        module="auth",
        action="auth.registered",
        actor_type="user",
        actor_id=str(user.id),
        detail={"username": user.username, "role": user.role.value},
    )

    return jsonify({
        "message": f"User '{username}' registered successfully.",
        "user": user.to_dict(),
    }), 201


@auth_bp.post("/login")
def login():
    """
    Authenticate credentials and issue a signed JWT access token.
    Request body: { "username": str, "password": str }
    """
    json_data = request.get_json(silent=True) or {}

    try:
        data = login_schema.load(json_data)
    except ValidationError as err:
        return jsonify({"error": {"code": 400, "message": "Validation error", "details": err.messages}}), 400

    username = data["username"].strip()
    password = data["password"]

    user = User.query.filter_by(username=username).first()

    # Fail securely if user not found, inactive, or password invalid
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

    # Issue JWT access token with role and username claims
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
    Revoke current JWT access token by adding its JTI to the token blocklist.
    """
    user_id = get_jwt_identity()
    jwt_payload = get_jwt()
    jti = jwt_payload.get("jti")

    if jti:
        token_blocklist.add(jti)

    write_audit(
        module="auth",
        action="auth.logout",
        actor_type="user",
        actor_id=str(user_id),
        detail={"jti": jti},
    )
    return jsonify({"message": "Logged out successfully and token revoked."}), 200


@auth_bp.get("/me")
@jwt_required()
def me():
    """Return profile information for the authenticated user."""
    user_id = get_jwt_identity()
    try:
        user = User.query.get(UUID(user_id))
    except (ValueError, TypeError):
        user = None

    if not user or not user.is_active:
        raise ResourceNotFoundError("User account not found or inactive.")

    return jsonify(user.to_dict()), 200


@auth_bp.get("/users")
@roles_required("admin")
def list_users():
    """
    Return list of all registered user accounts (Admin only).
    """
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({
        "users": [user.to_dict() for user in users],
        "total": len(users),
    }), 200



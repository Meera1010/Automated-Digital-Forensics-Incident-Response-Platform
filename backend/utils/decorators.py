"""
ADFIR Platform — Role-Based Access Control (RBAC) Decorators
=============================================================
Provides the `@roles_required` decorator to enforce endpoint authorization
based on user roles (`admin`, `analyst`, `viewer`).

Role Hierarchy:
  - admin / supervisor : Full system privileges (all endpoints).
  - analyst            : Incident investigation, evidence download, action execution.
  - viewer / readonly  : Read-only access to dashboard, incidents, and audit logs.
"""

import functools
import logging
from typing import List, Union
from uuid import UUID

from flask import jsonify
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request

from backend.audit.writer import write_audit
from backend.models.user import User, UserRole

logger = logging.getLogger(__name__)

# Normalize role equivalences
ROLE_ALIASES = {
    "supervisor": "admin",
    "readonly": "viewer",
    "admin": "admin",
    "analyst": "analyst",
    "viewer": "viewer",
}

# Hierarchy mapping: each role inherits access from lower roles
ROLE_HIERARCHY = {
    "admin": {"admin", "analyst", "viewer"},
    "analyst": {"analyst", "viewer"},
    "viewer": {"viewer"},
}


def roles_required(*allowed_roles: str):
    """
    Decorator to enforce Role-Based Access Control on Flask API routes.

    Usage:
        @app.route("/api/v1/rules", methods=["POST"])
        @roles_required("admin")
        def create_rule():
            ...

    Args:
        *allowed_roles: Role strings required to access the endpoint ('admin', 'analyst', 'viewer').
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # 1. Ensure a valid JWT token is present in the request
            verify_jwt_in_request()

            jwt_claims = get_jwt()
            user_id = get_jwt_identity()

            user_role_raw = jwt_claims.get("role", "viewer")
            normalized_user_role = ROLE_ALIASES.get(str(user_role_raw).lower(), "viewer")

            normalized_allowed = {ROLE_ALIASES.get(r.lower(), r.lower()) for r in allowed_roles}

            # 2. Check if user's role satisfies any allowed role in the hierarchy
            user_capabilities = ROLE_HIERARCHY.get(normalized_user_role, set())
            has_permission = bool(user_capabilities.intersection(normalized_allowed))

            if not has_permission:
                logger.warning(
                    "RBAC Access Denied: User %s (role: %s) requested endpoint requiring %s",
                    user_id, normalized_user_role, allowed_roles
                )

                # Log unauthorized access attempt in audit trail
                write_audit(
                    module="rbac",
                    action="auth.access_denied",
                    actor_type="user",
                    actor_id=str(user_id),
                    detail={
                        "user_role": normalized_user_role,
                        "required_roles": list(allowed_roles),
                    },
                )

                return jsonify({
                    "error": {
                        "code": 403,
                        "message": f"Permission denied. Required role(s): {', '.join(allowed_roles)}.",
                    }
                }), 403

            return fn(*args, **kwargs)

        return wrapper

    return decorator

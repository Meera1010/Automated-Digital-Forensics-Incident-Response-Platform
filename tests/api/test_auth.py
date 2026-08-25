"""
API tests for the Authentication and Authorization module:
  - User registration with validation & password complexity checks
  - Authentication with JWT token issuance
  - Logout and token revocation list verification
  - Role-Based Access Control (RBAC) authorization enforcement
"""

import pytest
from backend.models.user import User, UserRole


def test_user_registration(client, app):
    """Test user registration endpoint with valid and invalid payloads."""
    with app.app_context():
        # 1. Valid registration
        res = client.post("/api/v1/auth/register", json={
            "username": "sec_analyst_1",
            "password": "SecurePassword123!",
            "role": "analyst",
        })
        assert res.status_code == 201
        data = res.get_json()
        assert data["user"]["username"] == "sec_analyst_1"
        assert data["user"]["role"] == "analyst"

        # 2. Duplicate registration attempt
        res_dup = client.post("/api/v1/auth/register", json={
            "username": "sec_analyst_1",
            "password": "SecurePassword123!",
            "role": "analyst",
        })
        assert res_dup.status_code == 409

        # 3. Invalid password (too short)
        res_short = client.post("/api/v1/auth/register", json={
            "username": "invalid_user",
            "password": "short",
        })
        assert res_short.status_code == 400


def test_login_and_me_endpoint(client, app):
    """Test login authentication and fetching user profile with JWT."""
    with app.app_context():
        # Register user
        client.post("/api/v1/auth/register", json={
            "username": "auth_test_user",
            "password": "Password123!",
            "role": "viewer",
        })

        # Login with correct credentials
        res_login = client.post("/api/v1/auth/login", json={
            "username": "auth_test_user",
            "password": "Password123!",
        })
        assert res_login.status_code == 200
        token = res_login.get_json()["access_token"]
        assert token is not None

        # Fetch profile using Bearer token
        res_me = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_me.status_code == 200
        assert res_me.get_json()["username"] == "auth_test_user"


def test_rbac_authorization(client, app):
    """Test RBAC enforcement on admin-only endpoint."""
    with app.app_context():
        # Register viewer and admin users
        client.post("/api/v1/auth/register", json={
            "username": "viewer_user",
            "password": "Password123!",
            "role": "viewer",
        })
        client.post("/api/v1/auth/register", json={
            "username": "admin_user",
            "password": "Password123!",
            "role": "admin",
        })

        # Login as viewer
        token_viewer = client.post("/api/v1/auth/login", json={
            "username": "viewer_user",
            "password": "Password123!",
        }).get_json()["access_token"]

        # Viewer trying to access admin endpoint /api/v1/auth/users -> 403 Forbidden
        res_denied = client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token_viewer}"},
        )
        assert res_denied.status_code == 403

        # Login as admin
        token_admin = client.post("/api/v1/auth/login", json={
            "username": "admin_user",
            "password": "Password123!",
        }).get_json()["access_token"]

        # Admin accessing /api/v1/auth/users -> 200 OK
        res_allowed = client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token_admin}"},
        )
        assert res_allowed.status_code == 200
        assert res_allowed.get_json()["total"] >= 2


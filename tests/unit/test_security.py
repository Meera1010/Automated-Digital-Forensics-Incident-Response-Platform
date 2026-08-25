import pytest
from unittest.mock import patch
from flask_jwt_extended import create_access_token

from backend.vault import vault_manager
from backend.utils.error_handlers import ResourceNotFoundError
from backend.models.user import UserRole


@pytest.fixture
def auth_headers(app):
    """Generate auth headers for different roles."""
    def _get_headers(role_str):
        with app.app_context():
            access_token = create_access_token(
                identity="00000000-0000-0000-0000-000000000000",
                additional_claims={
                    "role": role_str,
                    "username": f"test_{role_str}",
                }
            )
            return {"Authorization": f"Bearer {access_token}"}
    return _get_headers


@patch("backend.utils.decorators.write_audit")
@patch("backend.api.auth.write_audit")
@patch("backend.api.auth.User")
def test_registration_requires_admin(mock_user_class, mock_auth_audit, mock_decorator_audit, client, auth_headers, app):
    """Test that only admins can register new users."""
    payload = {
        "username": "new_hacker",
        "password": "Password123!",
        "role": "admin"
    }
    
    mock_user_class.query.filter_by.return_value.first.return_value = None
    
    # Configure the instantiated User mock to return a dict for jsonify
    mock_instance = mock_user_class.return_value
    mock_instance.to_dict.return_value = {"username": "new_hacker", "role": "admin"}

    with app.app_context():
        # 1. Unauthenticated -> 401
        resp = client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 401

        # 2. Authenticated as viewer -> 403
        viewer_headers = auth_headers("viewer")
        resp = client.post("/api/v1/auth/register", json=payload, headers=viewer_headers)
        assert resp.status_code == 403

        # 3. Authenticated as admin -> 201 (Created)
        admin_headers = auth_headers("admin")
        
        # Mock user creation so we don't hit the DB for real
        with patch("backend.api.auth.db.session.add"), patch("backend.api.auth.db.session.commit"):
            resp = client.post("/api/v1/auth/register", json=payload, headers=admin_headers)
            assert resp.status_code == 201
            assert resp.json["user"]["username"] == "new_hacker"


@patch("werkzeug.security.check_password_hash")
@patch("backend.api.auth.User")
@patch("backend.api.auth.write_audit")
def test_login_timing_mitigation(mock_audit, mock_user_class, mock_check_hash, client, app):
    """Test that check_password_hash is ALWAYS called during login, even for non-existent users."""
    with app.app_context():
        mock_user_class.query.filter_by.return_value.first.return_value = None
        
        payload = {
            "username": "non_existent_user",
            "password": "Password123!"
        }
        
        resp = client.post("/api/v1/auth/login", json=payload)
        
        # Assert we failed securely
        assert resp.status_code == 401
        assert "Invalid username or password" in resp.json["error"]["message"]
        
        # Assert that the dummy check_password_hash was STILL called to mitigate timing attack
        mock_check_hash.assert_called_once()
        args, _ = mock_check_hash.call_args
        assert "L8vO" in args[0]  # Verify the dummy hash was used
        assert args[1] == "Password123!"


@patch("backend.api.evidence.EvidenceArtifact")
@patch("backend.utils.decorators.write_audit")
def test_download_evidence_requires_analyst_plus(mock_audit, mock_evidence_artifact_class, client, auth_headers):
    """Test that viewers cannot download evidence, but analysts can."""
    # Since we are just testing the route wrapper, we don't need the artifact to actually exist
    # If the RBAC fails, we get 403. If it succeeds, we get 404 (because artifact is missing).
    mock_evidence_artifact_class.query.get.return_value = None
    
    fake_uuid = "11111111-1111-1111-1111-111111111111"
    
    # 1. Authenticated as viewer -> 403 Forbidden
    viewer_headers = auth_headers("viewer")
    resp = client.get(f"/api/v1/evidence/{fake_uuid}/download", headers=viewer_headers)
    assert resp.status_code == 403
    
    # 2. Authenticated as analyst -> 404 Not Found (Passed RBAC!)
    analyst_headers = auth_headers("analyst")
    with pytest.raises(ResourceNotFoundError):
        client.get(f"/api/v1/evidence/{fake_uuid}/download", headers=analyst_headers)


def test_vault_manager_invalid_uuid(app):
    """Test that providing an invalid UUID string to retrieve() raises a 404, not a 500."""
    with app.app_context():
        invalid_uuid = "this-is-not-a-uuid"
        
        with pytest.raises(ResourceNotFoundError) as exc_info:
            vault_manager.retrieve(invalid_uuid)
            
        assert "not found" in str(exc_info.value)

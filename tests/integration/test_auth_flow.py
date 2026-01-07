"""Integration tests for authentication flow."""
import pytest
import json


@pytest.mark.integration
class TestAuthFlow:
    """Integration tests for authentication endpoints."""

    def test_register_login_logout_flow(self, client, db):
        """Test complete registration, login, and logout flow."""
        # Register
        register_data = {
            "email": "integration@example.com",
            "password": "TestPassword123!",
            "password_confirm": "TestPassword123!",
            "full_name": "Integration Test",
        }

        response = client.post(
            "/api/v1/auth/register",
            data=json.dumps(register_data),
            content_type="application/json",
        )

        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]
        assert data["data"]["user"]["email"] == "integration@example.com"

        # Logout
        response = client.post("/api/v1/auth/logout")
        assert response.status_code == 200

        # Login
        login_data = {
            "email": "integration@example.com",
            "password": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]

        # Logout again
        response = client.post("/api/v1/auth/logout")
        assert response.status_code == 200

    def test_get_current_user_authenticated(self, authenticated_client):
        """Test getting current user when authenticated."""
        response = authenticated_client.get("/api/v1/auth/me")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]

    def test_get_current_user_unauthenticated(self, client):
        """Test getting current user when not authenticated."""
        response = client.get("/api/v1/auth/me")

        assert response.status_code == 401
        data = response.get_json()
        assert data["success"] is False

    def test_invalid_credentials(self, client, test_user):
        """Test login with invalid credentials."""
        login_data = {
            "email": test_user.email,
            "password": "WrongPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 401
        data = response.get_json()
        assert data["success"] is False

    def test_duplicate_registration(self, client, test_user):
        """Test registering with existing email."""
        register_data = {
            "email": test_user.email,
            "password": "TestPassword123!",
            "password_confirm": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/register",
            data=json.dumps(register_data),
            content_type="application/json",
        )

        assert response.status_code == 409
        data = response.get_json()
        assert data["success"] is False

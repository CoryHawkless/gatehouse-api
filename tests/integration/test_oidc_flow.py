"""Integration tests for OIDC flow.

This module tests the complete OIDC authorization code flow with PKCE,
including discovery, authorization, token exchange, userinfo, refresh,
and revocation endpoints.
"""
import hashlib
import base64
import json
import secrets
import time
import pytest


@pytest.mark.integration
class TestOIDCDiscovery:
    """Tests for OIDC Discovery endpoint."""

    def test_discovery_returns_valid_json(self, client):
        """Test that discovery endpoint returns valid JSON configuration."""
        response = client.get("/.well-known/openid-configuration")
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Check required OIDC discovery fields
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "userinfo_endpoint" in data
        assert "jwks_uri" in data
        assert "registration_endpoint" in data
        assert "revocation_endpoint" in data
        assert "introspection_endpoint" in data

    def test_discovery_cache_header(self, client):
        """Test that discovery endpoint sets cache header."""
        response = client.get("/.well-known/openid-configuration")
        
        assert response.status_code == 200
        cache_header = response.headers.get("Cache-Control", "")
        assert "max-age" in cache_header

    def test_discovery_scopes_supported(self, client):
        """Test that discovery returns supported scopes."""
        response = client.get("/.well-known/openid-configuration")
        
        data = response.get_json()
        assert "scopes_supported" in data
        assert "openid" in data["scopes_supported"]
        assert "profile" in data["scopes_supported"]
        assert "email" in data["scopes_supported"]

    def test_discovery_response_types(self, client):
        """Test that discovery returns supported response types."""
        response = client.get("/.well-known/openid-configuration")
        
        data = response.get_json()
        assert "response_types_supported" in data
        assert "code" in data["response_types_supported"]

    def test_discovery_algorithms(self, client):
        """Test that discovery returns supported algorithms."""
        response = client.get("/.well-known/openid-configuration")
        
        data = response.get_json()
        assert "id_token_signing_alg_values_supported" in data
        assert "RS256" in data["id_token_signing_alg_values_supported"]


@pytest.mark.integration
class TestOIDCJWKS:
    """Tests for OIDC JWKS endpoint."""

    def test_jwks_returns_valid_jwks(self, client):
        """Test that JWKS endpoint returns valid JWKS document."""
        response = client.get("/oidc/jwks")
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "keys" in data
        assert isinstance(data["keys"], list)
        assert len(data["keys"]) > 0
        
        # Check key structure
        key = data["keys"][0]
        assert "kty" in key
        assert "kid" in key
        assert "alg" in key
        assert key["kty"] == "RSA"

    def test_jwks_cache_header(self, client):
        """Test that JWKS endpoint sets cache header."""
        response = client.get("/oidc/jwks")
        
        assert response.status_code == 200
        cache_header = response.headers.get("Cache-Control", "")
        assert "max-age" in cache_header

    def test_jwks_contains_signing_key(self, client, app):
        """Test that JWKS contains a valid signing key."""
        from app.services.oidc_jwks_service import OIDCJWKSService
        
        with app.app_context():
            # Initialize with a key
            jwks_service = OIDCJWKSService()
            jwks_service.initialize_with_key()
            
            response = client.get("/oidc/jwks")
            data = response.get_json()
            
            assert len(data["keys"]) > 0
            key = data["keys"][0]
            assert "n" in key
            assert "e" in key


@pytest.mark.integration
class TestOIDCClientRegistration:
    """Tests for OIDC Client Registration endpoint."""

    def test_register_client_success(self, client, test_organization):
        """Test successful client registration."""
        registration_data = {
            "client_name": "Test OAuth2 Client",
            "redirect_uris": ["https://example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid profile email",
            "token_endpoint_auth_method": "client_secret_basic",
        }
        
        response = client.post(
            "/oidc/register",
            data=json.dumps(registration_data),
            content_type="application/json",
        )
        
        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        assert "client_id" in data["data"]
        assert "client_secret" in data["data"]
        assert data["data"]["client_name"] == "Test OAuth2 Client"

    def test_register_client_missing_name(self, client):
        """Test client registration fails without client_name."""
        registration_data = {
            "redirect_uris": ["https://example.com/callback"],
        }
        
        response = client.post(
            "/oidc/register",
            data=json.dumps(registration_data),
            content_type="application/json",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_register_client_missing_redirect_uris(self, client):
        """Test client registration fails without redirect_uris."""
        registration_data = {
            "client_name": "Test Client",
        }
        
        response = client.post(
            "/oidc/register",
            data=json.dumps(registration_data),
            content_type="application/json",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_register_client_invalid_redirect_uri(self, client):
        """Test client registration fails with invalid redirect URI."""
        registration_data = {
            "client_name": "Test Client",
            "redirect_uris": ["not-a-valid-uri"],
        }
        
        response = client.post(
            "/oidc/register",
            data=json.dumps(registration_data),
            content_type="application/json",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False


@pytest.mark.integration
class TestOIDCAuthorizationCodeFlow:
    """Tests for OIDC Authorization Code Flow with PKCE."""

    @pytest.fixture
    def test_client(self, client, test_organization, test_user):
        """Create a test OIDC client."""
        from app.models import OIDCClient
        
        client_data = OIDCClient(
            organization_id=test_organization.id,
            name="Test PKCE Client",
            client_id="test_pkce_client",
            client_secret_hash="dummy_hash",
            redirect_uris=["https://example.com/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
            token_endpoint_auth_method="client_secret_basic",
            is_active=True,
            is_confidential=True,
            require_pkce=True,
        )
        from app.extensions import db
        db.session.add(client_data)
        db.session.commit()
        
        return client_data

    def _generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge.
        
        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        code_verifier = secrets.token_urlsafe(32)
        
        # Generate S256 code challenge
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        
        return code_verifier, code_challenge

    def test_authorization_endpoint_missing_params(self, client, test_client):
        """Test authorization fails with missing required parameters."""
        response = client.get("/oidc/authorize")
        
        assert response.status_code == 400
        
    def test_authorization_endpoint_invalid_client(self, client):
        """Test authorization fails with invalid client_id."""
        response = client.get(
            "/oidc/authorize",
            query_string={
                "client_id": "nonexistent_client",
                "redirect_uri": "https://example.com/callback",
                "response_type": "code",
            }
        )
        
        assert response.status_code == 302  # Redirect with error

    def test_authorization_endpoint_invalid_redirect_uri(self, client, test_client):
        """Test authorization fails with invalid redirect_uri."""
        response = client.get(
            "/oidc/authorize",
            query_string={
                "client_id": test_client.client_id,
                "redirect_uri": "https://malicious.com/callback",
                "response_type": "code",
            }
        )
        
        assert response.status_code == 302  # Redirect with error

    def test_authorization_endpoint_unsupported_response_type(self, client, test_client):
        """Test authorization fails with unsupported response_type."""
        response = client.get(
            "/oidc/authorize",
            query_string={
                "client_id": test_client.client_id,
                "redirect_uri": "https://example.com/callback",
                "response_type": "token",  # Not supported
            }
        )
        
        assert response.status_code == 302  # Redirect with error

    def test_authorization_endpoint_invalid_scope(self, client, test_client):
        """Test authorization fails with invalid scope."""
        response = client.get(
            "/oidc/authorize",
            query_string={
                "client_id": test_client.client_id,
                "redirect_uri": "https://example.com/callback",
                "response_type": "code",
                "scope": "invalid_scope",
            }
        )
        
        assert response.status_code == 302  # Redirect with error

    def test_authorization_code_flow_with_pkce(self, client, app, test_client, test_user):
        """Test complete authorization code flow with PKCE."""
        # Step 1: Generate PKCE parameters
        code_verifier, code_challenge = self._generate_pkce_pair()
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        
        # Step 2: Request authorization code via POST with credentials
        response = client.post(
            "/oidc/authorize",
            data={
                "client_id": test_client.client_id,
                "redirect_uri": "https://example.com/callback",
                "response_type": "code",
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "email": test_user.email,
                "password": test_user._test_password,
            }
        )
        
        assert response.status_code == 302
        
        # Parse redirect URL to get authorization code
        redirect_location = response.headers.get("Location", "")
        assert "code=" in redirect_location
        
        # Extract code from redirect
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(redirect_location)
        params = parse_qs(parsed.query)
        auth_code = params.get("code", [None])[0]
        returned_state = params.get("state", [None])[0]
        
        assert auth_code is not None
        assert returned_state == state

    def test_authorization_code_exchange_success(self, client, app, test_client, test_user):
        """Test successful token exchange with authorization code."""
        from app.services.oidc_service import OIDCService
        from app.models import OIDCAuthCode
        from app.extensions import db
        
        # First, generate an authorization code
        with app.app_context():
            code = OIDCService.generate_authorization_code(
                client_id=test_client.client_id,
                user_id=test_user.id,
                redirect_uri="https://example.com/callback",
                scope=["openid", "profile", "email"],
                state="test_state",
                nonce="test_nonce",
                code_challenge=None,
                code_challenge_method=None,
            )
            
            # Get the code hash for lookup
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            
            # Step 2: Exchange code for tokens
            response = client.post(
                "/oidc/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "https://example.com/callback",
                    "client_id": test_client.client_id,
                    "client_secret": "",  # Not needed for this test
                },
                content_type="application/x-www-form-urlencoded",
            )
            
            assert response.status_code == 200
            data = response.get_json()
            assert data["success"] is True
            
            # Check token response
            tokens = data["data"]
            assert "access_token" in tokens
            assert "token_type" in tokens
            assert tokens["token_type"] == "Bearer"
            assert "id_token" in tokens
            assert "refresh_token" in tokens
            assert "expires_in" in tokens

    def test_token_exchange_invalid_code(self, client, test_client):
        """Test token exchange fails with invalid authorization code."""
        response = client.post(
            "/oidc/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid_code",
                "redirect_uri": "https://example.com/callback",
                "client_id": test_client.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_token_exchange_missing_code(self, client, test_client):
        """Test token exchange fails without authorization code."""
        response = client.post(
            "/oidc/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "https://example.com/callback",
                "client_id": test_client.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_token_exchange_pkce_verification(self, client, app, test_client, test_user):
        """Test PKCE verification during token exchange."""
        from app.services.oidc_service import OIDCService
        
        # Generate PKCE pair
        code_verifier, code_challenge = self._generate_pkce_pair()
        
        # Generate authorization code with PKCE
        with app.app_context():
            code = OIDCService.generate_authorization_code(
                client_id=test_client.client_id,
                user_id=test_user.id,
                redirect_uri="https://example.com/callback",
                scope=["openid", "profile", "email"],
                state="test_state",
                nonce="test_nonce",
                code_challenge=code_challenge,
                code_challenge_method="S256",
            )
            
            # Token exchange without code_verifier should fail
            response = client.post(
                "/oidc/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "https://example.com/callback",
                    "client_id": test_client.client_id,
                    # Missing code_verifier
                },
                content_type="application/x-www-form-urlencoded",
            )
            
            assert response.status_code == 400
            data = response.get_json()
            assert data["success"] is False

    def test_token_exchange_with_pkce_verifier(self, client, app, test_client, test_user):
        """Test successful token exchange with valid PKCE code verifier."""
        from app.services.oidc_service import OIDCService
        
        # Generate PKCE pair
        code_verifier, code_challenge = self._generate_pkce_pair()
        
        # Generate authorization code with PKCE
        with app.app_context():
            code = OIDCService.generate_authorization_code(
                client_id=test_client.client_id,
                user_id=test_user.id,
                redirect_uri="https://example.com/callback",
                scope=["openid", "profile", "email"],
                state="test_state",
                nonce="test_nonce",
                code_challenge=code_challenge,
                code_challenge_method="S256",
            )
            
            # Token exchange with correct code_verifier
            response = client.post(
                "/oidc/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "https://example.com/callback",
                    "client_id": test_client.client_id,
                    "code_verifier": code_verifier,
                },
                content_type="application/x-www-form-urlencoded",
            )
            
            assert response.status_code == 200
            data = response.get_json()
            assert data["success"] is True


@pytest.mark.integration
class TestOIDCUserInfo:
    """Tests for OIDC UserInfo endpoint."""

    @pytest.fixture
    def test_client_with_user(self, client, test_organization, test_user):
        """Create a test OIDC client and get tokens."""
        from app.models import OIDCClient
        from app.services.oidc_service import OIDCService
        
        client_data = OIDCClient(
            organization_id=test_organization.id,
            name="Test UserInfo Client",
            client_id="test_userinfo_client",
            client_secret_hash="dummy_hash",
            redirect_uris=["https://example.com/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
            token_endpoint_auth_method="client_secret_basic",
            is_active=True,
            is_confidential=False,
            require_pkce=False,
        )
        from app.extensions import db
        db.session.add(client_data)
        db.session.commit()
        
        # Generate tokens directly
        with client.application.app_context():
            tokens = OIDCService.generate_tokens(
                client_id=client_data.client_id,
                user_id=test_user.id,
                scope=["openid", "profile", "email"],
                nonce="test_nonce",
            )
        
        return client_data, tokens["access_token"], test_user

    def test_userinfo_without_token(self, client):
        """Test UserInfo endpoint returns 401 without token."""
        response = client.get("/oidc/userinfo")
        
        assert response.status_code == 401
        data = response.get_json()
        assert data["success"] is False

    def test_userinfo_with_invalid_token(self, client):
        """Test UserInfo endpoint returns 401 with invalid token."""
        response = client.get(
            "/oidc/userinfo",
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        assert response.status_code == 401

    def test_userinfo_with_valid_token(self, client, test_client_with_user):
        """Test UserInfo endpoint returns claims with valid token."""
        _, access_token, test_user = test_client_with_user
        
        response = client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        
        userinfo = data["data"]
        assert "sub" in userinfo
        assert userinfo["sub"] == test_user.id
        assert "email" in userinfo
        assert userinfo["email"] == test_user.email

    def test_userinfo_claims_by_scope(self, client, app, test_organization, test_user):
        """Test UserInfo returns correct claims based on scopes."""
        from app.models import OIDCClient
        from app.services.oidc_service import OIDCService
        
        # Create client with only openid scope
        client_data = OIDCClient(
            organization_id=test_organization.id,
            name="Test OpenID Client",
            client_id="test_openid_client",
            client_secret_hash="dummy_hash",
            redirect_uris=["https://example.com/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            scopes=["openid"],  # Only openid
            token_endpoint_auth_method="client_secret_basic",
            is_active=True,
            is_confidential=False,
            require_pkce=False,
        )
        from app.extensions import db
        db.session.add(client_data)
        db.session.commit()
        
        with app.app_context():
            tokens = OIDCService.generate_tokens(
                client_id=client_data.client_id,
                user_id=test_user.id,
                scope=["openid"],
            )
        
        response = client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        userinfo = data["data"]
        
        # Should only have sub claim with openid scope
        assert userinfo["sub"] == test_user.id
        assert "email" not in userinfo
        assert "name" not in userinfo


@pytest.mark.integration
class TestOIDCTokenRefresh:
    """Tests for OIDC Token Refresh."""

    @pytest.fixture
    def test_client_with_refresh_token(self, client, test_organization, test_user):
        """Create a test OIDC client with refresh token."""
        from app.models import OIDCClient
        from app.services.oidc_service import OIDCService
        
        client_data = OIDCClient(
            organization_id=test_organization.id,
            name="Test Refresh Client",
            client_id="test_refresh_client",
            client_secret_hash="dummy_hash",
            redirect_uris=["https://example.com/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
            token_endpoint_auth_method="client_secret_basic",
            is_active=True,
            is_confidential=False,
            require_pkce=False,
        )
        from app.extensions import db
        db.session.add(client_data)
        db.session.commit()
        
        with client.application.app_context():
            tokens = OIDCService.generate_tokens(
                client_id=client_data.client_id,
                user_id=test_user.id,
                scope=["openid", "profile", "email"],
            )
        
        return client_data, tokens["refresh_token"]

    def test_refresh_access_token(self, client, test_client_with_refresh_token):
        """Test refreshing an access token."""
        client_data, refresh_token = test_client_with_refresh_token
        
        response = client.post(
            "/oidc/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        
        tokens = data["data"]
        assert "access_token" in tokens
        assert "refresh_token" in tokens  # Token rotation
        assert "id_token" in tokens
        assert "expires_in" in tokens

    def test_refresh_without_refresh_token(self, client, test_client_with_refresh_token):
        """Test refresh fails without refresh token."""
        client_data = test_client_with_refresh_token[0]
        
        response = client.post(
            "/oidc/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_refresh_with_invalid_token(self, client, test_client_with_refresh_token):
        """Test refresh fails with invalid refresh token."""
        client_data = test_client_with_refresh_token[0]
        
        response = client.post(
            "/oidc/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "invalid_refresh_token",
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False


@pytest.mark.integration
class TestOIDCTokenRevocation:
    """Tests for OIDC Token Revocation."""

    @pytest.fixture
    def test_client_with_tokens(self, client, test_organization, test_user):
        """Create a test OIDC client with valid tokens."""
        from app.models import OIDCClient
        from app.services.oidc_service import OIDCService
        
        client_data = OIDCClient(
            organization_id=test_organization.id,
            name="Test Revoke Client",
            client_id="test_revoke_client",
            client_secret_hash="dummy_hash",
            redirect_uris=["https://example.com/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
            token_endpoint_auth_method="client_secret_basic",
            is_active=True,
            is_confidential=False,
            require_pkce=False,
        )
        from app.extensions import db
        db.session.add(client_data)
        db.session.commit()
        
        with client.application.app_context():
            tokens = OIDCService.generate_tokens(
                client_id=client_data.client_id,
                user_id=test_user.id,
                scope=["openid", "profile", "email"],
            )
        
        return client_data, tokens["access_token"], tokens["refresh_token"]

    def test_revoke_access_token(self, client, test_client_with_tokens):
        """Test revoking an access token."""
        client_data, access_token, refresh_token = test_client_with_tokens
        
        response = client.post(
            "/oidc/revoke",
            data={
                "token": access_token,
                "token_type_hint": "access_token",
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

    def test_revoke_refresh_token(self, client, test_client_with_tokens):
        """Test revoking a refresh token."""
        client_data, access_token, refresh_token = test_client_with_tokens
        
        response = client.post(
            "/oidc/revoke",
            data={
                "token": refresh_token,
                "token_type_hint": "refresh_token",
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

    def test_revoke_without_token(self, client, test_client_with_tokens):
        """Test revocation fails without token."""
        client_data = test_client_with_tokens[0]
        
        response = client.post(
            "/oidc/revoke",
            data={
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_revoke_without_client_auth(self, client, test_client_with_tokens):
        """Test revocation fails without client authentication."""
        _, access_token, _ = test_client_with_tokens
        
        response = client.post(
            "/oidc/revoke",
            data={
                "token": access_token,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 401


@pytest.mark.integration
class TestOIDCTokenIntrospection:
    """Tests for OIDC Token Introspection."""

    @pytest.fixture
    def test_client_with_tokens(self, client, test_organization, test_user):
        """Create a test OIDC client with valid tokens."""
        from app.models import OIDCClient
        from app.services.oidc_service import OIDCService
        
        client_data = OIDCClient(
            organization_id=test_organization.id,
            name="Test Introspect Client",
            client_id="test_introspect_client",
            client_secret_hash="dummy_hash",
            redirect_uris=["https://example.com/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
            token_endpoint_auth_method="client_secret_basic",
            is_active=True,
            is_confidential=False,
            require_pkce=False,
        )
        from app.extensions import db
        db.session.add(client_data)
        db.session.commit()
        
        with client.application.app_context():
            tokens = OIDCService.generate_tokens(
                client_id=client_data.client_id,
                user_id=test_user.id,
                scope=["openid", "profile", "email"],
            )
        
        return client_data, tokens["access_token"]

    def test_introspect_active_token(self, client, test_client_with_tokens):
        """Test introspecting an active token."""
        client_data, access_token = test_client_with_tokens
        
        response = client.post(
            "/oidc/introspect",
            data={
                "token": access_token,
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        
        result = data["data"]
        assert result["active"] is True
        assert "sub" in result
        assert "exp" in result

    def test_introspect_without_token(self, client, test_client_with_tokens):
        """Test introspection fails without token."""
        client_data = test_client_with_tokens[0]
        
        response = client.post(
            "/oidc/introspect",
            data={
                "client_id": client_data.client_id,
            },
            content_type="application/x-www-form-urlencoded",
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False


@pytest.mark.integration
class TestOIDCCompleteFlow:
    """Tests for complete OIDC authentication flow."""

    def test_complete_oidc_flow(self, client, app, test_organization, test_user):
        """Test complete OIDC authorization code flow with PKCE."""
        from app.models import OIDCClient
        from app.services.oidc_service import OIDCService
        from app.extensions import db
        
        # Create a test client
        with app.app_context():
            client_data = OIDCClient(
                organization_id=test_organization.id,
                name="Complete Flow Client",
                client_id="complete_flow_client",
                client_secret_hash="dummy_hash",
                redirect_uris=["https://example.com/callback"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scopes=["openid", "profile", "email"],
                token_endpoint_auth_method="client_secret_basic",
                is_active=True,
                is_confidential=False,
                require_pkce=True,
            )
            db.session.add(client_data)
            db.session.commit()
            
            # Generate PKCE parameters
            code_verifier = secrets.token_urlsafe(32)
            digest = hashlib.sha256(code_verifier.encode()).digest()
            code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            state = secrets.token_urlsafe(16)
            nonce = secrets.token_urlsafe(16)
            
            # Step 1: Authorization Request
            auth_response = client.post(
                "/oidc/authorize",
                data={
                    "client_id": client_data.client_id,
                    "redirect_uri": "https://example.com/callback",
                    "response_type": "code",
                    "scope": "openid profile email",
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "email": test_user.email,
                    "password": test_user._test_password,
                }
            )
            
            assert auth_response.status_code == 302
            
            # Extract authorization code
            redirect_location = auth_response.headers.get("Location", "")
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(redirect_location)
            params = parse_qs(parsed.query)
            auth_code = params.get("code", [None])[0]
            
            assert auth_code is not None
            
            # Step 2: Token Exchange
            token_response = client.post(
                "/oidc/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": "https://example.com/callback",
                    "client_id": client_data.client_id,
                    "code_verifier": code_verifier,
                },
                content_type="application/x-www-form-urlencoded",
            )
            
            assert token_response.status_code == 200
            token_data = token_response.get_json()
            tokens = token_data["data"]
            
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]
            id_token = tokens["id_token"]
            
            # Step 3: UserInfo Request
            userinfo_response = client.get(
                "/oidc/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            assert userinfo_response.status_code == 200
            userinfo_data = userinfo_response.get_json()
            assert userinfo_data["data"]["sub"] == test_user.id
            
            # Step 4: Token Refresh
            refresh_response = client.post(
                "/oidc/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_data.client_id,
                },
                content_type="application/x-www-form-urlencoded",
            )
            
            assert refresh_response.status_code == 200
            refresh_data = refresh_response.get_json()
            new_access_token = refresh_data["data"]["access_token"]
            new_refresh_token = refresh_data["data"]["refresh_token"]
            
            # Step 5: Token Revocation
            revoke_response = client.post(
                "/oidc/revoke",
                data={
                    "token": new_refresh_token,
                    "token_type_hint": "refresh_token",
                    "client_id": client_data.client_id,
                },
                content_type="application/x-www-form-urlencoded",
            )
            
            assert revoke_response.status_code == 200
            
            # Verify refresh token was revoked
            refresh_after_revoke = client.post(
                "/oidc/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": new_refresh_token,
                    "client_id": client_data.client_id,
                },
                content_type="application/x-www-form-urlencoded",
            )
            
            assert refresh_after_revoke.status_code == 400

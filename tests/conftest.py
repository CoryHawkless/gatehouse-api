"""Pytest configuration and fixtures."""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone

from gatehouse_app import create_app
from gatehouse_app.extensions import db as _db
from gatehouse_app.models import User, Organization, OrganizationMember, AuthenticationMethod
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.utils.constants import OrganizationRole, AuthMethodType
from gatehouse_app.services.external_auth_service import ExternalProviderConfig, OAuthState


@pytest.fixture(scope="session")
def app():
    """Create application for testing."""
    app = create_app("testing")
    return app


@pytest.fixture(scope="function")
def db(app):
    """Create database for testing."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app, db):
    """Create test client."""
    return app.test_client()


@pytest.fixture(scope="function")
def test_user(db):
    """Create a test user."""
    email = "test@example.com"
    password = "TestPassword123!"
    full_name = "Test User"

    user = AuthService.register_user(
        email=email,
        password=password,
        full_name=full_name,
    )

    # Store password for testing
    user._test_password = password

    return user


@pytest.fixture(scope="function")
def test_organization(db, test_user):
    """Create a test organization."""
    from gatehouse_app.services.organization_service import OrganizationService

    org = OrganizationService.create_organization(
        name="Test Organization",
        slug="test-org",
        owner_user_id=test_user.id,
        description="A test organization",
    )

    return org


@pytest.fixture(scope="function")
def authenticated_client(client, test_user):
    """Create authenticated test client."""
    # Login
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": test_user.email,
            "password": test_user._test_password,
        },
    )

    assert response.status_code == 200

    return client


@pytest.fixture(scope="function")
def second_test_user(db):
    """Create a second test user."""
    email = "second@example.com"
    password = "TestPassword123!"
    full_name = "Second User"

    user = AuthService.register_user(
        email=email,
        password=password,
        full_name=full_name,
    )

    user._test_password = password

    return user


# =============================================================================
# External Auth Testing Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def google_provider_config(db, test_organization):
    """Create a Google OAuth provider configuration."""
    config = ExternalProviderConfig(
        organization_id=test_organization.id,
        provider_type=AuthMethodType.GOOGLE.value,
        client_id="test-google-client-id",
        client_secret_encrypted="encrypted-google-secret",
        auth_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
        scopes=["openid", "profile", "email"],
        redirect_uris=[
            "http://localhost:3000/callback",
            "http://localhost:5173/callback",
            "https://myapp.example.com/callback",
        ],
        is_active=True,
    )
    config.save()
    return config


@pytest.fixture(scope="function")
def github_provider_config(db, test_organization):
    """Create a GitHub OAuth provider configuration."""
    config = ExternalProviderConfig(
        organization_id=test_organization.id,
        provider_type=AuthMethodType.GITHUB.value,
        client_id="test-github-client-id",
        client_secret_encrypted="encrypted-github-secret",
        auth_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        scopes=["read:user", "user:email"],
        redirect_uris=["http://localhost:3000/callback"],
        is_active=True,
    )
    config.save()
    return config


@pytest.fixture(scope="function")
def microsoft_provider_config(db, test_organization):
    """Create a Microsoft OAuth provider configuration."""
    config = ExternalProviderConfig(
        organization_id=test_organization.id,
        provider_type=AuthMethodType.MICROSOFT.value,
        client_id="test-microsoft-client-id",
        client_secret_encrypted="encrypted-microsoft-secret",
        auth_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        userinfo_url="https://graph.microsoft.com/oidc/userinfo",
        scopes=["openid", "profile", "email", "User.Read"],
        redirect_uris=["http://localhost:3000/callback"],
        is_active=True,
    )
    config.save()
    return config


@pytest.fixture(scope="function")
def user_with_google_link(db, test_user):
    """Create a test user with a linked Google account."""
    auth_method = AuthenticationMethod(
        user_id=test_user.id,
        method_type=AuthMethodType.GOOGLE,
        provider_user_id="google-123456789",
        provider_data={
            "email": test_user.email,
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg",
        },
        verified=True,
        is_primary=False,
    )
    auth_method.save()
    return test_user


@pytest.fixture(scope="function")
def user_with_multiple_providers(db, test_user):
    """Create a test user with multiple linked external accounts."""
    # Google account
    google_method = AuthenticationMethod(
        user_id=test_user.id,
        method_type=AuthMethodType.GOOGLE,
        provider_user_id="google-123",
        provider_data={
            "email": test_user.email,
            "name": "Test User",
        },
        verified=True,
    )
    google_method.save()

    # GitHub account
    github_method = AuthenticationMethod(
        user_id=test_user.id,
        method_type=AuthMethodType.GITHUB,
        provider_user_id="github-456",
        provider_data={
            "email": "user@github.com",
            "name": "Test User",
        },
        verified=True,
    )
    github_method.save()

    return test_user


@pytest.fixture
def mock_google_oauth_token_response():
    """Mock Google OAuth token response."""
    return {
        "access_token": "ya29.mock-access-token",
        "refresh_token": "1//mock-refresh-token",
        "id_token": "eyJ.mock-id-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile email",
    }


@pytest.fixture
def mock_google_oauth_user_info():
    """Mock Google OAuth user info response."""
    return {
        "sub": "google-123456789",
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "picture": "https://example.com/avatar.jpg",
        "email": "testuser@gmail.com",
        "email_verified": True,
    }


@pytest.fixture
def mock_github_oauth_token_response():
    """Mock GitHub OAuth token response."""
    return {
        "access_token": "gho_mock-access-token",
        "token_type": "bearer",
        "scope": "read:user,user:email",
    }


@pytest.fixture
def mock_github_oauth_user_info():
    """Mock GitHub OAuth user info response."""
    return {
        "id": 123456789,
        "login": "testuser",
        "name": "Test User",
        "email": "testuser@github.com",
        "avatar_url": "https://example.com/avatar.jpg",
        "type": "User",
    }


@pytest.fixture
def oauth_login_state(db, test_organization):
    """Create an OAuth state for login flow."""
    state = OAuthState.create_state(
        flow_type="login",
        provider_type=AuthMethodType.GOOGLE,
        organization_id=test_organization.id,
        redirect_uri="http://localhost:3000/callback",
        nonce="mock-nonce",
        code_verifier="mock-code-verifier",
        code_challenge="mock-code-challenge",
        lifetime_seconds=600,
    )
    return state


@pytest.fixture
def oauth_register_state(db, test_organization):
    """Create an OAuth state for register flow."""
    state = OAuthState.create_state(
        flow_type="register",
        provider_type=AuthMethodType.GOOGLE,
        organization_id=test_organization.id,
        redirect_uri="http://localhost:3000/callback",
        lifetime_seconds=600,
    )
    return state


@pytest.fixture
def oauth_link_state(db, test_user, test_organization):
    """Create an OAuth state for link flow."""
    state = OAuthState.create_state(
        flow_type="link",
        provider_type=AuthMethodType.GOOGLE,
        user_id=test_user.id,
        organization_id=test_organization.id,
        redirect_uri="http://localhost:3000/callback",
        lifetime_seconds=600,
    )
    return state


@pytest.fixture
def expired_oauth_state(db, test_organization):
    """Create an expired OAuth state."""
    state = OAuthState.create_state(
        flow_type="login",
        provider_type=AuthMethodType.GOOGLE,
        organization_id=test_organization.id,
        redirect_uri="http://localhost:3000/callback",
        lifetime_seconds=-1,  # Already expired
    )
    return state


@pytest.fixture
def used_oauth_state(db, test_organization):
    """Create a used OAuth state."""
    state = OAuthState.create_state(
        flow_type="login",
        provider_type=AuthMethodType.GOOGLE,
        organization_id=test_organization.id,
        redirect_uri="http://localhost:3000/callback",
        lifetime_seconds=600,
    )
    state.mark_used()
    return state


@pytest.fixture
def mock_oauth_flow_mocks():
    """Common mocks for OAuth flow tests."""
    with patch.object(
        ExternalProviderConfig, 'get_client_secret', return_value='mock-secret'
    ) as mock_get_secret, patch(
        'requests.post'
    ) as mock_post, patch(
        'requests.get'
    ) as mock_get:
        # Mock token exchange response
        mock_post.return_value.json.return_value = {
            "access_token": "mock-access-token",
            "refresh_token": "mock-refresh-token",
            "id_token": "mock-id-token",
            "expires_in": 3600,
        }
        mock_post.return_value.raise_for_status = Mock()

        # Mock user info response
        mock_get.return_value.json.return_value = {
            "sub": "google-123",
            "email": "testuser@gmail.com",
            "email_verified": True,
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg",
        }
        mock_get.return_value.raise_for_status = Mock()

        yield {
            'get_secret': mock_get_secret,
            'post': mock_post,
            'get': mock_get,
        }

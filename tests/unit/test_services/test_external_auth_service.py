"""Unit tests for ExternalAuthService."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta, timezone

from gatehouse_app.services.external_auth_service import (
    ExternalAuthService,
    ExternalAuthError,
    OAuthState,
    ExternalProviderConfig,
)
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.models import User, AuthenticationMethod


@pytest.mark.unit
class TestExternalAuthService:
    """Tests for ExternalAuthService."""

    def test_get_provider_config_success(self, app, db, test_organization):
        """Test getting provider configuration successfully."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                client_secret_encrypted="encrypted-secret",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            # Get config
            result = ExternalAuthService.get_provider_config(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE,
            )

            assert result.id == config.id
            assert result.client_id == "test-client-id"
            assert result.is_active is True

    def test_get_provider_config_not_configured(self, app, db, test_organization):
        """Test getting provider configuration when not configured."""
        with app.app_context():
            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.get_provider_config(
                    organization_id=test_organization.id,
                    provider_type=AuthMethodType.GOOGLE,
                )

            assert exc_info.value.error_type == "PROVIDER_NOT_CONFIGURED"
            assert exc_info.value.status_code == 400

    def test_get_provider_config_inactive(self, app, db, test_organization):
        """Test getting provider configuration when inactive."""
        with app.app_context():
            # Create inactive provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=False,
            )
            config.save()

            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.get_provider_config(
                    organization_id=test_organization.id,
                    provider_type=AuthMethodType.GOOGLE,
                )

            assert exc_info.value.error_type == "PROVIDER_NOT_CONFIGURED"

    @patch('gatehouse_app.services.external_auth_service.AuditService')
    def test_initiate_link_flow_success(self, mock_audit, app, db, test_user, test_organization):
        """Test initiating account linking flow successfully."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            # Initiate link flow
            auth_url, state = ExternalAuthService.initiate_link_flow(
                user_id=test_user.id,
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
            )

            assert auth_url is not None
            assert state is not None
            assert len(state) == 43  # Base64 URL-safe token length

            # Verify state was created
            state_record = OAuthState.query.filter_by(state=state).first()
            assert state_record is not None
            assert state_record.flow_type == "link"
            assert state_record.user_id == test_user.id
            assert state_record.provider_type == AuthMethodType.GOOGLE.value

            # Verify audit log
            mock_audit.log_external_auth_link_initiated.assert_called_once()

    def test_initiate_link_flow_invalid_redirect_uri(self, app, db, test_user, test_organization):
        """Test initiating link flow with invalid redirect URI."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.initiate_link_flow(
                    user_id=test_user.id,
                    provider_type=AuthMethodType.GOOGLE,
                    organization_id=test_organization.id,
                    redirect_uri="http://malicious-site.com/callback",
                )

            assert exc_info.value.error_type == "INVALID_REDIRECT_URI"

    @patch('gatehouse_app.services.external_auth_service.ExternalAuthService._exchange_code')
    @patch('gatehouse_app.services.external_auth_service.ExternalAuthService._get_user_info')
    @patch('gatehouse_app.services.external_auth_service.AuditService')
    def test_complete_link_flow_success(
        self, mock_audit, mock_get_user_info, mock_exchange_code,
        app, db, test_user, test_organization
    ):
        """Test completing account linking flow successfully."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            # Create OAuth state
            state = OAuthState.create_state(
                flow_type="link",
                provider_type=AuthMethodType.GOOGLE,
                user_id=test_user.id,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            # Mock external provider responses
            mock_exchange_code.return_value = {
                "access_token": "mock-access-token",
                "refresh_token": "mock-refresh-token",
                "id_token": "mock-id-token",
                "expires_in": 3600,
            }

            mock_get_user_info.return_value = {
                "provider_user_id": "google-123",
                "email": "user@gmail.com",
                "email_verified": True,
                "name": "Test User",
                "picture": "https://example.com/avatar.jpg",
                "raw_data": {},
            }

            # Complete link flow
            auth_method = ExternalAuthService.complete_link_flow(
                provider_type=AuthMethodType.GOOGLE,
                authorization_code="mock-auth-code",
                state=state.state,
                redirect_uri="http://localhost:3000/callback",
            )

            assert auth_method is not None
            assert auth_method.user_id == test_user.id
            assert auth_method.method_type == AuthMethodType.GOOGLE
            assert auth_method.provider_user_id == "google-123"

            # Verify state is marked as used
            state_record = OAuthState.query.get(state.id)
            assert state_record.used is True

            # Verify audit log
            mock_audit.log_external_auth_link_completed.assert_called_once()

    def test_complete_link_flow_invalid_state(self, app, db):
        """Test completing link flow with invalid state."""
        with app.app_context():
            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.complete_link_flow(
                    provider_type=AuthMethodType.GOOGLE,
                    authorization_code="mock-auth-code",
                    state="invalid-state",
                    redirect_uri="http://localhost:3000/callback",
                )

            assert exc_info.value.error_type == "INVALID_STATE"

    def test_complete_link_flow_wrong_flow_type(self, app, db, test_organization):
        """Test completing link flow with wrong flow type state."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            # Create login flow state instead of link
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.complete_link_flow(
                    provider_type=AuthMethodType.GOOGLE,
                    authorization_code="mock-auth-code",
                    state=state.state,
                    redirect_uri="http://localhost:3000/callback",
                )

            assert exc_info.value.error_type == "INVALID_FLOW_TYPE"

    def test_complete_link_flow_provider_mismatch(self, app, db, test_organization):
        """Test completing link flow with provider mismatch."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            # Create state with different provider
            state = OAuthState.create_state(
                flow_type="link",
                provider_type=AuthMethodType.GITHUB,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.complete_link_flow(
                    provider_type=AuthMethodType.GOOGLE,
                    authorization_code="mock-auth-code",
                    state=state.state,
                    redirect_uri="http://localhost:3000/callback",
                )

            assert exc_info.value.error_type == "PROVIDER_MISMATCH"

    @patch('gatehouse_app.services.external_auth_service.ExternalAuthService._exchange_code')
    @patch('gatehouse_app.services.external_auth_service.ExternalAuthService._get_user_info')
    @patch('gatehouse_app.services.external_auth_service.AuditService')
    def test_authenticate_with_provider_success(
        self, mock_audit, mock_get_user_info, mock_exchange_code,
        app, db, test_user, test_organization
    ):
        """Test authenticating with provider successfully."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            # Create authentication method for user
            auth_method = AuthenticationMethod(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
                provider_user_id="google-123",
                provider_data={"email": test_user.email},
                verified=True,
            )
            auth_method.save()

            # Create OAuth state
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            # Mock external provider responses
            mock_exchange_code.return_value = {
                "access_token": "mock-access-token",
                "refresh_token": "mock-refresh-token",
                "id_token": "mock-id-token",
                "expires_in": 3600,
            }

            mock_get_user_info.return_value = {
                "provider_user_id": "google-123",
                "email": test_user.email,
                "email_verified": True,
                "name": "Test User",
                "picture": "https://example.com/avatar.jpg",
                "raw_data": {},
            }

            # Authenticate
            user, session_data = ExternalAuthService.authenticate_with_provider(
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
                authorization_code="mock-auth-code",
                state=state.state,
                redirect_uri="http://localhost:3000/callback",
            )

            assert user.id == test_user.id
            assert session_data is not None
            assert "token" in session_data

    @patch('gatehouse_app.services.external_auth_service.ExternalAuthService._exchange_code')
    @patch('gatehouse_app.services.external_auth_service.ExternalAuthService._get_user_info')
    @patch('gatehouse_app.services.external_auth_service.AuditService')
    def test_authenticate_with_provider_account_not_found(
        self, mock_audit, mock_get_user_info, mock_exchange_code,
        app, db, test_organization
    ):
        """Test authenticating with provider when account not found."""
        with app.app_context():
            # Create provider config
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            # Create OAuth state
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            # Mock external provider responses
            mock_exchange_code.return_value = {
                "access_token": "mock-access-token",
                "refresh_token": "mock-refresh-token",
                "id_token": "mock-id-token",
                "expires_in": 3600,
            }

            mock_get_user_info.return_value = {
                "provider_user_id": "google-456",
                "email": "newuser@gmail.com",
                "email_verified": True,
                "name": "New User",
                "picture": "https://example.com/avatar.jpg",
                "raw_data": {},
            }

            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.authenticate_with_provider(
                    provider_type=AuthMethodType.GOOGLE,
                    organization_id=test_organization.id,
                    authorization_code="mock-auth-code",
                    state=state.state,
                    redirect_uri="http://localhost:3000/callback",
                )

            assert exc_info.value.error_type == "ACCOUNT_NOT_FOUND"

    @patch('gatehouse_app.services.external_auth_service.AuditService')
    def test_unlink_provider_success(self, mock_audit, app, db, test_user):
        """Test unlinking provider successfully."""
        with app.app_context():
            # Create password auth method first (so user has other methods)
            password_method = AuthenticationMethod(
                user_id=test_user.id,
                method_type=AuthMethodType.PASSWORD,
                provider_user_id=test_user.id,
            )
            password_method.save()

            # Create Google auth method
            google_method = AuthenticationMethod(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
                provider_user_id="google-123",
                provider_data={"email": test_user.email},
                verified=True,
            )
            google_method.save()

            # Unlink Google
            result = ExternalAuthService.unlink_provider(
                user_id=test_user.id,
                provider_type=AuthMethodType.GOOGLE,
            )

            assert result is True

            # Verify auth method is deleted
            method = AuthenticationMethod.query.filter_by(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
            ).first()
            assert method is None

            # Verify audit log
            mock_audit.log_external_auth_unlink.assert_called_once()

    def test_unlink_provider_not_linked(self, app, db, test_user):
        """Test unlinking provider that is not linked."""
        with app.app_context():
            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.unlink_provider(
                    user_id=test_user.id,
                    provider_type=AuthMethodType.GOOGLE,
                )

            assert exc_info.value.error_type == "PROVIDER_NOT_LINKED"

    def test_unlink_provider_last_method(self, app, db, test_user):
        """Test unlinking last authentication method."""
        with app.app_context():
            # Create only Google auth method
            google_method = AuthenticationMethod(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
                provider_user_id="google-123",
                provider_data={"email": test_user.email},
                verified=True,
            )
            google_method.save()

            with pytest.raises(ExternalAuthError) as exc_info:
                ExternalAuthService.unlink_provider(
                    user_id=test_user.id,
                    provider_type=AuthMethodType.GOOGLE,
                )

            assert exc_info.value.error_type == "CANNOT_UNLINK_LAST"

    def test_get_linked_accounts(self, app, db, test_user):
        """Test getting linked accounts for user."""
        with app.app_context():
            # Create Google auth method
            google_method = AuthenticationMethod(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
                provider_user_id="google-123",
                provider_data={
                    "email": test_user.email,
                    "name": "Test User",
                    "picture": "https://example.com/avatar.jpg",
                },
                verified=True,
            )
            google_method.save()

            # Create GitHub auth method
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

            # Get linked accounts
            accounts = ExternalAuthService.get_linked_accounts(test_user.id)

            assert len(accounts) == 2

            google_account = next(a for a in accounts if a["provider_type"] == "google")
            assert google_account["provider_user_id"] == "google-123"
            assert google_account["email"] == test_user.email

            github_account = next(a for a in accounts if a["provider_type"] == "github")
            assert github_account["provider_user_id"] == "github-456"


@pytest.mark.unit
class TestOAuthState:
    """Tests for OAuthState model."""

    def test_create_state(self, app, db):
        """Test creating OAuth state."""
        with app.app_context():
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                user_id="user-123",
                organization_id="org-456",
                redirect_uri="http://localhost:3000/callback",
            )

            assert state.state is not None
            assert len(state.state) == 43
            assert state.flow_type == "login"
            assert state.provider_type == AuthMethodType.GOOGLE.value
            assert state.user_id == "user-123"
            assert state.organization_id == "org-456"
            assert state.redirect_uri == "http://localhost:3000/callback"
            assert state.used is False
            assert state.expires_at > datetime.now(timezone.utc)

    def test_is_valid(self, app, db):
        """Test OAuth state validity check."""
        with app.app_context():
            # Create valid state
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
            )

            assert state.is_valid() is True

            # Mark as used
            state.mark_used()

            assert state.is_valid() is False

    def test_is_valid_expired(self, app, db):
        """Test OAuth state validity with expiration."""
        with app.app_context():
            # Create expired state
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                lifetime_seconds=-1,  # Already expired
            )

            assert state.is_valid() is False


@pytest.mark.unit
class TestExternalProviderConfig:
    """Tests for ExternalProviderConfig model."""

    def test_is_redirect_uri_allowed(self, app, db, test_organization):
        """Test redirect URI validation."""
        with app.app_context():
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=[
                    "http://localhost:3000/callback",
                    "https://myapp.com/callback",
                ],
                is_active=True,
            )
            config.save()

            assert config.is_redirect_uri_allowed("http://localhost:3000/callback") is True
            assert config.is_redirect_uri_allowed("https://myapp.com/callback") is True
            assert config.is_redirect_uri_allowed("http://malicious.com/callback") is False

    def test_to_dict(self, app, db, test_organization):
        """Test converting config to dictionary."""
        with app.app_context():
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            result = config.to_dict()

            assert result["organization_id"] == test_organization.id
            assert result["provider_type"] == AuthMethodType.GOOGLE.value
            assert result["client_id"] == "test-client-id"
            assert "client_secret" not in result
            assert result["is_active"] is True

    def test_to_dict_include_secrets(self, app, db, test_organization):
        """Test converting config to dictionary with secrets."""
        with app.app_context():
            config = ExternalProviderConfig(
                organization_id=test_organization.id,
                provider_type=AuthMethodType.GOOGLE.value,
                client_id="test-client-id",
                client_secret_encrypted="encrypted-secret",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
                scopes=["openid", "profile", "email"],
                redirect_uris=["http://localhost:3000/callback"],
                is_active=True,
            )
            config.save()

            result = config.to_dict(include_secrets=True)

            assert "client_secret" in result


@pytest.mark.unit
class TestExternalAuthError:
    """Tests for ExternalAuthError exception."""

    def test_error_creation(self):
        """Test creating ExternalAuthError."""
        error = ExternalAuthError(
            message="Test error message",
            error_type="TEST_ERROR",
            status_code=400,
        )

        assert error.message == "Test error message"
        assert error.error_type == "TEST_ERROR"
        assert error.status_code == 400

    def test_error_default_status_code(self):
        """Test ExternalAuthError with default status code."""
        error = ExternalAuthError(
            message="Test error message",
            error_type="TEST_ERROR",
        )

        assert error.status_code == 400
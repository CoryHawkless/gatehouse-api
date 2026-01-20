"""Unit tests for OAuthFlowService."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta, timezone

from gatehouse_app.services.oauth_flow_service import (
    OAuthFlowService,
    OAuthFlowError,
)
from gatehouse_app.services.external_auth_service import OAuthState, ExternalProviderConfig
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.models import User, AuthenticationMethod


@pytest.mark.unit
class TestOAuthFlowService:
    """Tests for OAuthFlowService."""

    @patch('gatehouse_app.services.oauth_flow_service.AuditService')
    def test_initiate_login_flow_success(self, mock_audit, app, db, test_organization):
        """Test initiating login flow successfully."""
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

            with app.test_request_context():
                auth_url, state = OAuthFlowService.initiate_login_flow(
                    provider_type=AuthMethodType.GOOGLE,
                    organization_id=test_organization.id,
                )

                assert auth_url is not None
                assert state is not None
                assert len(state) == 43

                # Verify state was created with correct flow type
                state_record = OAuthState.query.filter_by(state=state).first()
                assert state_record is not None
                assert state_record.flow_type == "login"
                assert state_record.organization_id == test_organization.id

    def test_initiate_login_flow_invalid_redirect_uri(self, app, db, test_organization):
        """Test initiating login flow with invalid redirect URI."""
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

            with app.test_request_context():
                with pytest.raises(OAuthFlowError) as exc_info:
                    OAuthFlowService.initiate_login_flow(
                        provider_type=AuthMethodType.GOOGLE,
                        organization_id=test_organization.id,
                        redirect_uri="http://malicious.com/callback",
                    )

                assert exc_info.value.error_type == "INVALID_REDIRECT_URI"

    @patch('gatehouse_app.services.oauth_flow_service.AuditService')
    def test_initiate_register_flow_success(self, mock_audit, app, db, test_organization):
        """Test initiating register flow successfully."""
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

            with app.test_request_context():
                auth_url, state = OAuthFlowService.initiate_register_flow(
                    provider_type=AuthMethodType.GOOGLE,
                    organization_id=test_organization.id,
                )

                assert auth_url is not None
                assert state is not None

                # Verify state was created with correct flow type
                state_record = OAuthState.query.filter_by(state=state).first()
                assert state_record is not None
                assert state_record.flow_type == "register"

    @patch('gatehouse_app.services.oauth_flow_service.ExternalAuthService.authenticate_with_provider')
    @patch('gatehouse_app.services.oauth_flow_service.AuditService')
    def test_handle_callback_login_flow(
        self, mock_audit, mock_authenticate,
        app, db, test_user, test_organization
    ):
        """Test handling callback for login flow."""
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

            # Create authentication method
            auth_method = AuthenticationMethod(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
                provider_user_id="google-123",
                provider_data={"email": test_user.email},
                verified=True,
            )
            auth_method.save()

            # Create login state
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            # Mock authentication
            mock_authenticate.return_value = (test_user, {"token": "session-token", "expires_in": 86400})

            with app.test_request_context():
                result = OAuthFlowService.handle_callback(
                    provider_type=AuthMethodType.GOOGLE,
                    authorization_code="mock-auth-code",
                    state=state.state,
                    redirect_uri="http://localhost:3000/callback",
                )

                assert result["success"] is True
                assert result["flow_type"] == "login"
                assert result["user"]["id"] == test_user.id
                assert result["session"]["token"] == "session-token"

    @patch('gatehouse_app.services.oauth_flow_service.ExternalAuthService.complete_link_flow')
    @patch('gatehouse_app.services.oauth_flow_service.AuditService')
    def test_handle_callback_link_flow(
        self, mock_audit, mock_complete_link,
        app, db, test_user, test_organization
    ):
        """Test handling callback for link flow."""
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

            # Create link state
            state = OAuthState.create_state(
                flow_type="link",
                provider_type=AuthMethodType.GOOGLE,
                user_id=test_user.id,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            # Mock complete link
            mock_auth_method = Mock()
            mock_auth_method.id = "auth-method-123"
            mock_auth_method.provider_user_id = "google-123"
            mock_auth_method.verified = True
            mock_complete_link.return_value = mock_auth_method

            with app.test_request_context():
                result = OAuthFlowService.handle_callback(
                    provider_type=AuthMethodType.GOOGLE,
                    authorization_code="mock-auth-code",
                    state=state.state,
                    redirect_uri="http://localhost:3000/callback",
                )

                assert result["success"] is True
                assert result["flow_type"] == "link"
                assert result["linked_account"]["id"] == "auth-method-123"

    @patch('gatehouse_app.services.oauth_flow_service.ExternalAuthService._exchange_code')
    @patch('gatehouse_app.services.oauth_flow_service.ExternalAuthService._get_user_info')
    @patch('gatehouse_app.services.oauth_flow_service.ExternalAuthService._encrypt_provider_data')
    @patch('gatehouse_app.services.oauth_flow_service.AuditService')
    @patch('gatehouse_app.services.auth_service.AuthService.create_session')
    def test_handle_callback_register_flow(
        self, mock_create_session, mock_audit, mock_encrypt,
        mock_get_user_info, mock_exchange_code,
        app, db, test_organization
    ):
        """Test handling callback for register flow."""
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

            # Create register state
            state = OAuthState.create_state(
                flow_type="register",
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
                "provider_user_id": "google-new-123",
                "email": "newuser@gmail.com",
                "email_verified": True,
                "name": "New User",
                "picture": "https://example.com/avatar.jpg",
                "raw_data": {},
            }

            mock_encrypt.return_value = {
                "access_token": "mock-access-token",
                "email": "newuser@gmail.com",
                "name": "New User",
            }

            mock_session = Mock()
            mock_session.to_dict.return_value = {"token": "session-token", "expires_in": 86400}
            mock_create_session.return_value = mock_session

            with app.test_request_context():
                result = OAuthFlowService.handle_callback(
                    provider_type=AuthMethodType.GOOGLE,
                    authorization_code="mock-auth-code",
                    state=state.state,
                    redirect_uri="http://localhost:3000/callback",
                )

                assert result["success"] is True
                assert result["flow_type"] == "register"
                assert result["user"]["email"] == "newuser@gmail.com"
                assert result["session"]["token"] == "session-token"

    @patch('gatehouse_app.services.oauth_flow_service.ExternalAuthService._exchange_code')
    @patch('gatehouse_app.services.oauth_flow_service.ExternalAuthService._get_user_info')
    @patch('gatehouse_app.services.oauth_flow_service.AuditService')
    def test_handle_callback_register_flow_email_exists(
        self, mock_audit, mock_get_user_info, mock_exchange_code,
        app, db, test_user, test_organization
    ):
        """Test handling callback for register flow when email already exists."""
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

            # Create register state
            state = OAuthState.create_state(
                flow_type="register",
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

            # Return email that matches existing user
            mock_get_user_info.return_value = {
                "provider_user_id": "google-new-123",
                "email": test_user.email,  # Existing email
                "email_verified": True,
                "name": "Test User",
                "picture": "https://example.com/avatar.jpg",
                "raw_data": {},
            }

            with app.test_request_context():
                with pytest.raises(OAuthFlowError) as exc_info:
                    OAuthFlowService.handle_callback(
                        provider_type=AuthMethodType.GOOGLE,
                        authorization_code="mock-auth-code",
                        state=state.state,
                        redirect_uri="http://localhost:3000/callback",
                    )

                assert exc_info.value.error_type == "EMAIL_EXISTS"

    def test_handle_callback_invalid_state(self, app, db):
        """Test handling callback with invalid state."""
        with app.app_context():
            with app.test_request_context():
                with pytest.raises(OAuthFlowError) as exc_info:
                    OAuthFlowService.handle_callback(
                        provider_type=AuthMethodType.GOOGLE,
                        authorization_code="mock-auth-code",
                        state="invalid-state",
                    )

                assert exc_info.value.error_type == "INVALID_STATE"

    def test_handle_callback_provider_error(self, app, db):
        """Test handling callback with provider error."""
        with app.app_context():
            with app.test_request_context():
                with pytest.raises(OAuthFlowError) as exc_info:
                    OAuthFlowService.handle_callback(
                        provider_type=AuthMethodType.GOOGLE,
                        authorization_code=None,
                        state=None,
                        error="access_denied",
                        error_description="User denied access",
                    )

                assert exc_info.value.error_type == "ACCESS_DENIED"

    def test_handle_callback_unknown_flow_type(self, app, db, test_organization):
        """Test handling callback with unknown flow type."""
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

            # Create state with unknown flow type
            state = OAuthState.create_state(
                flow_type="unknown",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
                redirect_uri="http://localhost:3000/callback",
            )

            with app.test_request_context():
                with pytest.raises(OAuthFlowError) as exc_info:
                    OAuthFlowService.handle_callback(
                        provider_type=AuthMethodType.GOOGLE,
                        authorization_code="mock-auth-code",
                        state=state.state,
                    )

                assert exc_info.value.error_type == "INVALID_FLOW_TYPE"

    def test_validate_state_valid(self, app, db, test_organization):
        """Test validating a valid state."""
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

            # Create state
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
            )

            result = OAuthFlowService.validate_state(state.state)

            assert result is not None
            assert result.id == state.id

    def test_validate_state_invalid(self, app, db):
        """Test validating an invalid state."""
        with app.app_context():
            result = OAuthFlowService.validate_state("nonexistent-state")

            assert result is None

    def test_validate_state_expired(self, app, db, test_organization):
        """Test validating an expired state."""
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

            # Create expired state
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
                lifetime_seconds=-1,
            )

            result = OAuthFlowService.validate_state(state.state)

            assert result is None

    def test_validate_state_used(self, app, db, test_organization):
        """Test validating a used state."""
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

            # Create and mark state as used
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=AuthMethodType.GOOGLE,
                organization_id=test_organization.id,
            )
            state.mark_used()

            result = OAuthFlowService.validate_state(state.state)

            assert result is None


@pytest.mark.unit
class TestOAuthFlowError:
    """Tests for OAuthFlowError exception."""

    def test_error_creation(self):
        """Test creating OAuthFlowError."""
        error = OAuthFlowError(
            message="Test error message",
            error_type="TEST_ERROR",
            status_code=400,
        )

        assert error.message == "Test error message"
        assert error.error_type == "TEST_ERROR"
        assert error.status_code == 400

    def test_error_default_status_code(self):
        """Test OAuthFlowError with default status code."""
        error = OAuthFlowError(
            message="Test error message",
            error_type="TEST_ERROR",
        )

        assert error.status_code == 400
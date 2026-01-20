"""Integration tests for external authentication API flows."""
import pytest
import json
from unittest.mock import patch, Mock

from gatehouse_app.services.external_auth_service import (
    ExternalAuthService,
    ExternalProviderConfig,
    OAuthState,
)
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.utils.constants import AuthMethodType, OrganizationRole
from gatehouse_app.models import User, AuthenticationMethod, OrganizationMember


@pytest.mark.integration
class TestExternalAuthApiFlows:
    """Integration tests for external auth API flows."""

    def test_complete_account_linking_flow(
        self, app, db, client, test_user, test_organization
    ):
        """Test complete account linking flow: initiate → callback → complete."""
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

            # Create organization membership
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            assert login_response.status_code == 200
            token = login_response.get_json()["data"]["token"]

            with patch.object(
                ExternalAuthService, '_exchange_code'
            ) as mock_exchange, patch.object(
                ExternalAuthService, '_get_user_info'
            ) as mock_get_user_info:
                # Mock external provider responses
                mock_exchange.return_value = {
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

                # Step 1: Initiate link flow
                initiate_response = client.post(
                    "/api/v1/auth/external/google/link",
                    json={},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert initiate_response.status_code == 200
                initiate_data = initiate_response.get_json()
                assert "authorization_url" in initiate_data["data"]
                assert "state" in initiate_data["data"]
                state = initiate_data["data"]["state"]

                # Step 2: Simulate callback (complete link flow)
                with patch.object(AuditService, 'log_external_auth_link_completed'):
                    complete_response = client.get(
                        f"/api/v1/auth/external/google/callback",
                        query_string={
                            "code": "mock-auth-code",
                            "state": state,
                        },
                    )
                    # The callback returns 200 on success
                    assert complete_response.status_code == 200

                # Verify account is linked
                auth_method = AuthenticationMethod.query.filter_by(
                    user_id=test_user.id,
                    method_type=AuthMethodType.GOOGLE,
                    provider_user_id="google-123",
                ).first()
                assert auth_method is not None

    def test_complete_login_flow(
        self, app, db, client, test_user, test_organization
    ):
        """Test complete login flow: initiate → callback → authenticate."""
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

            # Create authentication method for user
            auth_method = AuthenticationMethod(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
                provider_user_id="google-123",
                provider_data={"email": test_user.email},
                verified=True,
            )
            auth_method.save()

            with patch.object(
                ExternalAuthService, '_exchange_code'
            ) as mock_exchange, patch.object(
                ExternalAuthService, '_get_user_info'
            ) as mock_get_user_info:
                # Mock external provider responses
                mock_exchange.return_value = {
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

                # Initiate login flow
                login_init_response = client.get(
                    "/api/v1/auth/external/google/authorize",
                    query_string={"flow": "login"},
                )
                assert login_init_response.status_code == 200
                login_init_data = login_init_response.get_json()
                assert "authorization_url" in login_init_data["data"]
                state = login_init_data["data"]["state"]

                # Simulate callback
                callback_response = client.get(
                    f"/api/v1/auth/external/google/callback",
                    query_string={
                        "code": "mock-auth-code",
                        "state": state,
                    },
                )
                assert callback_response.status_code == 200
                callback_data = callback_response.get_json()

                assert callback_data["success"] is True
                assert callback_data["flow_type"] == "login"
                assert "token" in callback_data["data"]
                assert callback_data["data"]["user"]["id"] == test_user.id

    def test_account_unlinking_flow(
        self, app, db, client, test_user, test_organization
    ):
        """Test account unlinking flow."""
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

            # Create organization membership
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Create password auth method
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

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # Unlink Google account
            with patch.object(AuditService, 'log_external_auth_unlink'):
                unlink_response = client.delete(
                    "/api/v1/auth/external/google/unlink",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert unlink_response.status_code == 200
                unlink_data = unlink_response.get_json()
                assert "success" in unlink_data or "message" in unlink_data

            # Verify account is unlinked
            auth_method = AuthenticationMethod.query.filter_by(
                user_id=test_user.id,
                method_type=AuthMethodType.GOOGLE,
            ).first()
            assert auth_method is None

    def test_provider_configuration_crud(
        self, app, db, client, test_user, test_organization
    ):
        """Test provider configuration CRUD operations."""
        with app.app_context():
            # Create organization membership as admin
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.ADMIN,
            )
            member.save()

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # Step 1: Create provider config
            with patch.object(AuditService, 'log_external_auth_config_create'):
                create_response = client.post(
                    "/api/v1/auth/external/google/config",
                    json={
                        "client_id": "new-client-id",
                        "client_secret": "new-client-secret",
                        "scopes": ["openid", "profile", "email"],
                        "redirect_uris": ["http://localhost:3000/callback"],
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert create_response.status_code == 201
                create_data = create_response.get_json()
                assert create_data["data"]["provider_type"] == "google"
                assert create_data["data"]["client_id"] == "new-client-id"

            config_id = create_data["data"]["id"]

            # Step 2: List providers
            list_response = client.get(
                "/api/v1/auth/external/providers",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert list_response.status_code == 200
            list_data = list_response.get_json()
            google_provider = next(
                p for p in list_data["data"]["providers"] if p["id"] == "google"
            )
            assert google_provider["is_configured"] is True

            # Step 3: Get provider config
            get_response = client.get(
                "/api/v1/auth/external/google/config",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert get_response.status_code == 200
            get_data = get_response.get_json()
            assert get_data["data"]["client_id"] == "new-client-id"

            # Step 4: Update provider config
            with patch.object(AuditService, 'log_external_auth_config_update'):
                update_response = client.post(
                    "/api/v1/auth/external/google/config",
                    json={
                        "client_id": "updated-client-id",
                        "client_secret": "updated-client-secret",
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert update_response.status_code == 200
                update_data = update_response.get_json()
                assert update_data["data"]["client_id"] == "updated-client-id"

            # Step 5: Delete provider config
            with patch.object(AuditService, 'log_external_auth_config_delete'):
                delete_response = client.delete(
                    "/api/v1/auth/external/google/config",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert delete_response.status_code == 200

            # Verify deletion
            get_deleted_response = client.get(
                "/api/v1/auth/external/google/config",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert get_deleted_response.status_code == 404

    def test_invalid_state_error(self, app, db, client, test_user, test_organization):
        """Test error handling for invalid OAuth state."""
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

            # Try callback with invalid state
            callback_response = client.get(
                "/api/v1/auth/external/google/callback",
                query_string={
                    "code": "mock-auth-code",
                    "state": "invalid-state",
                },
            )
            assert callback_response.status_code == 400
            callback_data = callback_response.get_json()
            assert callback_data["error_type"] == "INVALID_STATE"

    def test_expired_state_error(self, app, db, client, test_user, test_organization):
        """Test error handling for expired OAuth state."""
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
                lifetime_seconds=-1,  # Already expired
            )

            # Try callback with expired state
            callback_response = client.get(
                "/api/v1/auth/external/google/callback",
                query_string={
                    "code": "mock-auth-code",
                    "state": state.state,
                },
            )
            assert callback_response.status_code == 400
            callback_data = callback_response.get_json()
            assert callback_data["error_type"] == "INVALID_STATE"

    def test_provider_not_configured_error(
        self, app, db, client, test_user, test_organization
    ):
        """Test error handling when provider is not configured."""
        with app.app_context():
            # Create organization membership
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # Try to link with unconfigured provider
            link_response = client.post(
                "/api/v1/auth/external/google/link",
                json={},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert link_response.status_code == 400
            link_data = link_response.get_json()
            assert link_data["error_type"] == "PROVIDER_NOT_CONFIGURED"

    def test_linked_accounts_list(self, app, db, client, test_user, test_organization):
        """Test listing linked accounts."""
        with app.app_context():
            # Create organization membership
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Create authentication methods
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

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # List linked accounts
            list_response = client.get(
                "/api/v1/auth/external/linked-accounts",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert list_response.status_code == 200
            list_data = list_response.get_json()

            assert len(list_data["data"]["linked_accounts"]) == 2
            assert list_data["data"]["unlink_available"] is True

    def test_non_admin_cannot_manage_providers(
        self, app, db, client, test_user, test_organization
    ):
        """Test that non-admin users cannot manage provider configurations."""
        with app.app_context():
            # Create organization membership as regular member
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # Try to create provider config (should fail)
            create_response = client.post(
                "/api/v1/auth/external/google/config",
                json={
                    "client_id": "client-id",
                    "client_secret": "client-secret",
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            assert create_response.status_code == 403
            assert create_response.get_json()["error_type"] == "FORBIDDEN"

    def test_unsupported_provider_error(
        self, app, db, client, test_user, test_organization
    ):
        """Test error handling for unsupported provider."""
        with app.app_context():
            # Create organization membership
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # Try to link with unsupported provider
            link_response = client.post(
                "/api/v1/auth/external/unsupported/link",
                json={},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert link_response.status_code == 400
            link_data = link_response.get_json()
            assert link_data["error_type"] == "UNSUPPORTED_PROVIDER"


@pytest.mark.integration
class TestExternalAuthAuditLogging:
    """Integration tests for audit logging in external auth flows."""

    @patch('gatehouse_app.services.audit_service.AuditService')
    def test_audit_log_on_link_initiated(
        self, mock_audit, app, db, client, test_user, test_organization
    ):
        """Test audit log is created when link flow is initiated."""
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

            # Create organization membership
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # Initiate link flow
            link_response = client.post(
                "/api/v1/auth/external/google/link",
                json={},
                headers={"Authorization": f"Bearer {token}"},
            )

            # Verify audit log was called
            mock_audit.log_external_auth_link_initiated.assert_called_once()

    @patch('gatehouse_app.services.audit_service.AuditService')
    def test_audit_log_on_unlink(
        self, mock_audit, app, db, client, test_user, test_organization
    ):
        """Test audit log is created when account is unlinked."""
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

            # Create organization membership
            member = OrganizationMember(
                user_id=test_user.id,
                organization_id=test_organization.id,
                role=OrganizationRole.MEMBER,
            )
            member.save()

            # Create password auth method
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

            # Login to get token
            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": test_user.email,
                    "password": test_user._test_password,
                },
            )
            token = login_response.get_json()["data"]["token"]

            # Unlink Google account
            unlink_response = client.delete(
                "/api/v1/auth/external/google/unlink",
                headers={"Authorization": f"Bearer {token}"},
            )

            # Verify audit log was called
            mock_audit.log_external_auth_unlink.assert_called_once()
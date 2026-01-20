"""OAuth flow service for handling external authentication flows."""
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from flask import current_app, request, g

from gatehouse_app.extensions import db
from gatehouse_app.models import User, AuthenticationMethod
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.services.external_auth_service import (
    ExternalAuthService,
    ExternalAuthError,
    OAuthState,
    ExternalProviderConfig,
)

logger = logging.getLogger(__name__)


class OAuthFlowError(Exception):
    """Exception for OAuth flow errors."""

    def __init__(self, message: str, error_type: str, status_code: int = 400):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        super().__init__(message)


class OAuthFlowService:
    """Service for managing OAuth authentication flows."""

    @classmethod
    def initiate_login_flow(
        cls,
        provider_type: AuthMethodType,
        organization_id: str = None,
        redirect_uri: str = None,
        state_data: dict = None,
    ) -> Tuple[str, str]:
        """
        Initiate OAuth login flow.

        Args:
            provider_type: The authentication provider type
            organization_id: Optional organization context for SSO
            redirect_uri: Optional custom redirect URI
            state_data: Additional state data to include

        Returns:
            Tuple of (authorization_url, state)
        """
        # Get request context for audit logging
        try:
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get("User-Agent") if request else None
        except RuntimeError:
            ip_address = None
            user_agent = None

        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Get provider config
            config = ExternalAuthService.get_provider_config(organization_id, provider_type)

            # Validate redirect URI
            if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
                raise OAuthFlowError(
                    "Invalid redirect URI",
                    "INVALID_REDIRECT_URI",
                    400,
                )

            # Generate PKCE
            code_verifier = secrets.token_urlsafe(32)
            code_challenge = ExternalAuthService._compute_s256_challenge(code_verifier)

            # Create OAuth state for login flow
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=provider_type,
                organization_id=organization_id,
                redirect_uri=redirect_uri or (config.redirect_uris[0] if config.redirect_uris else None),
                code_verifier=code_verifier,
                code_challenge=code_challenge,
                extra_data=state_data,
                lifetime_seconds=600,
            )

            # Build authorization URL
            auth_url = ExternalAuthService._build_authorization_url(
                config=config,
                state=state,
            )

            logger.info(
                f"OAuth login flow initiated for provider={provider_type_str}, "
                f"org_id={organization_id}, state_id={state.id}"
            )

            return auth_url, state.state

        except ExternalAuthError as e:
            # Log failed initiation
            AuditService.log_action(
                action="external_auth.login.initiated",
                organization_id=organization_id,
                metadata={
                    "provider_type": provider_type_str,
                    "failure_reason": e.error_type,
                    "ip_address": ip_address,
                },
                description=f"OAuth login initiation failed: {e.message}",
                success=False,
                error_message=e.message,
            )
            raise

    @classmethod
    def initiate_register_flow(
        cls,
        provider_type: AuthMethodType,
        organization_id: str = None,
        redirect_uri: str = None,
    ) -> Tuple[str, str]:
        """
        Initiate OAuth registration flow.

        Args:
            provider_type: The authentication provider type
            organization_id: Optional organization context
            redirect_uri: Optional custom redirect URI

        Returns:
            Tuple of (authorization_url, state)
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Get provider config
            config = ExternalAuthService.get_provider_config(organization_id, provider_type)

            # Validate redirect URI
            if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
                raise OAuthFlowError(
                    "Invalid redirect URI",
                    "INVALID_REDIRECT_URI",
                    400,
                )

            # Generate PKCE
            code_verifier = secrets.token_urlsafe(32)
            code_challenge = ExternalAuthService._compute_s256_challenge(code_verifier)

            # Create OAuth state for register flow
            state = OAuthState.create_state(
                flow_type="register",
                provider_type=provider_type,
                organization_id=organization_id,
                redirect_uri=redirect_uri or (config.redirect_uris[0] if config.redirect_uris else None),
                code_verifier=code_verifier,
                code_challenge=code_challenge,
                lifetime_seconds=600,
            )

            # Build authorization URL
            auth_url = ExternalAuthService._build_authorization_url(
                config=config,
                state=state,
            )

            logger.info(
                f"OAuth register flow initiated for provider={provider_type_str}, "
                f"org_id={organization_id}, state_id={state.id}"
            )

            return auth_url, state.state

        except ExternalAuthError as e:
            AuditService.log_action(
                action="external_auth.register.initiated",
                organization_id=organization_id,
                metadata={
                    "provider_type": provider_type_str,
                    "failure_reason": e.error_type,
                },
                description=f"OAuth registration initiation failed: {e.message}",
                success=False,
                error_message=e.message,
            )
            raise

    @classmethod
    def handle_callback(
        cls,
        provider_type: AuthMethodType,
        authorization_code: str,
        state: str,
        redirect_uri: str = None,
        error: str = None,
        error_description: str = None,
    ) -> dict:
        """
        Handle OAuth callback from provider.

        Args:
            provider_type: The authentication provider type
            authorization_code: Authorization code from provider
            state: State parameter from provider
            redirect_uri: Redirect URI used in the flow
            error: Error code if auth failed
            error_description: Human-readable error description

        Returns:
            Dict with flow result
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Get request context for audit logging
        try:
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get("User-Agent") if request else None
        except RuntimeError:
            ip_address = None
            user_agent = None

        # Handle error response from provider
        if error:
            AuditService.log_external_auth_login_failed(
                organization_id=None,
                provider_type=provider_type_str,
                failure_reason=error,
                error_message=error_description or error,
            )
            raise OAuthFlowError(
                error_description or f"OAuth error: {error}",
                error.upper() if error else "OAUTH_ERROR",
                400,
            )

        # Validate state
        state_record = OAuthState.query.filter_by(state=state).first()
        if not state_record or not state_record.is_valid():
            AuditService.log_external_auth_login_failed(
                organization_id=state_record.organization_id if state_record else None,
                provider_type=provider_type_str,
                failure_reason="invalid_state",
                error_message="Invalid or expired OAuth state",
            )
            raise OAuthFlowError(
                "Invalid or expired OAuth state",
                "INVALID_STATE",
                400,
            )

        # Route to appropriate handler based on flow type
        if state_record.flow_type == "login":
            return cls._handle_login_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=redirect_uri or state_record.redirect_uri,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        elif state_record.flow_type == "link":
            return cls._handle_link_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=redirect_uri or state_record.redirect_uri,
            )
        elif state_record.flow_type == "register":
            return cls._handle_register_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=redirect_uri or state_record.redirect_uri,
            )
        else:
            raise OAuthFlowError(
                f"Unknown flow type: {state_record.flow_type}",
                "INVALID_FLOW_TYPE",
                400,
            )

    @classmethod
    def _handle_login_callback(
        cls,
        provider_type: AuthMethodType,
        state_record: OAuthState,
        authorization_code: str,
        redirect_uri: str,
        ip_address: str = None,
        user_agent: str = None,
    ) -> dict:
        """Handle login flow callback."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Authenticate with provider
            user, session_data = ExternalAuthService.authenticate_with_provider(
                provider_type=provider_type,
                organization_id=state_record.organization_id,
                authorization_code=authorization_code,
                state=state_record.state,
                redirect_uri=redirect_uri,
            )

            logger.info(
                f"OAuth login successful for user={user.id}, "
                f"provider={provider_type_str}, org_id={state_record.organization_id}"
            )

            return {
                "success": True,
                "flow_type": "login",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "organization_id": state_record.organization_id,
                },
                "session": session_data,
            }

        except ExternalAuthError as e:
            logger.warning(
                f"OAuth login failed for state={state_record.id}, "
                f"provider={provider_type_str}, error={e.message}"
            )
            raise

    @classmethod
    def _handle_link_callback(
        cls,
        provider_type: AuthMethodType,
        state_record: OAuthState,
        authorization_code: str,
        redirect_uri: str,
    ) -> dict:
        """Handle account linking flow callback."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Complete link flow
            auth_method = ExternalAuthService.complete_link_flow(
                provider_type=provider_type,
                authorization_code=authorization_code,
                state=state_record.state,
                redirect_uri=redirect_uri,
            )

            logger.info(
                f"OAuth link successful for user={state_record.user_id}, "
                f"provider={provider_type_str}, auth_method_id={auth_method.id}"
            )

            return {
                "success": True,
                "flow_type": "link",
                "linked_account": {
                    "id": auth_method.id,
                    "provider_type": provider_type_str,
                    "provider_user_id": auth_method.provider_user_id,
                    "verified": auth_method.verified,
                },
            }

        except ExternalAuthError as e:
            logger.warning(
                f"OAuth link failed for state={state_record.id}, "
                f"provider={provider_type_str}, error={e.message}"
            )
            raise

    @classmethod
    def _handle_register_callback(
        cls,
        provider_type: AuthMethodType,
        state_record: OAuthState,
        authorization_code: str,
        redirect_uri: str,
    ) -> dict:
        """Handle registration flow callback."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Get provider config
            config = ExternalAuthService.get_provider_config(
                state_record.organization_id, provider_type
            )

            # Exchange code for tokens
            tokens = ExternalAuthService._exchange_code(
                config=config,
                code=authorization_code,
                redirect_uri=redirect_uri,
                code_verifier=state_record.code_verifier,
            )

            # Get user info
            user_info = ExternalAuthService._get_user_info(
                config=config,
                access_token=tokens["access_token"],
            )

            # Check if user already exists by email
            existing_user = User.query.filter_by(
                email=user_info["email"]
            ).first()

            if existing_user:
                # User exists - suggest linking
                raise OAuthFlowError(
                    f"An account with email {user_info['email']} already exists. "
                    "Please log in with your password and link your Google account from settings.",
                    "EMAIL_EXISTS",
                    400,
                )

            # Create new user
            user = User(
                email=user_info["email"],
                full_name=user_info.get("name", ""),
                status="active",
            )
            user.save()

            # Create authentication method
            auth_method = AuthenticationMethod(
                user_id=user.id,
                method_type=provider_type,
                provider_user_id=user_info["provider_user_id"],
                provider_data=ExternalAuthService._encrypt_provider_data(tokens, user_info),
                verified=user_info.get("email_verified", False),
                is_primary=True,
            )
            auth_method.save()

            # Mark state as used
            state_record.mark_used()

            # Audit log - registration success
            AuditService.log_action(
                action="user.register",
                user_id=user.id,
                organization_id=state_record.organization_id,
                resource_type="user",
                resource_id=user.id,
                metadata={
                    "provider_type": provider_type_str,
                    "provider_user_id": user_info["provider_user_id"],
                    "auth_method_id": auth_method.id,
                },
                description=f"User registered via {provider_type_str}",
                success=True,
            )

            AuditService.log_external_auth_link_completed(
                user_id=user.id,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                provider_user_id=user_info["provider_user_id"],
                auth_method_id=auth_method.id,
            )

            logger.info(
                f"OAuth registration successful for email={user_info['email']}, "
                f"provider={provider_type_str}, user_id={user.id}"
            )

            # Create session
            from gatehouse_app.services.auth_service import AuthService
            session = AuthService.create_session(
                user=user,
                organization_id=state_record.organization_id,
            )

            return {
                "success": True,
                "flow_type": "register",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "organization_id": state_record.organization_id,
                },
                "session": session.to_dict(),
            }

        except ExternalAuthError as e:
            logger.warning(
                f"OAuth registration failed for state={state_record.id}, "
                f"provider={provider_type_str}, error={e.message}"
            )
            raise

    @classmethod
    def validate_state(cls, state: str) -> Optional[OAuthState]:
        """
        Validate and return OAuth state.

        Args:
            state: The state parameter to validate

        Returns:
            OAuthState if valid, None otherwise
        """
        state_record = OAuthState.query.filter_by(state=state).first()
        if state_record and state_record.is_valid():
            return state_record
        return None

    @classmethod
    def cleanup_expired_states(cls):
        """Remove expired OAuth states."""
        OAuthState.cleanup_expired()
        logger.info("Expired OAuth states cleaned up")

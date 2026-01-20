"""External authentication provider service."""
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from flask import current_app

from gatehouse_app.extensions import db
from gatehouse_app.models import User, AuthenticationMethod
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class ExternalAuthError(Exception):
    """Base exception for external auth errors."""

    def __init__(self, message: str, error_type: str, status_code: int = 400):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        super().__init__(message)


class OAuthState(BaseModel):
    """Temporary OAuth state storage for secure flow management."""

    __tablename__ = "oauth_states"

    # State identifier (used in OAuth redirects)
    state = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # Flow type
    flow_type = db.Column(db.String(50), nullable=False)  # 'link', 'login', 'register'

    # User context
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=True, index=True
    )

    # Provider information
    provider_type = db.Column(db.String(50), nullable=False)

    # OAuth parameters
    nonce = db.Column(db.String(128), nullable=True)
    code_verifier = db.Column(db.String(128), nullable=True)
    code_challenge = db.Column(db.String(128), nullable=True)
    redirect_uri = db.Column(db.String(2048), nullable=True)

    # Additional state data
    extra_data = db.Column(db.JSON, nullable=True)

    # Expiration
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    # Status
    used = db.Column(db.Boolean, default=False, nullable=False)

    @classmethod
    def create_state(
        cls,
        flow_type: str,
        provider_type: AuthMethodType,
        user_id: str = None,
        organization_id: str = None,
        redirect_uri: str = None,
        nonce: str = None,
        code_verifier: str = None,
        code_challenge: str = None,
        extra_data: dict = None,
        lifetime_seconds: int = 600,
    ) -> "OAuthState":
        """Create a new OAuth state record."""
        state = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds)

        return cls.create(
            state=state,
            flow_type=flow_type,
            provider_type=provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type,
            user_id=user_id,
            organization_id=organization_id,
            redirect_uri=redirect_uri,
            nonce=nonce or secrets.token_urlsafe(16),
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            extra_data=extra_data,
            expires_at=expires_at,
        )

    def is_valid(self) -> bool:
        """Check if state is still valid."""
        return (
            not self.used
            and self.expires_at
            and self.expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)
        )

    def mark_used(self):
        """Mark state as used."""
        self.used = True
        self.save()

    @classmethod
    def cleanup_expired(cls):
        """Remove expired states."""
        cls.query.filter(cls.expires_at < datetime.now(timezone.utc)).delete()
        db.session.commit()


class ExternalProviderConfig(BaseModel):
    """OAuth provider configuration per organization."""

    __tablename__ = "external_provider_configs"

    # Organization reference
    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Provider type
    provider_type = db.Column(db.String(50), nullable=False, index=True)

    # OAuth credentials (client_secret is encrypted)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret_encrypted = db.Column(db.String(512), nullable=True)

    # Provider endpoints
    auth_url = db.Column(db.String(2048), nullable=False)
    token_url = db.Column(db.String(2048), nullable=False)
    userinfo_url = db.Column(db.String(2048), nullable=True)
    jwks_url = db.Column(db.String(2048), nullable=True)

    # Configuration
    scopes = db.Column(db.JSON, nullable=False, default=list)
    redirect_uris = db.Column(db.JSON, nullable=False, default=list)

    # Provider-specific settings
    settings = db.Column(db.JSON, nullable=True)

    # Status
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    organization = db.relationship(
        "Organization", back_populates="external_provider_configs"
    )

    # Indexes
    __table_args__ = (
        db.Index("idx_provider_config_org", "organization_id", "provider_type"),
        db.UniqueConstraint(
            "organization_id",
            "provider_type",
            name="uix_org_provider_type",
        ),
    )

    def get_client_secret(self) -> str:
        """Decrypt and return client secret."""
        from gatehouse_app.utils.encryption import decrypt
        if self.client_secret_encrypted:
            return decrypt(self.client_secret_encrypted)
        return None

    def set_client_secret(self, secret: str):
        """Encrypt and store client secret."""
        from gatehouse_app.utils.encryption import encrypt
        self.client_secret_encrypted = encrypt(secret)

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        """Check if redirect URI is allowed."""
        return uri in (self.redirect_uris or [])

    def to_dict(self, include_secrets: bool = False) -> dict:
        """Convert to dictionary."""
        data = {
            "id": self.id,
            "organization_id": self.organization_id,
            "provider_type": self.provider_type,
            "client_id": self.client_id,
            "auth_url": self.auth_url,
            "token_url": self.token_url,
            "userinfo_url": self.userinfo_url,
            "scopes": self.scopes,
            "redirect_uris": self.redirect_uris,
            "is_active": self.is_active,
            "settings": self.settings,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_secrets and self.client_secret_encrypted:
            data["client_secret"] = self.get_client_secret()
        return data


class ExternalAuthService:
    """Service for external authentication operations."""

    @classmethod
    def get_provider_config(
        cls,
        organization_id: str,
        provider_type: AuthMethodType,
    ) -> ExternalProviderConfig:
        """Get provider configuration for organization."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type
        config = ExternalProviderConfig.query.filter_by(
            organization_id=organization_id,
            provider_type=provider_type_str,
            is_active=True,
        ).first()

        if not config:
            raise ExternalAuthError(
                f"{provider_type_str.title()} OAuth is not configured for this organization",
                "PROVIDER_NOT_CONFIGURED",
                400,
            )

        return config

    @classmethod
    def initiate_link_flow(
        cls,
        user_id: str,
        provider_type: AuthMethodType,
        organization_id: str,
        redirect_uri: str = None,
    ) -> Tuple[str, str]:
        """
        Initiate account linking flow.

        Returns:
            Tuple of (redirect_url, state)
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Get provider config
        config = cls.get_provider_config(organization_id, provider_type)

        # Validate redirect URI
        if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
            raise ExternalAuthError(
                "Invalid redirect URI",
                "INVALID_REDIRECT_URI",
                400,
            )

        # Generate PKCE
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = cls._compute_s256_challenge(code_verifier)

        # Create OAuth state
        state = OAuthState.create_state(
            flow_type="link",
            provider_type=provider_type,
            user_id=user_id,
            organization_id=organization_id,
            redirect_uri=redirect_uri or config.redirect_uris[0],
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            lifetime_seconds=600,
        )

        # Build authorization URL (simplified - in production would use provider-specific implementation)
        auth_url = cls._build_authorization_url(
            config=config,
            state=state,
        )

        # Audit log - link initiated
        AuditService.log_external_auth_link_initiated(
            user_id=user_id,
            organization_id=organization_id,
            provider_type=provider_type_str,
            state_id=state.id,
        )

        return auth_url, state.state

    @classmethod
    def complete_link_flow(
        cls,
        provider_type: AuthMethodType,
        authorization_code: str,
        state: str,
        redirect_uri: str,
    ) -> AuthenticationMethod:
        """Complete account linking flow."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Validate state
        state_record = OAuthState.query.filter_by(state=state).first()
        if not state_record or not state_record.is_valid():
            AuditService.log_external_auth_link_failed(
                user_id=None,
                organization_id=None,
                provider_type=provider_type_str,
                error_message="Invalid or expired OAuth state",
                failure_reason="invalid_state",
            )
            raise ExternalAuthError(
                "Invalid or expired OAuth state",
                "INVALID_STATE",
                400,
            )

        if state_record.flow_type != "link":
            AuditService.log_external_auth_link_failed(
                user_id=state_record.user_id,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                error_message="Invalid flow type for this operation",
                failure_reason="invalid_flow_type",
            )
            raise ExternalAuthError(
                "Invalid flow type for this operation",
                "INVALID_FLOW_TYPE",
                400,
            )

        if state_record.provider_type != provider_type_str:
            AuditService.log_external_auth_link_failed(
                user_id=state_record.user_id,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                error_message="Provider mismatch",
                failure_reason="provider_mismatch",
            )
            raise ExternalAuthError(
                "Provider mismatch",
                "PROVIDER_MISMATCH",
                400,
            )

        # Get provider config
        config = cls.get_provider_config(
            state_record.organization_id, provider_type
        )

        # Exchange code for tokens (simplified - in production would use provider-specific implementation)
        tokens = cls._exchange_code(
            config=config,
            code=authorization_code,
            redirect_uri=redirect_uri,
            code_verifier=state_record.code_verifier,
        )

        # Get user info
        user_info = cls._get_user_info(
            config=config,
            access_token=tokens["access_token"],
        )

        # Get user
        user = User.query.get(state_record.user_id)
        if not user:
            AuditService.log_external_auth_link_failed(
                user_id=None,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                error_message="User not found",
                failure_reason="user_not_found",
            )
            raise ExternalAuthError(
                "User not found",
                "USER_NOT_FOUND",
                400,
            )

        # Create or update authentication method
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=provider_type,
            provider_user_id=user_info["provider_user_id"],
        ).first()

        if auth_method:
            # Update existing
            auth_method.provider_data = cls._encrypt_provider_data(tokens, user_info)
            auth_method.verified = user_info.get("email_verified", False)
            auth_method.last_used_at = datetime.utcnow()
            auth_method.save()
        else:
            # Create new
            auth_method = AuthenticationMethod(
                user_id=user.id,
                method_type=provider_type,
                provider_user_id=user_info["provider_user_id"],
                provider_data=cls._encrypt_provider_data(tokens, user_info),
                verified=user_info.get("email_verified", False),
                is_primary=False,
                last_used_at=datetime.utcnow(),
            )
            auth_method.save()

        # Mark state as used
        state_record.mark_used()

        # Audit log - link completed
        AuditService.log_external_auth_link_completed(
            user_id=user.id,
            organization_id=state_record.organization_id,
            provider_type=provider_type_str,
            provider_user_id=user_info["provider_user_id"],
            auth_method_id=auth_method.id,
        )

        return auth_method

    @classmethod
    def authenticate_with_provider(
        cls,
        provider_type: AuthMethodType,
        organization_id: str,
        authorization_code: str,
        state: str,
        redirect_uri: str,
    ) -> Tuple[User, dict]:
        """Authenticate user with external provider and return tokens."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Validate state
        state_record = OAuthState.query.filter_by(state=state).first()
        if not state_record or not state_record.is_valid():
            AuditService.log_external_auth_login_failed(
                organization_id=organization_id,
                provider_type=provider_type_str,
                failure_reason="invalid_state",
                error_message="Invalid or expired OAuth state",
            )
            raise ExternalAuthError(
                "Invalid or expired OAuth state",
                "INVALID_STATE",
                400,
            )

        # Get provider config
        config = cls.get_provider_config(organization_id, provider_type)

        # Exchange code for tokens
        tokens = cls._exchange_code(
            config=config,
            code=authorization_code,
            redirect_uri=redirect_uri,
            code_verifier=state_record.code_verifier,
        )

        # Get user info
        user_info = cls._get_user_info(
            config=config,
            access_token=tokens["access_token"],
        )

        # Look up user by provider_user_id
        auth_method = AuthenticationMethod.query.filter_by(
            method_type=provider_type,
            provider_user_id=user_info["provider_user_id"],
        ).first()

        if not auth_method:
            # Check if email matches existing user
            existing_user = User.query.filter_by(
                email=user_info["email"]
            ).first()

            if existing_user:
                AuditService.log_external_auth_login_failed(
                    organization_id=organization_id,
                    provider_type=provider_type_str,
                    provider_user_id=user_info["provider_user_id"],
                    email=user_info["email"],
                    failure_reason="email_exists",
                    error_message=f"An account with email {user_info['email']} already exists",
                )
                raise ExternalAuthError(
                    f"An account with email {user_info['email']} already exists. "
                    "Please log in with your password and link your Google account from settings.",
                    "EMAIL_EXISTS",
                    400,
                )

            AuditService.log_external_auth_login_failed(
                organization_id=organization_id,
                provider_type=provider_type_str,
                provider_user_id=user_info["provider_user_id"],
                email=user_info["email"],
                failure_reason="account_not_found",
                error_message="No Gatehouse account matches this external account",
            )
            raise ExternalAuthError(
                "No Gatehouse account matches this external account. Please register first.",
                "ACCOUNT_NOT_FOUND",
                400,
            )

        user = auth_method.user

        # Update tokens
        auth_method.provider_data = cls._encrypt_provider_data(tokens, user_info)
        auth_method.last_used_at = datetime.utcnow()
        auth_method.save()

        # Mark state as used
        state_record.mark_used()

        # Create session
        from gatehouse_app.services.auth_service import AuthService
        session = AuthService.create_session(
            user=user,
            organization_id=organization_id,
        )

        # Audit log - login success
        AuditService.log_external_auth_login(
            user_id=user.id,
            organization_id=organization_id,
            provider_type=provider_type_str,
            provider_user_id=user_info["provider_user_id"],
            auth_method_id=auth_method.id,
            session_id=session.id,
        )

        return user, session.to_dict()

    @classmethod
    def unlink_provider(
        cls,
        user_id: str,
        provider_type: AuthMethodType,
        organization_id: str = None,
    ) -> bool:
        """Unlink external provider from user account."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user_id,
            method_type=provider_type,
        ).first()

        if not auth_method:
            raise ExternalAuthError(
                f"Provider not linked",
                "PROVIDER_NOT_LINKED",
                400,
            )

        # Check if this is the last auth method
        other_methods = AuthenticationMethod.query.filter_by(
            user_id=user_id,
        ).count()

        if other_methods <= 1:
            raise ExternalAuthError(
                "Cannot unlink the last authentication method",
                "CANNOT_UNLINK_LAST",
                400,
            )

        provider_user_id = auth_method.provider_user_id
        auth_method_id = auth_method.id
        auth_method.delete()

        # Audit log - unlink
        AuditService.log_external_auth_unlink(
            user_id=user_id,
            organization_id=organization_id,
            provider_type=provider_type_str,
            provider_user_id=provider_user_id,
            auth_method_id=auth_method_id,
        )

        return True

    @classmethod
    def get_linked_accounts(cls, user_id: str) -> list:
        """Get all linked external accounts for user."""
        methods = AuthenticationMethod.query.filter_by(
            user_id=user_id,
        ).all()

        external_providers = [
            AuthMethodType.GOOGLE,
            AuthMethodType.GITHUB,
            AuthMethodType.MICROSOFT,
        ]

        return [
            {
                "id": m.id,
                "provider_type": m.method_type.value if hasattr(m.method_type, 'value') else str(m.method_type),
                "provider_user_id": m.provider_user_id,
                "email": m.provider_data.get("email") if m.provider_data else None,
                "name": m.provider_data.get("name") if m.provider_data else None,
                "picture": m.provider_data.get("picture") if m.provider_data else None,
                "verified": m.verified,
                "linked_at": m.created_at.isoformat() if m.created_at else None,
                "last_used_at": m.last_used_at.isoformat() if m.last_used_at else None,
            }
            for m in methods
            if m.method_type in external_providers or str(m.method_type) in [p.value for p in external_providers]
        ]

    @staticmethod
    def _compute_s256_challenge(verifier: str) -> str:
        """Compute S256 code challenge from verifier."""
        import hashlib
        import base64

        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    @staticmethod
    def _build_authorization_url(config: ExternalProviderConfig, state: OAuthState) -> str:
        """Build authorization URL (simplified - provider-specific in production)."""
        from urllib.parse import urlencode

        params = {
            "client_id": config.client_id,
            "redirect_uri": state.redirect_uri,
            "response_type": "code",
            "scope": " ".join(config.scopes or ["openid", "profile", "email"]),
            "state": state.state,
            "access_type": config.settings.get("access_type", "offline") if config.settings else "offline",
            "prompt": config.settings.get("prompt", "consent") if config.settings else "consent",
        }

        if state.nonce:
            params["nonce"] = state.nonce

        if state.code_challenge:
            params["code_challenge"] = state.code_challenge
            params["code_challenge_method"] = "S256"

        return f"{config.auth_url}?{urlencode(params)}"

    @staticmethod
    def _exchange_code(config: ExternalProviderConfig, code: str, redirect_uri: str, code_verifier: str = None) -> dict:
        """Exchange authorization code for tokens (simplified - provider-specific in production)."""
        import requests

        data = {
            "client_id": config.client_id,
            "client_secret": config.get_client_secret(),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        if code_verifier:
            data["code_verifier"] = code_verifier

        response = requests.post(config.token_url, data=data)
        response.raise_for_status()

        return response.json()

    @staticmethod
    def _get_user_info(config: ExternalProviderConfig, access_token: str) -> dict:
        """Get user info from provider (simplified - provider-specific in production)."""
        import requests

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(config.userinfo_url, headers=headers)
        response.raise_for_status()

        data = response.json()

        # Standardize user info
        return {
            "provider_user_id": data.get("sub"),
            "email": data.get("email"),
            "email_verified": data.get("email_verified", False),
            "name": data.get("name"),
            "first_name": data.get("given_name"),
            "last_name": data.get("family_name"),
            "picture": data.get("picture"),
            "raw_data": data,
        }

    @staticmethod
    def _encrypt_provider_data(tokens: dict, user_info: dict) -> dict:
        """Encrypt and store provider tokens and user info."""
        from gatehouse_app.utils.encryption import encrypt

        result = {
            "access_token": encrypt(tokens.get("access_token")) if tokens.get("access_token") else None,
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": tokens.get("expires_in"),
            "refresh_token": encrypt(tokens.get("refresh_token")) if tokens.get("refresh_token") else None,
            "scope": tokens.get("scope", []),
            "id_token": encrypt(tokens.get("id_token")) if tokens.get("id_token") else None,
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "picture": user_info.get("picture"),
            "raw_data": user_info.get("raw_data", {}),
        }

        return result

    @staticmethod
    def _decrypt_provider_data(provider_data: dict) -> dict:
        """
        Decrypt provider tokens from stored data.
        
        This method handles backward compatibility with existing data where
        access_token may be stored in plain text (unencrypted).
        """
        from gatehouse_app.utils.encryption import decrypt

        if not provider_data:
            return {}

        result = {
            "token_type": provider_data.get("token_type", "Bearer"),
            "expires_in": provider_data.get("expires_in"),
            "scope": provider_data.get("scope", []),
            "email": provider_data.get("email"),
            "name": provider_data.get("name"),
            "picture": provider_data.get("picture"),
            "raw_data": provider_data.get("raw_data", {}),
        }

        # Decrypt access_token with backward compatibility
        access_token = provider_data.get("access_token")
        if access_token:
            # Try to decrypt - if it fails, assume it's plain text (old data)
            try:
                result["access_token"] = decrypt(access_token)
            except Exception:
                # Access token is plain text (pre-encryption data)
                result["access_token"] = access_token
        else:
            result["access_token"] = None

        # Decrypt refresh_token
        refresh_token = provider_data.get("refresh_token")
        if refresh_token:
            try:
                result["refresh_token"] = decrypt(refresh_token)
            except Exception:
                result["refresh_token"] = refresh_token
        else:
            result["refresh_token"] = None

        # Decrypt id_token
        id_token = provider_data.get("id_token")
        if id_token:
            try:
                result["id_token"] = decrypt(id_token)
            except Exception:
                result["id_token"] = id_token
        else:
            result["id_token"] = None

        return result
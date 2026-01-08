"""OIDC Service - Main OIDC service layer."""
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from flask import current_app, g

from app.extensions import db
from app.models import (
    User, OIDCClient, OIDCAuthCode, OIDCRefreshToken,
    OIDCSession, OIDCTokenMetadata
)
from app.exceptions.validation_exceptions import (
    ValidationError, NotFoundError, BadRequestError
)
from app.exceptions.auth_exceptions import UnauthorizedError, InvalidTokenError
from app.services.oidc_token_service import OIDCTokenService
from app.services.oidc_session_service import OIDCSessionService
from app.services.oidc_audit_service import OIDCAuditService
from app.services.oidc_jwks_service import OIDCJWKSService


class OIDCError(Exception):
    """Base exception for OIDC errors."""
    
    def __init__(self, error: str, error_description: str = None, status_code: int = 400):
        self.error = error
        self.error_description = error_description
        self.status_code = status_code


class InvalidClientError(OIDCError):
    """Raised when client authentication fails."""
    
    def __init__(self, error_description: str = "Invalid client"):
        super().__init__("invalid_client", error_description, 401)


class InvalidGrantError(OIDCError):
    """Raised when grant is invalid."""
    
    def __init__(self, error_description: str = "Invalid grant"):
        super().__init__("invalid_grant", error_description, 400)


class InvalidRequestError(OIDCError):
    """Raised when request is malformed."""
    
    def __init__(self, error_description: str = "Invalid request"):
        super().__init__("invalid_request", error_description, 400)


class OIDCService:
    """Main OIDC service handling all OpenID Connect operations.
    
    This service provides:
    - Authorization code generation and validation
    - Token generation (access, refresh, ID tokens)
    - Token refresh with rotation
    - Token validation and introspection
    - Token revocation
    """
    
    @staticmethod
    def _generate_code() -> str:
        """Generate a secure authorization code.
        
        Returns:
            URL-safe base64 encoded code
        """
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def _hash_value(value: str) -> str:
        """Hash a value for secure storage.
        
        Args:
            value: Value to hash
        
        Returns:
            SHA256 hash
        """
        return hashlib.sha256(value.encode()).hexdigest()
    
    @classmethod
    def generate_authorization_code(
        cls,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: list,
        state: str,
        nonce: str,
        code_challenge: str = None,
        code_challenge_method: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> str:
        """Generate an authorization code for the auth code flow.
        
        Args:
            client_id: OIDC client ID
            user_id: User ID
            redirect_uri: Redirect URI
            scope: Requested scopes
            state: State parameter
            nonce: Nonce for ID token
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method ("S256" or "plain")
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Authorization code string
        
        Raises:
            ValidationError: If parameters are invalid
            NotFoundError: If client not found
        """
        # Validate client exists and is active
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            raise NotFoundError("Client not found")
        
        if not client.is_active:
            raise ValidationError("Client is not active")
        
        # Validate redirect URI
        if not client.is_redirect_uri_allowed(redirect_uri):
            raise ValidationError("Invalid redirect_uri")
        
        # Validate scopes
        allowed_scopes = client.scopes or []
        valid_scopes = [s for s in scope if s in allowed_scopes]
        
        if not valid_scopes:
            raise ValidationError("Invalid scopes")
        
        # Generate authorization code
        code = cls._generate_code()
        code_hash = cls._hash_value(code)
        
        # Create auth code record
        auth_code = OIDCAuthCode.create_code(
            client_id=client.id,
            user_id=user_id,
            code_hash=code_hash,
            redirect_uri=redirect_uri,
            scope=valid_scopes,
            nonce=nonce,
            code_verifier=code_challenge,  # Store for validation
            ip_address=ip_address,
            user_agent=user_agent,
            lifetime_seconds=600,  # 10 minutes
        )
        
        # Log authorization event
        OIDCAuditService.log_authorization_event(
            client_id=client_id,
            user_id=user_id,
            success=True,
            redirect_uri=redirect_uri,
            scope=valid_scopes,
        )
        
        return code
    
    @classmethod
    def validate_authorization_code(
        cls,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Tuple[Dict, User]:
        """Validate and consume an authorization code.
        
        Args:
            code: Authorization code
            client_id: OIDC client ID
            redirect_uri: Redirect URI
            code_verifier: PKCE code verifier (required if PKCE was used)
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Tuple of (claims dict, User instance)
        
        Raises:
            InvalidGrantError: If code is invalid
            ValidationError: If PKCE validation fails
        """
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            raise InvalidGrantError("Invalid client")
        
        # Hash the provided code and find matching auth code
        code_hash = cls._hash_value(code)
        auth_code = OIDCAuthCode.query.filter_by(
            code_hash=code_hash,
            client_id=client.id,
            deleted_at=None
        ).first()
        
        if not auth_code:
            OIDCAuditService.log_authorization_event(
                client_id=client_id,
                success=False,
                error_code="invalid_grant",
                error_description="Invalid or expired authorization code",
            )
            raise InvalidGrantError("Invalid or expired authorization code")
        
        # Check if already used
        if auth_code.is_used:
            OIDCAuditService.log_authorization_event(
                client_id=client_id,
                user_id=auth_code.user_id,
                success=False,
                error_code="invalid_grant",
                error_description="Authorization code already used",
            )
            raise InvalidGrantError("Authorization code already used")
        
        # Check expiration
        if auth_code.is_expired():
            OIDCAuditService.log_authorization_event(
                client_id=client_id,
                user_id=auth_code.user_id,
                success=False,
                error_code="invalid_grant",
                error_description="Authorization code expired",
            )
            raise InvalidGrantError("Authorization code expired")
        
        # Validate redirect URI
        if auth_code.redirect_uri != redirect_uri:
            raise InvalidGrantError("Invalid redirect_uri")
        
        # Validate PKCE if required
        if client.require_pkce and auth_code.code_verifier:
            if not code_verifier:
                raise ValidationError("code_verifier is required")
            
            # Verify code verifier
            expected_challenge = cls._compute_code_challenge(code_verifier, "S256")
            if expected_challenge != auth_code.code_verifier:
                OIDCAuditService.log_authorization_event(
                    client_id=client_id,
                    user_id=auth_code.user_id,
                    success=False,
                    error_code="invalid_grant",
                    error_description="Invalid code_verifier",
                )
                raise InvalidGrantError("Invalid code_verifier")
        
        # Mark code as used
        auth_code.mark_as_used()
        
        # Get user
        user = User.query.get(auth_code.user_id)
        if not user:
            raise InvalidGrantError("User not found")
        
        claims = {
            "user_id": auth_code.user_id,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": auth_code.scope,
            "nonce": auth_code.nonce,
        }
        
        return claims, user
    
    @classmethod
    def _compute_code_challenge(cls, verifier: str, method: str = "S256") -> str:
        """Compute PKCE code challenge from verifier.
        
        Args:
            verifier: Code verifier
            method: Challenge method
        
        Returns:
            Code challenge
        """
        import hashlib
        import base64
        
        if method == "S256":
            digest = hashlib.sha256(verifier.encode()).digest()
            return base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return verifier
    
    @classmethod
    def generate_tokens(
        cls,
        client_id: str,
        user_id: str,
        scope: list,
        nonce: str = None,
        refresh_token: str = None,
        ip_address: str = None,
        user_agent: str = None,
        auth_time: int = None
    ) -> Dict:
        """Generate access token, ID token, and refresh token.
        
        Args:
            client_id: OIDC client ID
            user_id: User ID
            scope: Granted scopes
            nonce: Nonce for ID token
            refresh_token: Existing refresh token (for rotation)
            ip_address: Client IP address
            user_agent: Client user agent
            auth_time: Authentication time
        
        Returns:
            Dictionary with tokens
        """
        import hashlib
        
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            raise InvalidClientError()
        
        # Generate access token
        access_token_jti = OIDCTokenService._generate_jti()
        access_token = OIDCTokenService.create_access_token(
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            jti=access_token_jti,
        )
        
        # Generate ID token
        id_token = OIDCTokenService.create_id_token(
            client_id=client_id,
            user_id=user_id,
            nonce=nonce,
            scope=scope,
            access_token=access_token,
            auth_time=auth_time,
        )
        
        # Generate or rotate refresh token
        if "refresh_token" in (client.grant_types or []):
            if refresh_token:
                # Rotate existing refresh token
                refresh_token_obj = OIDCRefreshToken.query.filter_by(
                    token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
                    deleted_at=None
                ).first()
                
                if refresh_token_obj and refresh_token_obj.is_valid():
                    # Create new refresh token
                    new_refresh, new_hash = OIDCTokenService.create_refresh_token(
                        client_id=client_id,
                        user_id=user_id,
                        scope=scope,
                        access_token_id=access_token_jti,
                    )
                    
                    # Rotate in database
                    refresh_token_obj.rotate(new_hash)
                    final_refresh_token = new_refresh
                else:
                    final_refresh_token = None
            else:
                # Create new refresh token
                final_refresh_token, refresh_hash = OIDCTokenService.create_refresh_token(
                    client_id=client_id,
                    user_id=user_id,
                    scope=scope,
                    access_token_id=access_token_jti,
                )
                
                # Store refresh token
                OIDCRefreshToken.create_token(
                    client_id=client.id,
                    user_id=user_id,
                    token_hash=refresh_hash,
                    scope=scope,
                    access_token_id=access_token_jti,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    lifetime_seconds=client.refresh_token_lifetime or 2592000,
                )
        else:
            final_refresh_token = None
        
        # Store token metadata
        client_db_id = client.id
        
        # Access token metadata
        OIDCTokenMetadata.create_metadata(
            client_id=client_db_id,
            user_id=user_id,
            token_type="access_token",
            token_jti=access_token_jti,
            expires_at=datetime.utcnow() + timedelta(seconds=client.access_token_lifetime or 3600),
        )
        
        # ID token metadata (using access token JTI as reference)
        id_token_jti = OIDCTokenService._generate_jti()
        OIDCTokenMetadata.create_metadata(
            client_id=client_db_id,
            user_id=user_id,
            token_type="id_token",
            token_jti=id_token_jti,
            expires_at=datetime.utcnow() + timedelta(seconds=client.id_token_lifetime or 3600),
        )
        
        # Log token event
        OIDCAuditService.log_token_event(
            client_id=client_id,
            user_id=user_id,
            token_type="access_token",
            success=True,
            grant_type="authorization_code",
            scopes=scope,
        )
        
        result = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime or 3600,
            "id_token": id_token,
        }
        
        if final_refresh_token:
            result["refresh_token"] = final_refresh_token
        
        return result
    
    @classmethod
    def refresh_access_token(
        cls,
        refresh_token: str,
        client_id: str,
        scope: list = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Dict:
        """Refresh an access token with token rotation.
        
        Args:
            refresh_token: The refresh token
            client_id: OIDC client ID
            scope: Optional scope override
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Dictionary with new tokens
        
        Raises:
            InvalidGrantError: If refresh token is invalid
        """
        import hashlib
        
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            raise InvalidClientError()
        
        # Find refresh token
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        refresh_token_obj = OIDCRefreshToken.query.filter_by(
            token_hash=token_hash,
            deleted_at=None
        ).first()
        
        if not refresh_token_obj:
            OIDCAuditService.log_token_event(
                client_id=client_id,
                success=False,
                error_code="invalid_grant",
                error_description="Invalid refresh token",
            )
            raise InvalidGrantError("Invalid refresh token")
        
        # Check if valid
        if not refresh_token_obj.is_valid():
            OIDCAuditService.log_token_event(
                client_id=client_id,
                user_id=refresh_token_obj.user_id,
                success=False,
                error_code="invalid_grant",
                error_description="Refresh token expired or revoked",
            )
            raise InvalidGrantError("Refresh token expired or revoked")
        
        # Validate client matches
        if refresh_token_obj.client_id != client.id:
            raise InvalidGrantError("Client mismatch")
        
        # Get original scope or use provided
        granted_scope = scope or (refresh_token_obj.scope or [])
        
        # Generate new access token
        access_token_jti = OIDCTokenService._generate_jti()
        access_token = OIDCTokenService.create_access_token(
            client_id=client_id,
            user_id=refresh_token_obj.user_id,
            scope=granted_scope,
            jti=access_token_jti,
        )
        
        # Generate new ID token
        id_token = OIDCTokenService.create_id_token(
            client_id=client_id,
            user_id=refresh_token_obj.user_id,
            scope=granted_scope,
            access_token=access_token,
        )
        
        # Rotate refresh token
        new_refresh, new_hash = OIDCTokenService.create_refresh_token(
            client_id=client_id,
            user_id=refresh_token_obj.user_id,
            scope=granted_scope,
            access_token_id=access_token_jti,
        )
        
        refresh_token_obj.rotate(new_hash)
        
        # Store new token metadata
        OIDCTokenMetadata.create_metadata(
            client_id=client.id,
            user_id=refresh_token_obj.user_id,
            token_type="access_token",
            token_jti=access_token_jti,
            expires_at=datetime.utcnow() + timedelta(seconds=client.access_token_lifetime or 3600),
        )
        
        # Log refresh event
        OIDCAuditService.log_token_event(
            client_id=client_id,
            user_id=refresh_token_obj.user_id,
            token_type="access_token",
            success=True,
            grant_type="refresh_token",
            scopes=granted_scope,
        )
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime or 3600,
            "id_token": id_token,
            "refresh_token": new_refresh,
        }
    
    @classmethod
    def validate_access_token(cls, token: str, client_id: str = None) -> Dict:
        """Validate an access token and return its claims.
        
        Args:
            token: JWT access token
            client_id: Optional client ID to validate audience
        
        Returns:
            Token claims
        
        Raises:
            InvalidTokenError: If token is invalid
        """
        try:
            claims = OIDCTokenService.validate_access_token(token, client_id)
            return claims
        except Exception as e:
            OIDCAuditService.log_event(
                event_type="token_validation",
                client_id=client_id,
                success=False,
                error_code="invalid_token",
                error_description=str(e),
            )
            raise InvalidTokenError(str(e))
    
    @classmethod
    def revoke_token(
        cls,
        token: str,
        client_id: str,
        token_type_hint: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> bool:
        """Revoke a token.
        
        Args:
            token: Token to revoke
            client_id: OIDC client ID
            token_type_hint: Hint about token type
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            True if token was revoked
        """
        import hashlib
        
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            raise InvalidClientError()
        
        revoked = False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Try to revoke as refresh token
        if token_type_hint in (None, "refresh_token"):
            refresh_token = OIDCRefreshToken.query.filter_by(
                token_hash=token_hash,
                deleted_at=None
            ).first()
            
            if refresh_token:
                refresh_token.revoke(reason="revoked_by_client")
                revoked = True
                
                OIDCAuditService.log_token_revocation_event(
                    client_id=client_id,
                    user_id=refresh_token.user_id,
                    token_type="refresh_token",
                    reason="revoked_by_client",
                )
        
        # Try to revoke as access token (JTI lookup)
        if not revoked or token_type_hint in (None, "access_token"):
            try:
                # Decode token to get JTI
                claims = OIDCTokenService.decode_token(token)
                jti = claims.get("jti")
                
                if jti:
                    revoked_at = OIDCTokenMetadata.revoke_by_jti(
                        jti,
                        reason="revoked_by_client"
                    )
                    if revoked_at:
                        revoked = True
                        
                        OIDCAuditService.log_token_revocation_event(
                            client_id=client_id,
                            user_id=claims.get("sub"),
                            token_type="access_token",
                            reason="revoked_by_client",
                        )
            except Exception:
                pass
        
        return revoked
    
    @classmethod
    def introspect_token(
        cls,
        token: str,
        client_id: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Dict:
        """Introspect a token and return its status and claims.
        
        Args:
            token: Token to introspect
            client_id: Client ID for validation
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Introspection response
        """
        result = OIDCTokenService.introspect_token(token, client_id)
        
        # Log introspection
        OIDCAuditService.log_event(
            event_type="token_introspection",
            client_id=client_id,
            user_id=result.get("sub"),
            success=result.get("active", False),
            metadata={"active": result.get("active")},
        )
        
        return result
    
    @classmethod
    def get_jwks(cls) -> Dict:
        """Get the JWKS document.
        
        Returns:
            JWKS document
        """
        jwks_service = OIDCJWKSService()
        return jwks_service.get_jwks()
    
    @classmethod
    def get_userinfo(cls, access_token: str) -> Dict:
        """Get user information using access token.
        
        Args:
            access_token: Access token
        
        Returns:
            User information dictionary
        """
        claims = cls.validate_access_token(access_token)
        
        user_id = claims.get("sub")
        user = User.query.get(user_id)
        
        if not user:
            raise NotFoundError("User not found")
        
        # Get scopes from token
        scope_str = claims.get("scope", "")
        scopes = scope_str.split() if scope_str else []
        
        userinfo = {"sub": user_id}
        
        # Add claims based on scope
        if "profile" in scopes and user.full_name:
            userinfo["name"] = user.full_name
        
        if "email" in scopes:
            userinfo["email"] = user.email
            userinfo["email_verified"] = user.email_verified
        
        # Log userinfo access
        OIDCAuditService.log_userinfo_event(
            access_token=access_token,
            user_id=user_id,
            client_id=claims.get("client_id"),
            success=True,
            scopes_claimed=scopes,
        )
        
        return userinfo

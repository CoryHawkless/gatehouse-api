"""OIDC Session Service for session management during OIDC flow."""
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from datetime import timezone
from flask import current_app, g

from app.extensions import db
from app.models import OIDCSession, OIDCClient, User
from app.exceptions.validation_exceptions import NotFoundError, ValidationError


class OIDCSessionService:
    """Service for managing OIDC authentication sessions.
    
    This service handles:
    - Creating OIDC sessions during authorization flow
    - Validating sessions with state and nonce
    - Managing PKCE code challenges
    - Cleaning up expired sessions
    """
    
    @staticmethod
    def _generate_state() -> str:
        """Generate a secure state parameter.
        
        Returns:
            URL-safe base64 encoded state
        """
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def _generate_nonce() -> str:
        """Generate a secure nonce for OIDC.
        
        Returns:
            URL-safe base64 encoded nonce
        """
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def _generate_code_challenge(verifier: str, method: str = "S256") -> str:
        """Generate a PKCE code challenge from verifier.
        
        Args:
            verifier: The code verifier
            method: Challenge method ("S256" or "plain")
        
        Returns:
            Code challenge string
        """
        import hashlib
        import base64
        
        if method == "S256":
            digest = hashlib.sha256(verifier.encode()).digest()
            return base64.urlsafe_b64encode(digest).decode().rstrip("=")
        elif method == "plain":
            return verifier
        else:
            raise ValueError(f"Unsupported code challenge method: {method}")
    
    @classmethod
    def validate_code_verifier(cls, code_verifier: str, code_challenge: str, 
                               method: str = "S256") -> bool:
        """Validate a PKCE code verifier against the stored challenge.
        
        Args:
            code_verifier: The code verifier from the token request
            code_challenge: The code challenge from the authorization request
            method: The challenge method used
        
        Returns:
            True if validation succeeds
        """
        if not code_verifier or not code_challenge:
            return False
        
        # Validate code verifier length (43-128 characters)
        if method == "S256" and not (43 <= len(code_verifier) <= 128):
            return False
        
        # Calculate expected challenge
        expected_challenge = cls._generate_code_challenge(code_verifier, method)
        
        return secrets.compare_digest(expected_challenge, code_challenge)
    
    @classmethod
    def create_session(
        cls,
        user_id: str,
        client_id: str,
        state: str = None,
        nonce: str = None,
        redirect_uri: str = None,
        scope: list = None,
        code_challenge: str = None,
        code_challenge_method: str = None,
        lifetime_seconds: int = 600
    ) -> OIDCSession:
        """Create a new OIDC session for the authorization flow.
        
        Args:
            user_id: The user ID
            client_id: The OIDC client ID
            state: State parameter (generated if not provided)
            nonce: Nonce for ID token validation (generated if not provided)
            redirect_uri: Redirect URI from authorization request
            scope: Requested scopes
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method ("S256" or "plain")
            lifetime_seconds: Session lifetime in seconds
        
        Returns:
            OIDCSession instance
        """
        # Generate state and nonce if not provided
        state = state or cls._generate_state()
        nonce = nonce or cls._generate_nonce()
        
        session = OIDCSession.create_session(
            user_id=user_id,
            client_id=client_id,
            state=state,
            nonce=nonce,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            lifetime_seconds=lifetime_seconds,
        )
        
        return session
    
    @classmethod
    def validate_session(cls, state: str, nonce: str = None) -> Tuple[OIDCSession, User]:
        """Validate an OIDC session by state and optionally nonce.
        
        Args:
            state: The state parameter
            nonce: The nonce to validate (optional)
        
        Returns:
            Tuple of (OIDCSession, User)
        
        Raises:
            ValidationError: If session is invalid
            NotFoundError: If session not found
        """
        session = OIDCSession.get_by_state(state)
        
        if not session:
            raise NotFoundError("OIDC session not found or expired")
        
        if session.is_expired():
            raise ValidationError("OIDC session has expired")
        
        # Validate nonce if provided
        if nonce and not session.validate_nonce(nonce):
            raise ValidationError("Invalid nonce")
        
        # Get user
        user = User.query.get(session.user_id)
        if not user:
            raise NotFoundError("User not found")
        
        return session, user
    
    @classmethod
    def validate_pkce(cls, session: OIDCSession, code_verifier: str) -> bool:
        """Validate PKCE code verifier against the session's code challenge.
        
        Args:
            session: OIDCSession instance
            code_verifier: The code verifier from token request
        
        Returns:
            True if validation succeeds
        
        Raises:
            ValidationError: If PKCE validation fails
        """
        if not session.code_challenge:
            # No PKCE was used, skip validation
            return True
        
        if not code_verifier:
            raise ValidationError("code_verifier is required")
        
        is_valid = session.validate_code_challenge(code_verifier)
        
        if not is_valid:
            raise ValidationError("Invalid code_verifier")
        
        return True
    
    @classmethod
    def mark_session_authenticated(cls, session: OIDCSession) -> OIDCSession:
        """Mark a session as authenticated (user has logged in).
        
        Args:
            session: OIDCSession instance
        
        Returns:
            Updated OIDCSession instance
        """
        session.mark_authenticated()
        return session
    
    @classmethod
    def cleanup_expired_sessions(cls, older_than_hours: int = 24) -> int:
        """Remove expired OIDC sessions.
        
        Args:
            older_than_hours: Only delete sessions expired more than this many hours ago
        
        Returns:
            Number of sessions deleted
        """
        from datetime import timedelta
        
        cutoff = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)
        
        # Get expired sessions
        expired_sessions = OIDCSession.query.filter(
            OIDCSession.expires_at < datetime.now(timezone.utc),
            OIDCSession.deleted_at == None
        ).all()
        
        count = 0
        for session in expired_sessions:
            # Only hard delete if past the grace period
            if session.expires_at < cutoff:
                session.delete()
                count += 1
        
        return count
    
    @classmethod
    def get_session_by_state(cls, state: str) -> Optional[OIDCSession]:
        """Get an OIDC session by state.
        
        Args:
            state: The state parameter
        
        Returns:
            OIDCSession instance or None
        """
        return OIDCSession.get_by_state(state)
    
    @classmethod
    def validate_redirect_uri(cls, client_id: str, redirect_uri: str) -> bool:
        """Validate that a redirect URI is allowed for a client.
        
        Args:
            client_id: The OIDC client ID
            redirect_uri: The redirect URI to validate
        
        Returns:
            True if redirect URI is allowed
        """
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            return False
        
        return client.is_redirect_uri_allowed(redirect_uri)
    
    @classmethod
    def validate_scopes(cls, client_id: str, requested_scopes: list) -> list:
        """Validate and filter scopes against client's allowed scopes.
        
        Args:
            client_id: The OIDC client ID
            requested_scopes: List of requested scopes
        
        Returns:
            List of allowed scopes
        """
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            return []
        
        allowed_scopes = client.scopes or []
        
        # Filter to only allowed scopes
        valid_scopes = [s for s in requested_scopes if s in allowed_scopes]
        
        return valid_scopes

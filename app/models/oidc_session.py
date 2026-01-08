"""OIDC Session model for OIDC session tracking."""
from datetime import datetime
from app.extensions import db
from app.models.base import BaseModel


class OIDCSession(BaseModel):
    """OIDC Session model for tracking OIDC authentication sessions.

    This model tracks the state during the OIDC authentication flow,
    including PKCE parameters and nonce validation.
    """

    __tablename__ = "oidc_sessions"

    # User reference
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    # Client reference
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=False, index=True
    )

    # State management
    state = db.Column(db.String(255), nullable=False, index=True)
    nonce = db.Column(db.String(255), nullable=True)  # For OIDC ID Token validation

    # Authorization request parameters
    redirect_uri = db.Column(db.String(512), nullable=False)
    scope = db.Column(db.JSON, nullable=True)  # Requested scopes

    # PKCE parameters
    code_challenge = db.Column(db.String(255), nullable=True)
    code_challenge_method = db.Column(db.String(10), nullable=True)  # "S256" or "plain"

    # Timing
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    authenticated_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="oidc_sessions")
    client = db.relationship("OIDCClient", back_populates="oidc_sessions")

    def __repr__(self):
        """String representation of OIDCSession."""
        return f"<OIDCSession user_id={self.user_id} client_id={self.client_id} state={self.state[:8]}...>"

    def is_expired(self):
        """Check if the OIDC session has expired."""
        return datetime.utcnow() > self.expires_at

    def is_authenticated(self):
        """Check if the user has been authenticated in this session."""
        return self.authenticated_at is not None

    def mark_authenticated(self):
        """Mark the session as authenticated."""
        self.authenticated_at = datetime.utcnow()
        db.session.commit()

    def validate_nonce(self, expected_nonce):
        """Validate the nonce matches the expected value.

        Args:
            expected_nonce: The expected nonce value

        Returns:
            bool: True if nonce matches
        """
        return self.nonce == expected_nonce

    def validate_code_challenge(self, code_verifier):
        """Validate the code verifier against the stored code challenge.

        Args:
            code_verifier: The PKCE code verifier

        Returns:
            bool: True if code challenge is valid
        """
        if not self.code_challenge:
            return False

        if self.code_challenge_method == "S256":
            import hashlib
            import base64
            # SHA256 hash of code_verifier
            digest = hashlib.sha256(code_verifier.encode()).digest()
            # Base64 URL encode without padding
            expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            return self.code_challenge == expected
        elif self.code_challenge_method == "plain":
            return self.code_challenge == code_verifier

        return False

    @classmethod
    def create_session(cls, user_id, client_id, state, redirect_uri, scope=None,
                       nonce=None, code_challenge=None, code_challenge_method=None,
                       lifetime_seconds=600):
        """Create a new OIDC session.

        Args:
            user_id: The user ID
            client_id: The OIDC client ID
            state: The state parameter
            redirect_uri: The redirect URI
            scope: Requested scopes
            nonce: OIDC nonce
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method ("S256" or "plain")
            lifetime_seconds: Session lifetime in seconds

        Returns:
            OIDCSession instance
        """
        from datetime import timedelta
        session = cls(
            user_id=user_id,
            client_id=client_id,
            state=state,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=datetime.utcnow() + timedelta(seconds=lifetime_seconds),
        )
        db.session.add(session)
        db.session.commit()
        return session

    @classmethod
    def get_by_state(cls, state):
        """Get a session by state parameter.

        Args:
            state: The state parameter

        Returns:
            OIDCSession instance or None
        """
        return cls.query.filter_by(state=state, deleted_at=None).first()

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        return super().to_dict(exclude=exclude)


# Add relationship back to User model
from app.models.user import User
User.oidc_sessions = db.relationship(
    "OIDCSession", back_populates="user", cascade="all, delete-orphan"
)

# Add relationship back to OIDCClient model
from app.models.oidc_client import OIDCClient
OIDCClient.oidc_sessions = db.relationship(
    "OIDCSession", back_populates="client", cascade="all, delete-orphan"
)

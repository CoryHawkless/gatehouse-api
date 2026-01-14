"""OIDC Authorization Code model for auth code flow."""
from datetime import datetime, timedelta, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OIDCAuthCode(BaseModel):
    """OIDC Authorization Code model for authorization code flow.

    Authorization codes are single-use, short-lived codes used in the
    authorization code grant flow. The code is hashed for security.
    """

    __tablename__ = "oidc_authorization_codes"

    # Client and User references
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=False, index=True
    )
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    # Authorization code (hashed for security)
    code_hash = db.Column(db.String(255), nullable=False)

    # Request parameters
    redirect_uri = db.Column(db.String(512), nullable=False)
    scope = db.Column(db.JSON, nullable=True)  # Requested scopes
    nonce = db.Column(db.String(255), nullable=True)  # For OIDC ID Token validation
    code_verifier = db.Column(db.String(255), nullable=True)  # For PKCE

    # Status tracking
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    is_used = db.Column(db.Boolean, default=False, nullable=False)

    # Request metadata
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    # Relationships
    client = db.relationship("OIDCClient", back_populates="authorization_codes")
    user = db.relationship("User", back_populates="oidc_auth_codes")

    def __repr__(self):
        """String representation of OIDCAuthCode."""
        return f"<OIDCAuthCode client_id={self.client_id} user_id={self.user_id} used={self.is_used}>"

    def is_expired(self):
        """Check if the authorization code has expired."""
        # Handle both timezone-aware and timezone-naive expires_at values
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            # Make naive datetime timezone-aware (UTC)
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_valid(self):
        """Check if the authorization code is valid for use."""
        return not self.is_used and not self.is_expired() and self.deleted_at is None

    def mark_as_used(self):
        """Mark the authorization code as used."""
        self.is_used = True
        self.used_at = datetime.now(timezone.utc)
        db.session.commit()

    @classmethod
    def create_code(cls, client_id, user_id, code_hash, redirect_uri, scope=None,
                    nonce=None, code_verifier=None, ip_address=None, user_agent=None,
                    lifetime_seconds=600):
        """Create a new authorization code.

        Args:
            client_id: The OIDC client ID
            user_id: The user ID
            code_hash: Hashed authorization code
            redirect_uri: The redirect URI
            scope: Requested scopes
            nonce: OIDC nonce
            code_verifier: PKCE code verifier
            ip_address: Client IP address
            user_agent: Client user agent
            lifetime_seconds: Code lifetime in seconds (default 10 minutes)

        Returns:
            OIDCAuthCode instance
        """
        code = cls(
            client_id=client_id,
            user_id=user_id,
            code_hash=code_hash,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_verifier=code_verifier,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.session.add(code)
        db.session.commit()
        return code

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        # Always exclude code hash
        exclude.append("code_hash")
        exclude.append("code_verifier")
        return super().to_dict(exclude=exclude)


# Add relationship back to User model
from gatehouse_app.models.user import User
User.oidc_auth_codes = db.relationship(
    "OIDCAuthCode", back_populates="user", cascade="all, delete-orphan"
)

# Add relationship back to OIDCClient model
from gatehouse_app.models.oidc_client import OIDCClient
OIDCClient.authorization_codes = db.relationship(
    "OIDCAuthCode", back_populates="client", cascade="all, delete-orphan"
)

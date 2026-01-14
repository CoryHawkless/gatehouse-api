"""OIDC Token Metadata model for token revocation tracking."""
import uuid
from datetime import datetime, timezone
from app.extensions import db
from app.models.base import BaseModel


class OIDCTokenMetadata(BaseModel):
    """OIDC Token Metadata model for tracking issued tokens.

    This model stores metadata about issued tokens (access tokens, refresh tokens, ID tokens)
    for the purpose of token revocation. The id field matches the JTI (JWT ID) claim.
    """

    __tablename__ = "oidc_token_metadata"

    # Token identifier (matches JTI in JWT)
    id = db.Column(
        db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    # Client and User references
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=False, index=True
    )
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    # Token type
    token_type = db.Column(db.String(50), nullable=False)  # "access_token", "refresh_token", "id_token"

    # Token identifier for revocation lookup
    token_jti = db.Column(db.String(255), nullable=False, index=True)  # JWT ID claim

    # Timing
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    # Revocation tracking
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    # Relationships
    client = db.relationship("OIDCClient", back_populates="token_metadata")
    user = db.relationship("User", back_populates="oidc_token_metadata")

    def __repr__(self):
        """String representation of OIDCTokenMetadata."""
        return f"<OIDCTokenMetadata jti={self.token_jti[:8]}... type={self.token_type} revoked={self.is_revoked()}>"

    def is_expired(self):
        """Check if the token has expired."""
        # Handle both timezone-aware and timezone-naive expires_at values
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_revoked(self):
        """Check if the token has been revoked."""
        return self.revoked_at is not None

    def is_valid(self):
        """Check if the token is valid (not expired and not revoked)."""
        return not self.is_revoked() and not self.is_expired() and self.deleted_at is None

    def revoke(self, reason=None):
        """Revoke the token.

        Args:
            reason: Optional reason for revocation
        """
        self.revoked_at = datetime.now(timezone.utc)
        self.revoked_reason = reason
        db.session.commit()

    @classmethod
    def create_metadata(cls, client_id, user_id, token_type, token_jti,
                        expires_at, ip_address=None, user_agent=None):
        """Create token metadata for tracking.

        Args:
            client_id: The OIDC client ID
            user_id: The user ID
            token_type: Type of token ("access_token", "refresh_token", "id_token")
            token_jti: JWT ID claim
            expires_at: Token expiration datetime
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            OIDCTokenMetadata instance
        """
        metadata = cls(
            id=str(uuid.uuid4()),
            client_id=client_id,
            user_id=user_id,
            token_type=token_type,
            token_jti=token_jti,
            expires_at=expires_at,
        )
        db.session.add(metadata)
        db.session.commit()
        return metadata

    @classmethod
    def get_by_jti(cls, token_jti):
        """Get token metadata by JWT ID.

        Args:
            token_jti: The JWT ID

        Returns:
            OIDCTokenMetadata instance or None
        """
        return cls.query.filter_by(token_jti=token_jti, deleted_at=None).first()

    @classmethod
    def revoke_by_jti(cls, token_jti, reason=None):
        """Revoke a token by its JWT ID.

        Args:
            token_jti: The JWT ID
            reason: Optional revocation reason

        Returns:
            bool: True if token was found and revoked
        """
        metadata = cls.get_by_jti(token_jti)
        if metadata:
            metadata.revoke(reason)
            return True
        return False

    @classmethod
    def revoke_all_for_user(cls, user_id, client_id=None, reason=None):
        """Revoke all tokens for a user.

        Args:
            user_id: The user ID
            client_id: Optional client ID to filter by
            reason: Optional revocation reason

        Returns:
            int: Number of tokens revoked
        """
        query = cls.query.filter_by(user_id=user_id, deleted_at=None)
        if client_id:
            query = query.filter_by(client_id=client_id)

        tokens = query.filter(cls.revoked_at == None).all()
        count = 0
        for token in tokens:
            token.revoke(reason)
            count += 1
        return count

    @classmethod
    def revoke_all_for_client(cls, client_id, user_id=None, reason=None):
        """Revoke all tokens for a client.

        Args:
            client_id: The client ID
            user_id: Optional user ID to filter by
            reason: Optional revocation reason

        Returns:
            int: Number of tokens revoked
        """
        query = cls.query.filter_by(client_id=client_id, deleted_at=None)
        if user_id:
            query = query.filter_by(user_id=user_id)

        tokens = query.filter(cls.revoked_at == None).all()
        count = 0
        for token in tokens:
            token.revoke(reason)
            count += 1
        return count

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        return super().to_dict(exclude=exclude)


# Add relationship back to User model
from app.models.user import User
User.oidc_token_metadata = db.relationship(
    "OIDCTokenMetadata", back_populates="user", cascade="all, delete-orphan"
)

# Add relationship back to OIDCClient model
from app.models.oidc_client import OIDCClient
OIDCClient.token_metadata = db.relationship(
    "OIDCTokenMetadata", back_populates="client", cascade="all, delete-orphan"
)

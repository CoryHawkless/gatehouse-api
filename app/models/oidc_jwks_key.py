"""OIDC JWKS Key model for persisting signing keys."""
from datetime import datetime, timezone
from app.extensions import db
from app.models.base import BaseModel


class OidcJwksKey(BaseModel):
    """
    OIDC JWKS Key model for persisting JSON Web Key Set signing keys.

    This model stores RSA/ECDSA key pairs used for signing OIDC tokens.
    Multiple keys can be stored to support key rotation scenarios.

    Attributes:
        id: Integer primary key
        kid: Unique key ID used in JWT "kid" header
        key_type: Type of key (e.g., "RSA", "EC")
        private_key: PEM-encoded private key
        public_key: PEM-encoded public key
        algorithm: Signing algorithm (e.g., "RS256", "ES256")
        created_at: When the key was created
        is_active: Whether this key is currently active for signing
        is_primary: Whether this is the primary signing key
        expires_at: ...
    """

    __tablename__ = "oidc_jwks_keys"

    # Override the default UUID id with integer primary key
    id = db.Column(db.Integer, primary_key=True)

    expires_at = db.Column(db.DateTime, nullable=True)

    # Key identification and type
    kid = db.Column(db.String(255), unique=True, nullable=False, index=True)
    key_type = db.Column(db.String(50), nullable=False)  # e.g., "RSA", "EC"
    algorithm = db.Column(db.String(50), nullable=False)  # e.g., "RS256", "ES256"

    # Key material (PEM-encoded)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)

    # Key status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_primary = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        """String representation of OidcJwksKey."""
        return f"<OidcJwksKey kid={self.kid} key_type={self.key_type} algorithm={self.algorithm}>"

    def to_dict(self, exclude_private_key=True):
        """
        Convert model to dictionary.

        Args:
            exclude_private_key: If True, excludes the private key from output

        Returns:
            Dictionary representation of the model
        """
        exclude = ["private_key"] if exclude_private_key else []
        return super().to_dict(exclude=exclude)

    @classmethod
    def get_active_keys(cls):
        """Get all active keys for signing operations."""
        return cls.query.filter(cls.is_active == True).all()

    @classmethod
    def get_primary_key(cls):
        """Get the primary signing key."""
        return cls.query.filter(cls.is_primary == True).first()

    @classmethod
    def get_key_by_kid(cls, kid):
        """Get a key by its key ID."""
        return cls.query.filter(cls.kid == kid, cls.is_active == True).first()
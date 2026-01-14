"""Authentication method model."""
from app.extensions import db
from app.models.base import BaseModel
from app.utils.constants import AuthMethodType


class AuthenticationMethod(BaseModel):
    """Authentication method model storing user authentication credentials."""

    __tablename__ = "authentication_methods"

    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    method_type = db.Column(db.Enum(AuthMethodType), nullable=False, index=True)

    # For password authentication
    password_hash = db.Column(db.String(255), nullable=True)

    # For OAuth/OIDC providers
    provider_user_id = db.Column(db.String(255), nullable=True)
    provider_data = db.Column(db.JSON, nullable=True)

    # # For TOTP authentication
    # totp_secret = db.Column(db.String(32), nullable=True)
    # totp_backup_codes = db.Column(db.JSON, nullable=True)
    # totp_verified_at = db.Column(db.DateTime, nullable=True)

    # Metadata
    is_primary = db.Column(db.Boolean, default=False, nullable=False)
    verified = db.Column(db.Boolean, default=False, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="authentication_methods")

    # Ensure unique provider combinations
    __table_args__ = (
        db.Index("idx_user_method", "user_id", "method_type"),
        db.UniqueConstraint(
            "user_id", "method_type", "provider_user_id", name="uix_user_method_provider"
        ),
    )

    def __repr__(self):
        """String representation of AuthenticationMethod."""
        return f"<AuthenticationMethod user_id={self.user_id} type={self.method_type}>"

    def is_password(self):
        """Check if this is a password authentication method."""
        return self.method_type == AuthMethodType.PASSWORD

    def is_oauth(self):
        """Check if this is an OAuth authentication method."""
        return self.method_type in [
            AuthMethodType.GOOGLE,
            AuthMethodType.GITHUB,
            AuthMethodType.MICROSOFT,
        ]

    def is_totp(self):
        """Check if this is a TOTP authentication method."""
        return self.method_type == AuthMethodType.TOTP

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        # Always exclude password hash and TOTP secrets
        exclude.append("password_hash")
        exclude.append("totp_secret")
        exclude.append("totp_backup_codes")
        return super().to_dict(exclude=exclude)

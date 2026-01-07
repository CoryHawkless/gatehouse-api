"""OIDC Client model."""
from app.extensions import db
from app.models.base import BaseModel
from app.utils.constants import OIDCGrantType, OIDCResponseType


class OIDCClient(BaseModel):
    """OIDC client model for OAuth2/OIDC integrations."""

    __tablename__ = "oidc_clients"

    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )
    name = db.Column(db.String(255), nullable=False)
    client_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    client_secret_hash = db.Column(db.String(255), nullable=False)

    # OAuth/OIDC configuration
    redirect_uris = db.Column(db.JSON, nullable=False)  # List of allowed redirect URIs
    grant_types = db.Column(db.JSON, nullable=False)  # List of allowed grant types
    response_types = db.Column(db.JSON, nullable=False)  # List of allowed response types
    scopes = db.Column(db.JSON, nullable=False)  # List of allowed scopes

    # Client metadata
    logo_uri = db.Column(db.String(512), nullable=True)
    client_uri = db.Column(db.String(512), nullable=True)
    policy_uri = db.Column(db.String(512), nullable=True)
    tos_uri = db.Column(db.String(512), nullable=True)

    # Settings
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_confidential = db.Column(db.Boolean, default=True, nullable=False)
    require_pkce = db.Column(db.Boolean, default=True, nullable=False)

    # Token lifetimes (in seconds)
    access_token_lifetime = db.Column(db.Integer, default=3600, nullable=False)
    refresh_token_lifetime = db.Column(db.Integer, default=2592000, nullable=False)
    id_token_lifetime = db.Column(db.Integer, default=3600, nullable=False)

    # Relationships
    organization = db.relationship("Organization", back_populates="oidc_clients")

    def __repr__(self):
        """String representation of OIDCClient."""
        return f"<OIDCClient {self.name} client_id={self.client_id}>"

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        # Always exclude client secret
        exclude.append("client_secret_hash")
        return super().to_dict(exclude=exclude)

    def has_grant_type(self, grant_type):
        """Check if client supports a specific grant type."""
        return grant_type in self.grant_types

    def has_response_type(self, response_type):
        """Check if client supports a specific response type."""
        return response_type in self.response_types

    def is_redirect_uri_allowed(self, redirect_uri):
        """Check if a redirect URI is allowed for this client."""
        return redirect_uri in self.redirect_uris

    def has_scope(self, scope):
        """Check if client is allowed to request a specific scope."""
        return scope in self.scopes

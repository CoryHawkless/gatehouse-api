"""User model."""
from app.extensions import db
from app.models.base import BaseModel
from app.utils.constants import UserStatus


class User(BaseModel):
    """User model representing a user account."""

    __tablename__ = "users"

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    full_name = db.Column(db.String(255), nullable=True)
    avatar_url = db.Column(db.String(512), nullable=True)
    status = db.Column(
        db.Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False, index=True
    )
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)

    # Relationships
    authentication_methods = db.relationship(
        "AuthenticationMethod", back_populates="user", cascade="all, delete-orphan"
    )
    sessions = db.relationship("Session", back_populates="user", cascade="all, delete-orphan")
    organization_memberships = db.relationship(
        "OrganizationMember",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="OrganizationMember.user_id",
    )
    audit_logs = db.relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        """String representation of User."""
        return f"<User {self.email}>"

    def to_dict(self, exclude=None):
        """Convert user to dictionary, excluding sensitive fields by default."""
        exclude = exclude or []
        # Always exclude password-related fields
        default_exclude = []
        all_exclude = list(set(default_exclude + exclude))
        return super().to_dict(exclude=all_exclude)

    def has_password_auth(self):
        """Check if user has password authentication enabled."""
        from app.models.authentication_method import AuthenticationMethod
        from app.utils.constants import AuthMethodType

        return (
            AuthenticationMethod.query.filter_by(
                user_id=self.id, method_type=AuthMethodType.PASSWORD, deleted_at=None
            ).first()
            is not None
        )

    def get_organizations(self):
        """Get all organizations the user is a member of."""
        return [membership.organization for membership in self.organization_memberships]

"""Session model."""
from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models.base import BaseModel
from app.utils.constants import SessionStatus


class Session(BaseModel):
    """Session model for tracking user sessions."""

    __tablename__ = "sessions"

    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    status = db.Column(db.Enum(SessionStatus), default=SessionStatus.ACTIVE, nullable=False)

    # Session metadata
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    device_info = db.Column(db.JSON, nullable=True)

    # Timing
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="sessions")

    def __repr__(self):
        """String representation of Session."""
        return f"<Session user_id={self.user_id} status={self.status}>"

    def is_active(self):
        """Check if session is currently active."""
        now = datetime.now(timezone.utc)
        return (
            self.status == SessionStatus.ACTIVE
            and self.expires_at > now
            and self.deleted_at is None
        )

    def is_expired(self):
        """Check if session has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def refresh(self, duration_seconds=86400):
        """
        Refresh session expiration.

        Args:
            duration_seconds: New session duration in seconds
        """
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        self.last_activity_at = datetime.now(timezone.utc)
        db.session.commit()

    def revoke(self, reason=None):
        """
        Revoke the session.

        Args:
            reason: Optional reason for revocation
        """
        self.status = SessionStatus.REVOKED
        self.revoked_at = datetime.now(timezone.utc)
        if reason:
            self.revoked_reason = reason
        db.session.commit()

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        # Exclude token from dict
        exclude.append("token")
        return super().to_dict(exclude=exclude)

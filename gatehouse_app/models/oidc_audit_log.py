"""OIDC Audit Log model for comprehensive OIDC event tracking."""
from datetime import datetime
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OIDCAuditLog(BaseModel):
    """OIDC Audit Log model for comprehensive OIDC event tracking.

    This model logs all OIDC-related events for security, compliance,
    and debugging purposes.
    """

    __tablename__ = "oidc_audit_logs"

    # Event type categorization
    event_type = db.Column(db.String(100), nullable=False, index=True)

    # Client and User references
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=True, index=True
    )
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=True, index=True
    )

    # Event outcome
    success = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # Error details (for failed events)
    error_code = db.Column(db.String(100), nullable=True)
    error_description = db.Column(db.Text, nullable=True)

    # Request context
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.Text, nullable=True)
    request_id = db.Column(db.String(36), nullable=True, index=True)

    # Additional event metadata
    event_metadata = db.Column(db.JSON, nullable=True)

    # Relationships
    client = db.relationship("OIDCClient", back_populates="audit_logs")
    user = db.relationship("User", back_populates="oidc_audit_logs")

    def __repr__(self):
        """String representation of OIDCAuditLog."""
        status = "success" if self.success else "failed"
        return f"<OIDCAuditLog event={self.event_type} status={status} client={self.client_id}>"

    @classmethod
    def log_event(cls, event_type, client_id=None, user_id=None, success=True,
                  error_code=None, error_description=None, ip_address=None,
                  user_agent=None, request_id=None, event_metadata=None):
        """Log an OIDC event.

        Args:
            event_type: Type of event (e.g., "authorization_request", "token_issue")
            client_id: The OIDC client ID
            user_id: The user ID
            success: Whether the event was successful
            error_code: Error code if event failed
            error_description: Error description if event failed
            ip_address: Client IP address
            user_agent: Client user agent
            request_id: Request ID for correlation
            event_metadata: Additional event metadata

        Returns:
            OIDCAuditLog instance
        """
        log = cls(
            event_type=event_type,
            client_id=client_id,
            user_id=user_id,
            success=success,
            error_code=error_code,
            error_description=error_description,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            event_metadata=event_metadata,
        )
        db.session.add(log)
        db.session.commit()
        return log

    @classmethod
    def log_authorization_request(cls, client_id, user_id, redirect_uri, scope,
                                   ip_address=None, user_agent=None, request_id=None,
                                   success=True, error_code=None, error_description=None):
        """Log an authorization request event."""
        return cls.log_event(
            event_type="authorization_request",
            client_id=client_id,
            user_id=user_id,
            success=success,
            error_code=error_code,
            error_description=error_description,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            event_metadata={
                "redirect_uri": redirect_uri,
                "scope": scope,
            }
        )

    @classmethod
    def log_token_issue(cls, client_id, user_id, token_type,
                        ip_address=None, user_agent=None, request_id=None):
        """Log a token issuance event."""
        return cls.log_event(
            event_type="token_issue",
            client_id=client_id,
            user_id=user_id,
            success=True,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            event_metadata={"token_type": token_type}
        )

    @classmethod
    def log_token_revocation(cls, client_id, user_id, token_type, reason=None,
                             ip_address=None, user_agent=None, request_id=None):
        """Log a token revocation event."""
        return cls.log_event(
            event_type="token_revocation",
            client_id=client_id,
            user_id=user_id,
            success=True,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            event_metadata={
                "token_type": token_type,
                "reason": reason,
            }
        )

    @classmethod
    def log_authentication_failure(cls, client_id, error_code, error_description,
                                   ip_address=None, user_agent=None, request_id=None):
        """Log an authentication failure event."""
        return cls.log_event(
            event_type="authentication_failure",
            client_id=client_id,
            success=False,
            error_code=error_code,
            error_description=error_description,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )

    @classmethod
    def get_events_for_user(cls, user_id, limit=100):
        """Get audit events for a user.

        Args:
            user_id: The user ID
            limit: Maximum number of events to return

        Returns:
            List of OIDCAuditLog instances
        """
        return cls.query.filter_by(user_id=user_id, deleted_at=None)\
            .order_by(cls.created_at.desc())\
            .limit(limit)\
            .all()

    @classmethod
    def get_events_for_client(cls, client_id, limit=100):
        """Get audit events for a client.

        Args:
            client_id: The client ID
            limit: Maximum number of events to return

        Returns:
            List of OIDCAuditLog instances
        """
        return cls.query.filter_by(client_id=client_id, deleted_at=None)\
            .order_by(cls.created_at.desc())\
            .limit(limit)\
            .all()

    @classmethod
    def get_failed_events(cls, client_id=None, user_id=None, start_date=None,
                          end_date=None, limit=100):
        """Get failed audit events.

        Args:
            client_id: Optional client ID filter
            user_id: Optional user ID filter
            start_date: Optional start date filter
            end_date: Optional end date filter
            limit: Maximum number of events to return

        Returns:
            List of OIDCAuditLog instances
        """
        query = cls.query.filter_by(success=False, deleted_at=None)
        if client_id:
            query = query.filter_by(client_id=client_id)
        if user_id:
            query = query.filter_by(user_id=user_id)
        if start_date:
            query = query.filter(cls.created_at >= start_date)
        if end_date:
            query = query.filter(cls.created_at <= end_date)

        return query.order_by(cls.created_at.desc()).limit(limit).all()

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        return super().to_dict(exclude=exclude)


# Add relationship back to User model
from gatehouse_app.models.user import User
User.oidc_audit_logs = db.relationship(
    "OIDCAuditLog", back_populates="user", cascade="all, delete-orphan"
)

# Add relationship back to OIDCClient model
from gatehouse_app.models.oidc_client import OIDCClient
OIDCClient.audit_logs = db.relationship(
    "OIDCAuditLog", back_populates="client", cascade="all, delete-orphan"
)

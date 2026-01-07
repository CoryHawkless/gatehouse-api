"""Audit service."""
from flask import request, g
from app.models.audit_log import AuditLog
from app.utils.constants import AuditAction


class AuditService:
    """Service for audit logging."""

    @staticmethod
    def log_action(
        action,
        user_id=None,
        organization_id=None,
        resource_type=None,
        resource_id=None,
        metadata=None,
        description=None,
        success=True,
        error_message=None,
    ):
        """
        Create an audit log entry.

        Args:
            action: AuditAction enum value
            user_id: ID of user performing the action
            organization_id: ID of related organization
            resource_type: Type of resource being acted upon
            resource_id: ID of resource being acted upon
            metadata: Additional metadata dictionary
            description: Human-readable description
            success: Whether the action succeeded
            error_message: Error message if action failed

        Returns:
            AuditLog instance
        """
        # Get request details if available
        ip_address = None
        user_agent = None
        request_id = None

        try:
            if request:
                ip_address = request.remote_addr
                user_agent = request.headers.get("User-Agent")
                request_id = g.get("request_id")
        except RuntimeError:
            # No request context
            pass

        log_entry = AuditLog(
            action=action,
            user_id=user_id,
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata=metadata,
            description=description,
            success=success,
            error_message=error_message,
        )
        log_entry.save()

        return log_entry

    @staticmethod
    def get_user_activity(user_id, limit=50):
        """
        Get recent activity for a user.

        Args:
            user_id: User ID
            limit: Maximum number of records to return

        Returns:
            List of AuditLog instances
        """
        return (
            AuditLog.query.filter_by(user_id=user_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_organization_activity(organization_id, limit=50):
        """
        Get recent activity for an organization.

        Args:
            organization_id: Organization ID
            limit: Maximum number of records to return

        Returns:
            List of AuditLog instances
        """
        return (
            AuditLog.query.filter_by(organization_id=organization_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .all()
        )

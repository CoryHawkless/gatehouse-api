"""OIDC Audit Service for comprehensive OIDC event logging."""
from datetime import datetime
from typing import Dict, List, Optional

from flask import g

from app.models import OIDCAuditLog, OIDCClient, User
from app.exceptions.validation_exceptions import NotFoundError


class OIDCAuditService:
    """Service for OIDC-specific audit logging.
    
    This service provides methods to log all OIDC-related events including:
    - Authorization requests and responses
    - Token issuance and refresh
    - Token revocation
    - UserInfo endpoint access
    - Authentication failures
    """
    
    # Event type constants
    EVENT_AUTHORIZATION_REQUEST = "authorization_request"
    EVENT_AUTHORIZATION_RESPONSE = "authorization_response"
    EVENT_TOKEN_ISSUE = "token_issue"
    EVENT_TOKEN_REFRESH = "token_refresh"
    EVENT_TOKEN_REVOCATION = "token_revocation"
    EVENT_TOKEN_INTROSPECTION = "token_introspection"
    EVENT_USERINFO_ACCESS = "userinfo_access"
    EVENT_AUTHENTICATION_FAILURE = "authentication_failure"
    EVENT_AUTHORIZATION_FAILURE = "authorization_failure"
    EVENT_JWKS_ACCESS = "jwks_access"
    EVENT_REGISTRATION = "client_registration"
    
    @classmethod
    def _get_request_context(cls) -> Dict:
        """Extract request context for logging.
        
        Returns:
            Dictionary with IP, user_agent, and request_id
        """
        from flask import request
        
        return {
            "ip_address": request.remote_addr if request else None,
            "user_agent": request.headers.get("User-Agent") if request else None,
            "request_id": g.get("request_id"),
        }
    
    @classmethod
    def log_event(
        cls,
        event_type: str,
        client_id: str = None,
        user_id: str = None,
        success: bool = True,
        error_code: str = None,
        error_description: str = None,
        metadata: Dict = None
    ) -> OIDCAuditLog:
        """Log a generic OIDC event.
        
        Args:
            event_type: Type of event
            client_id: OIDC client ID
            user_id: User ID
            success: Whether the event was successful
            error_code: Error code if failed
            error_description: Error description if failed
            metadata: Additional event metadata
        
        Returns:
            OIDCAuditLog instance
        """
        context = cls._get_request_context()
        
        log = OIDCAuditLog.log_event(
            event_type=event_type,
            client_id=client_id,
            user_id=user_id,
            success=success,
            error_code=error_code,
            error_description=error_description,
            ip_address=context["ip_address"],
            user_agent=context["user_agent"],
            request_id=context["request_id"],
            event_metadata=metadata,
        )
        
        return log
    
    @classmethod
    def log_authorization_event(
        cls,
        client_id: str,
        user_id: str = None,
        success: bool = True,
        error_code: str = None,
        error_description: str = None,
        redirect_uri: str = None,
        scope: list = None,
        response_type: str = None
    ) -> OIDCAuditLog:
        """Log an authorization event.
        
        Args:
            client_id: OIDC client ID
            user_id: User ID (if authenticated)
            success: Whether authorization was successful
            error_code: Error code if failed
            error_description: Error description if failed
            redirect_uri: Redirect URI from request
            scope: Requested scopes
            response_type: Response type (e.g., "code")
        
        Returns:
            OIDCAuditLog instance
        """
        metadata = {
            "redirect_uri": redirect_uri,
            "scope": scope,
            "response_type": response_type,
        }
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        return cls.log_event(
            event_type=cls.EVENT_AUTHORIZATION_REQUEST,
            client_id=client_id,
            user_id=user_id,
            success=success,
            error_code=error_code,
            error_description=error_description,
            metadata=metadata,
        )
    
    @classmethod
    def log_token_event(
        cls,
        client_id: str,
        user_id: str = None,
        token_type: str = "access_token",
        success: bool = True,
        error_code: str = None,
        error_description: str = None,
        grant_type: str = None,
        scopes: list = None
    ) -> OIDCAuditLog:
        """Log a token issuance or refresh event.
        
        Args:
            client_id: OIDC client ID
            user_id: User ID
            token_type: Type of token issued
            success: Whether token issuance was successful
            error_code: Error code if failed
            error_description: Error description if failed
            grant_type: Grant type used (e.g., "authorization_code", "refresh_token")
            scopes: Scopes included in the token
        
        Returns:
            OIDCAuditLog instance
        """
        metadata = {
            "token_type": token_type,
            "grant_type": grant_type,
            "scopes": scopes,
        }
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        return cls.log_event(
            event_type=cls.EVENT_TOKEN_ISSUE if token_type else cls.EVENT_TOKEN_REFRESH,
            client_id=client_id,
            user_id=user_id,
            success=success,
            error_code=error_code,
            error_description=error_description,
            metadata=metadata,
        )
    
    @classmethod
    def log_userinfo_event(
        cls,
        access_token: str = None,
        user_id: str = None,
        client_id: str = None,
        success: bool = True,
        error_code: str = None,
        error_description: str = None,
        scopes_claimed: list = None
    ) -> OIDCAuditLog:
        """Log a UserInfo endpoint access event.
        
        Args:
            access_token: Access token used (masked)
            user_id: User ID returned
            client_id: Client ID making the request
            success: Whether access was successful
            error_code: Error code if failed
            error_description: Error description if failed
            scopes_claimed: Scopes claimed in the request
        
        Returns:
            OIDCAuditLog instance
        """
        # Mask the access token for security
        masked_token = None
        if access_token:
            masked_token = access_token[:8] + "..." + access_token[-4:] if len(access_token) > 12 else "***"
        
        metadata = {
            "token_prefix": masked_token,
            "scopes_claimed": scopes_claimed,
        }
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        return cls.log_event(
            event_type=cls.EVENT_USERINFO_ACCESS,
            client_id=client_id,
            user_id=user_id,
            success=success,
            error_code=error_code,
            error_description=error_description,
            metadata=metadata,
        )
    
    @classmethod
    def log_token_revocation_event(
        cls,
        client_id: str,
        user_id: str = None,
        token_type: str = "access_token",
        reason: str = None,
        success: bool = True,
        error_code: str = None,
        error_description: str = None
    ) -> OIDCAuditLog:
        """Log a token revocation event.
        
        Args:
            client_id: OIDC client ID
            user_id: User ID
            token_type: Type of token being revoked
            reason: Revocation reason
            success: Whether revocation was successful
            error_code: Error code if failed
            error_description: Error description if failed
        
        Returns:
            OIDCAuditLog instance
        """
        metadata = {
            "token_type": token_type,
            "reason": reason,
        }
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        return cls.log_event(
            event_type=cls.EVENT_TOKEN_REVOCATION,
            client_id=client_id,
            user_id=user_id,
            success=success,
            error_code=error_code,
            error_description=error_description,
            metadata=metadata,
        )
    
    @classmethod
    def log_authentication_failure(
        cls,
        client_id: str = None,
        error_code: str = "authentication_failed",
        error_description: str = "Authentication failed",
        user_id: str = None
    ) -> OIDCAuditLog:
        """Log an authentication failure event.
        
        Args:
            client_id: OIDC client ID
            error_code: Error code
            error_description: Error description
            user_id: User ID if known
        
        Returns:
            OIDCAuditLog instance
        """
        return cls.log_event(
            event_type=cls.EVENT_AUTHENTICATION_FAILURE,
            client_id=client_id,
            user_id=user_id,
            success=False,
            error_code=error_code,
            error_description=error_description,
        )
    
    @classmethod
    def get_events_for_user(
        cls,
        user_id: str,
        limit: int = 100,
        include_deleted: bool = False
    ) -> List[OIDCAuditLog]:
        """Get audit events for a specific user.
        
        Args:
            user_id: User ID
            limit: Maximum number of events to return
            include_deleted: Include soft-deleted events
        
        Returns:
            List of OIDCAuditLog instances
        """
        return OIDCAuditLog.get_events_for_user(user_id, limit)
    
    @classmethod
    def get_events_for_client(
        cls,
        client_id: str,
        limit: int = 100
    ) -> List[OIDCAuditLog]:
        """Get audit events for a specific client.
        
        Args:
            client_id: Client ID
            limit: Maximum number of events to return
        
        Returns:
            List of OIDCAuditLog instances
        """
        return OIDCAuditLog.get_events_for_client(client_id, limit)
    
    @classmethod
    def get_failed_events(
        cls,
        client_id: str = None,
        user_id: str = None,
        start_date: datetime = None,
        end_date: datetime = None,
        limit: int = 100
    ) -> List[OIDCAuditLog]:
        """Get failed audit events for analysis.
        
        Args:
            client_id: Optional client ID filter
            user_id: Optional user ID filter
            start_date: Optional start date filter
            end_date: Optional end date filter
            limit: Maximum number of events to return
        
        Returns:
            List of failed OIDCAuditLog instances
        """
        return OIDCAuditLog.get_failed_events(
            client_id=client_id,
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
    
    @classmethod
    def get_event_summary(
        cls,
        client_id: str = None,
        days: int = 30
    ) -> Dict:
        """Get a summary of audit events.
        
        Args:
            client_id: Optional client ID filter
            days: Number of days to look back
        
        Returns:
            Summary dictionary with event counts
        """
        from datetime import timedelta
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        query = OIDCAuditLog.query.filter(
            OIDCAuditLog.created_at >= start_date
        )
        
        if client_id:
            query = query.filter_by(client_id=client_id)
        
        events = query.all()
        
        # Count by event type
        event_counts = {}
        success_count = 0
        failure_count = 0
        
        for event in events:
            event_type = event.event_type
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            if event.success:
                success_count += 1
            else:
                failure_count += 1
        
        return {
            "total_events": len(events),
            "successful_events": success_count,
            "failed_events": failure_count,
            "by_event_type": event_counts,
            "period_days": days,
        }

"""Custom decorators for authentication and authorization."""
from functools import wraps
from flask import request, g
from app.utils.response import api_response
from app.utils.constants import OrganizationRole


def login_required(f):
    """Decorator to require Bearer token authentication.
    
    Extracts token from Authorization: Bearer {token} header,
    validates the session, and sets g.current_user and g.current_session.
    """
    from app.services.session_service import SessionService
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return api_response(
                success=False,
                message="Authorization header is required",
                status=401,
                error_type="AUTH_REQUIRED"
            )
        
        # Expect format: "Bearer {token}"
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return api_response(
                success=False,
                message="Invalid authorization format. Use: Bearer {token}",
                status=401,
                error_type="INVALID_AUTH_FORMAT"
            )
        
        token = parts[1]
        
        # Get active session by token
        session = SessionService.get_active_session_by_token(token)
        
        if not session:
            return api_response(
                success=False,
                message="Invalid or expired session",
                status=401,
                error_type="INVALID_TOKEN"
            )
        
        # Validate session is active
        if not session.is_active():
            return api_response(
                success=False,
                message="Session is no longer active",
                status=401,
                error_type="SESSION_INACTIVE"
            )
        
        # Update last_activity_at timestamp
        from datetime import datetime, timezone
        session.last_activity_at = datetime.now(timezone.utc)
        from app import db
        db.session.commit()
        
        # Set context variables
        g.current_user = session.user
        g.current_session = session
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_role(*allowed_roles):
    """
    Decorator to require specific organization roles.

    Args:
        *allowed_roles: Variable number of OrganizationRole values

    Raises:
        ForbiddenError: If user doesn't have required role
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ensure user is authenticated first
            if not hasattr(g, "current_user"):
                raise UnauthorizedError("Authentication required")

            # Get organization_id from kwargs or URL parameters
            org_id = kwargs.get("org_id") or kwargs.get("organization_id")
            if not org_id:
                raise ForbiddenError("Organization context required")

            # Check user's role in the organization
            from app.models.organization_member import OrganizationMember

            membership = OrganizationMember.query.filter_by(
                user_id=g.current_user.id,
                organization_id=org_id,
            ).first()

            if not membership:
                raise ForbiddenError("Not a member of this organization")

            if membership.role not in allowed_roles:
                raise ForbiddenError(
                    f"Requires one of the following roles: {', '.join(allowed_roles)}"
                )

            g.current_membership = membership
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_owner(f):
    """Decorator to require organization owner role."""
    return require_role(OrganizationRole.OWNER)(f)


def require_admin(f):
    """Decorator to require organization admin or owner role."""
    return require_role(OrganizationRole.OWNER, OrganizationRole.ADMIN)(f)

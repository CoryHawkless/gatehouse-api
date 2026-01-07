"""Authentication endpoints."""
from flask import request, session, g
from marshmallow import ValidationError
from app.api.v1 import api_v1_bp
from app.utils.response import api_response
from app.schemas.auth_schema import RegisterSchema, LoginSchema
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.utils.decorators import login_required
from app.utils.constants import AuditAction


@api_v1_bp.route("/auth/register", methods=["POST"])
def register():
    """
    Register a new user.

    Request body:
        email: User email
        password: User password
        password_confirm: Password confirmation
        full_name: Optional full name

    Returns:
        201: User created successfully
        400: Validation error
        409: Email already exists
    """
    try:
        # Validate request data
        schema = RegisterSchema()
        data = schema.load(request.json)

        # Register user
        user = AuthService.register_user(
            email=data["email"],
            password=data["password"],
            full_name=data.get("full_name"),
        )

        # Create session
        user_session = AuthService.create_session(user)

        return api_response(
            data={
                "user": user.to_dict(),
                "token": user_session.token,
                "expires_at": user_session.expires_at.isoformat() + "Z" if user_session.expires_at.isoformat()[-1] != "Z" else user_session.expires_at.isoformat(),
            },
            message="Registration successful",
            status=201,
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/auth/login", methods=["POST"])
def login():
    """
    Login user.

    Request body:
        email: User email
        password: User password
        remember_me: Optional boolean for extended session

    Returns:
        200: Login successful
        400: Validation error
        401: Invalid credentials
    """
    try:
        # Validate request data
        schema = LoginSchema()
        data = schema.load(request.json)

        # Authenticate user
        user = AuthService.authenticate(
            email=data["email"],
            password=data["password"],
        )

        # Create session
        duration = 2592000 if data.get("remember_me") else 86400  # 30 days vs 1 day
        user_session = AuthService.create_session(user, duration_seconds=duration)

        return api_response(
            data={
                "user": user.to_dict(),
                "token": user_session.token,
                "expires_at": user_session.expires_at.isoformat() + "Z" if user_session.expires_at.isoformat()[-1] != "Z" else user_session.expires_at.isoformat(),
            },
            message="Login successful",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    """
    Logout current user.

    Returns:
        200: Logout successful
        401: Not authenticated
    """
    # Revoke current session (g.current_session is set by login_required decorator)
    if g.current_session:
        AuthService.revoke_session(g.current_session.id, reason="User logout")

    return api_response(
        message="Logout successful",
    )


@api_v1_bp.route("/auth/me", methods=["GET"])
@login_required
def get_current_user():
    """
    Get current authenticated user.

    Returns:
        200: User data
        401: Not authenticated
    """
    user = g.current_user

    return api_response(
        data={
            "user": user.to_dict(),
            "organizations": [
                {"id": org.id, "name": org.name, "slug": org.slug}
                for org in user.get_organizations()
            ],
        },
        message="User retrieved successfully",
    )


@api_v1_bp.route("/auth/sessions", methods=["GET"])
@login_required
def get_user_sessions():
    """
    Get all active sessions for current user.

    Returns:
        200: List of active sessions
        401: Not authenticated
    """
    from app.services.session_service import SessionService

    sessions = SessionService.get_user_sessions(g.current_user.id, active_only=True)

    return api_response(
        data={
            "sessions": [session.to_dict() for session in sessions],
            "count": len(sessions),
        },
        message="Sessions retrieved successfully",
    )


@api_v1_bp.route("/auth/sessions/<session_id>", methods=["DELETE"])
@login_required
def revoke_session(session_id):
    """
    Revoke a specific session.

    Args:
        session_id: ID of session to revoke

    Returns:
        200: Session revoked
        401: Not authenticated
        404: Session not found
    """
    from app.models.session import Session

    # Ensure session belongs to current user
    user_session = Session.query.filter_by(
        id=session_id, user_id=g.current_user.id, deleted_at=None
    ).first()

    if not user_session:
        return api_response(
            success=False,
            message="Session not found",
            status=404,
            error_type="NOT_FOUND",
        )

    AuthService.revoke_session(session_id, reason="Revoked by user")

    return api_response(
        message="Session revoked successfully",
    )

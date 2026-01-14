"""Authentication endpoints."""
from flask import request, session, g
from marshmallow import ValidationError
from app.api.v1 import api_v1_bp
from app.utils.response import api_response
from app.schemas.auth_schema import (
    RegisterSchema,
    LoginSchema,
    TOTPVerifyEnrollmentSchema,
    TOTPVerifySchema,
    TOTPDisableSchema,
    TOTPRegenerateBackupCodesSchema,
)
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.utils.decorators import login_required
from app.utils.constants import AuditAction
from app.exceptions.auth_exceptions import InvalidCredentialsError
from app.exceptions.validation_exceptions import ConflictError


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
        200: Login successful or TOTP code required
        400: Validation error
        401: Invalid credentials
    """
    try:
        # Validate request data
        schema = LoginSchema()
        data = schema.load(request.json)

        # Authenticate user with email and password
        user = AuthService.authenticate(
            email=data["email"],
            password=data["password"],
        )

        # Check if user has TOTP enabled for two-factor authentication
        if user.has_totp_enabled():
            # TOTP is enabled - store user_id in session for TOTP verification
            # The /auth/totp/verify endpoint will retrieve this user_id
            session["totp_pending_user_id"] = user.id

            # Return response indicating TOTP code is required
            # Do NOT create session or return token yet - wait for TOTP verification
            return api_response(
                data={
                    "requires_totp": True,
                },
                message="TOTP code required. Please enter your 6-digit code from your authenticator app.",
            )

        # TOTP is NOT enabled - proceed with normal login flow
        # Create session with appropriate duration based on remember_me preference
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


@api_v1_bp.route("/auth/totp/enroll", methods=["POST"])
@login_required
def enroll_totp():
    """
    Initiate TOTP enrollment for the current user.

    Returns:
        201: TOTP enrollment initiated with secret, provisioning_uri, qr_code, and backup_codes
        401: Not authenticated
        409: TOTP already enabled
    """
    try:
        # Initiate TOTP enrollment
        result = AuthService.enroll_totp(g.current_user)

        return api_response(
            data={
                "secret": result["secret"],
                "provisioning_uri": result["provisioning_uri"],
                "qr_code": result["qr_code"],
                "backup_codes": result["backup_codes"],
            },
            message="TOTP enrollment initiated. Please verify with your authenticator app.",
            status=201,
        )

    except ConflictError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/verify-enrollment", methods=["POST"])
@login_required
def verify_totp_enrollment():
    """
    Complete TOTP enrollment by verifying the first TOTP code.

    Request body:
        code: 6-digit TOTP code from authenticator app

    Returns:
        200: TOTP enrollment completed successfully
        400: Validation error
        401: Not authenticated
        401: Invalid TOTP code
    """
    try:
        # Validate request data
        schema = TOTPVerifyEnrollmentSchema()
        data = schema.load(request.json)

        # Verify TOTP enrollment
        AuthService.verify_totp_enrollment(g.current_user, data["code"])

        return api_response(
            message="TOTP enrollment completed successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/verify", methods=["POST"])
def verify_totp():
    """
    Verify TOTP code during login.

    Request body:
        code: 6-digit TOTP code or backup code
        is_backup_code: True if code is a backup code, False if TOTP code (default: False)

    Returns:
        200: TOTP code verified successfully with session token
        400: Validation error
        401: Invalid TOTP code or session not found
    """
    try:
        # Validate request data
        schema = TOTPVerifySchema()
        data = schema.load(request.json)

        # Get user from temporary session (stored in Flask session by login endpoint)
        user_id = session.get("totp_pending_user_id")
        if not user_id:
            return api_response(
                success=False,
                message="No pending TOTP verification. Please login first.",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )

        # Get user from database
        from app.models.user import User
        user = User.query.get(user_id)
        if not user:
            return api_response(
                success=False,
                message="User not found",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )

        # Verify TOTP code
        AuthService.authenticate_with_totp(
            user, data["code"], data.get("is_backup_code", False)
        )

        # Create full session
        user_session = AuthService.create_session(user)

        # Clear temporary session
        session.pop("totp_pending_user_id", None)

        return api_response(
            data={
                "user": user.to_dict(),
                "token": user_session.token,
                "expires_at": user_session.expires_at.isoformat() + "Z"
                if user_session.expires_at.isoformat()[-1] != "Z"
                else user_session.expires_at.isoformat(),
            },
            message="TOTP verification successful",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/disable", methods=["DELETE"])
@login_required
def disable_totp():
    """
    Disable TOTP for the current user.

    Request body:
        password: User's current password for verification

    Returns:
        200: TOTP disabled successfully
        400: Validation error
        401: Not authenticated or invalid password
        401: TOTP not enabled
    """
    try:
        # Validate request data
        schema = TOTPDisableSchema()
        data = schema.load(request.json)

        # Disable TOTP
        AuthService.disable_totp(g.current_user, data["password"])

        return api_response(
            message="TOTP disabled successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/status", methods=["GET"])
@login_required
def get_totp_status():
    """
    Get TOTP status for the current user.

    Returns:
        200: TOTP status with totp_enabled, verified_at, and backup_codes_remaining
        401: Not authenticated
    """
    user = g.current_user

    # Check if TOTP is enabled
    totp_enabled = user.has_totp_enabled()

    # Get TOTP method to check backup codes remaining
    backup_codes_remaining = 0
    verified_at = None

    if totp_enabled:
        totp_method = user.get_totp_method()
        if totp_method and totp_method.provider_data:
            backup_codes = totp_method.provider_data.get("backup_codes", [])
            backup_codes_remaining = len(backup_codes)
        if totp_method and totp_method.totp_verified_at:
            verified_at = totp_method.totp_verified_at.isoformat() + "Z" if totp_method.totp_verified_at.isoformat()[-1] != "Z" else totp_method.totp_verified_at.isoformat()

    return api_response(
        data={
            "totp_enabled": totp_enabled,
            "verified_at": verified_at,
            "backup_codes_remaining": backup_codes_remaining,
        },
        message="TOTP status retrieved successfully",
    )


@api_v1_bp.route("/auth/totp/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_totp_backup_codes():
    """
    Generate new backup codes for TOTP.

    Request body:
        password: User's current password for verification

    Returns:
        200: New backup codes generated successfully
        400: Validation error
        401: Not authenticated or invalid password
        401: TOTP not enabled
    """
    try:
        # Validate request data
        schema = TOTPRegenerateBackupCodesSchema()
        data = schema.load(request.json)

        # Regenerate backup codes
        backup_codes = AuthService.regenerate_totp_backup_codes(
            g.current_user, data["password"]
        )

        return api_response(
            data={
                "backup_codes": backup_codes,
            },
            message="Backup codes regenerated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )

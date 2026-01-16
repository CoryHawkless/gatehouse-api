"""Authentication endpoints."""
import json
from flask import request, session, g, jsonify
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.schemas.auth_schema import (
    RegisterSchema,
    LoginSchema,
    TOTPVerifyEnrollmentSchema,
    TOTPVerifySchema,
    TOTPDisableSchema,
    TOTPRegenerateBackupCodesSchema,
)
from gatehouse_app.schemas.webauthn_schema import (
    WebAuthnRegistrationBeginSchema,
    WebAuthnRegistrationCompleteSchema,
    WebAuthnLoginBeginSchema,
    WebAuthnLoginCompleteSchema,
    WebAuthnCredentialRenameSchema,
)
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.webauthn_service import WebAuthnService
from gatehouse_app.services.user_service import UserService
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.constants import AuditAction
from gatehouse_app.exceptions.auth_exceptions import InvalidCredentialsError
from gatehouse_app.exceptions.validation_exceptions import ConflictError, NotFoundError


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
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Validate request data
        schema = LoginSchema()
        data = schema.load(request.json)

        # Authenticate user with email and password
        user = AuthService.authenticate(
            email=data["email"],
            password=data["password"],
        )

        # SECURITY CHECK: Log MFA enrollment status to validate the vulnerability
        has_totp = user.has_totp_enabled()
        has_webauthn = user.has_webauthn_enabled()
        logger.warning(f"[SECURITY DIAGNOSTIC] Login attempt for user {user.email} - TOTP enabled: {has_totp}, WebAuthn enabled: {has_webauthn}")

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
        # SECURITY DIAGNOSTIC: This is where the vulnerability occurs - no WebAuthn check!
        if has_webauthn:
            logger.error(f"[SECURITY VULNERABILITY DETECTED] User {user.email} has WebAuthn enrolled but is bypassing it! Creating session without MFA verification.")
        
        # Evaluate MFA policy after primary authentication
        remember_me = data.get("remember_me", False)
        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me)

        # Create session with appropriate duration based on remember_me preference
        duration = 2592000 if remember_me else 86400  # 30 days vs 1 day

        # Determine if this should be a compliance-only session
        is_compliance_only = policy_result.create_compliance_only_session

        user_session = AuthService.create_session(
            user,
            duration_seconds=duration,
            is_compliance_only=is_compliance_only
        )

        # Build response data
        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z" if user_session.expires_at.isoformat()[-1] != "Z" else user_session.expires_at.isoformat(),
        }

        # Add MFA compliance information
        if policy_result.compliance_summary:
            response_data["mfa_compliance"] = {
                "overall_status": policy_result.compliance_summary.overall_status,
                "missing_methods": policy_result.compliance_summary.missing_methods,
                "deadline_at": policy_result.compliance_summary.deadline_at,
                "orgs": [
                    {
                        "organization_id": org.organization_id,
                        "organization_name": org.organization_name,
                        "status": org.status,
                        "deadline_at": org.deadline_at,
                    }
                    for org in policy_result.compliance_summary.orgs
                ],
            }

        # Add requires_mfa_enrollment flag if compliance-only session
        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True

        return api_response(
            data=response_data,
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
    from gatehouse_app.services.session_service import SessionService

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
    from gatehouse_app.models.session import Session

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
        client_timestamp: Optional client UTC timestamp in seconds since epoch

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
        AuthService.verify_totp_enrollment(
            g.current_user,
            data["code"],
            client_utc_timestamp=data.get("client_timestamp"),
        )

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
        client_timestamp: Optional client UTC timestamp in seconds since epoch

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
        from gatehouse_app.models.user import User
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
            user,
            data["code"],
            data.get("is_backup_code", False),
            client_utc_timestamp=data.get("client_timestamp"),
        )

        # Evaluate MFA policy after primary authentication
        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me=False)

        # Determine if this should be a compliance-only session
        is_compliance_only = policy_result.create_compliance_only_session

        # Create session
        user_session = AuthService.create_session(user, is_compliance_only=is_compliance_only)

        # Clear temporary session
        session.pop("totp_pending_user_id", None)

        # Build response data
        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z"
            if user_session.expires_at.isoformat()[-1] != "Z"
            else user_session.expires_at.isoformat(),
        }

        # Add MFA compliance information
        if policy_result.compliance_summary:
            response_data["mfa_compliance"] = {
                "overall_status": policy_result.compliance_summary.overall_status,
                "missing_methods": policy_result.compliance_summary.missing_methods,
                "deadline_at": policy_result.compliance_summary.deadline_at,
                "orgs": [
                    {
                        "organization_id": org.organization_id,
                        "organization_name": org.organization_name,
                        "status": org.status,
                        "deadline_at": org.deadline_at,
                    }
                    for org in policy_result.compliance_summary.orgs
                ],
            }

        # Add requires_mfa_enrollment flag if compliance-only session
        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True

        return api_response(
            data=response_data,
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


# =============================================================================
# WebAuthn Passkey Endpoints
# =============================================================================


@api_v1_bp.route("/auth/webauthn/register/begin", methods=["POST"])
@login_required
def begin_webauthn_registration():
    """
    Begin WebAuthn passkey registration.
    
    Returns:
        200: PublicKeyCredentialCreationOptions (raw JSON, no wrapper)
        401: Not authenticated
    """
    user = g.current_user
    
    # Generate registration challenge
    options = WebAuthnService.generate_registration_challenge(user)
    
    # Return unwrapped JSON for WebAuthn
    return jsonify(options), 200


@api_v1_bp.route("/auth/webauthn/register/complete", methods=["POST"])
@login_required
def complete_webauthn_registration():
    """
    Complete WebAuthn passkey registration.
    
    Request body:
        id: Credential ID
        rawId: Base64URL-encoded credential ID
        type: "public-key"
        response: Attestation response data
        transports: List of transport types
    
    Returns:
        200: Registration successful
        400: Validation error
        401: Not authenticated
        409: Credential already exists
    """
    import base64
    import logging
    logger = logging.getLogger(__name__)
    
    user_email = g.current_user.email
    logger.info(f"WebAuthn registration completion started for user: {user_email}")
    
    try:
        # Validate request data
        schema = WebAuthnRegistrationCompleteSchema()
        data = schema.load(request.json)
        
        # Extract challenge from client data
        client_data_json_b64 = data.get("response", {}).get("clientDataJSON", "")
        
        if not client_data_json_b64:
            logger.error(f"WebAuthn registration failed - missing clientDataJSON for user: {user_email}")
            return api_response(
                success=False,
                message="Missing clientDataJSON in response",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        try:
            # Add padding if needed
            padding = 4 - (len(client_data_json_b64) % 4)
            if padding != 4:
                client_data_json_b64_padded = client_data_json_b64 + '=' * padding
            else:
                client_data_json_b64_padded = client_data_json_b64
            
            client_data_json = base64.urlsafe_b64decode(client_data_json_b64_padded)
            client_data_dict = json.loads(client_data_json)
            
        except Exception as e:
            logger.error(f"WebAuthn registration failed - client data decode error for user {user_email}: {e}")
            return api_response(
                success=False,
                message=f"Failed to decode client data JSON: {str(e)}",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        challenge = client_data_dict.get("challenge")
        
        if not challenge:
            logger.error(f"WebAuthn registration failed - no challenge in client data for user: {user_email}")
            return api_response(
                success=False,
                message="Invalid challenge in client data",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        # Verify registration response
        auth_method = WebAuthnService.verify_registration_response(
            g.current_user,
            data,
            challenge
        )
        
        logger.info(f"WebAuthn registration completed successfully for user: {user_email}")
        
        return api_response(
            data={
                "credential": auth_method.to_webauthn_dict(),
            },
            message="Passkey registered successfully",
            status=201,
        )
        
    except ValidationError as e:
        logger.error(f"WebAuthn registration validation error for user {user_email}: {e.messages}")
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
        
    except InvalidCredentialsError as e:
        logger.warning(f"WebAuthn registration failed for user {user_email}: {e.message}")
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )
        
    except Exception as e:
        logger.exception(f"WebAuthn registration unexpected error for user {user_email}: {e}")
        return api_response(
            success=False,
            message="An unexpected error occurred during registration",
            status=500,
            error_type="INTERNAL_ERROR",
        )


@api_v1_bp.route("/auth/webauthn/login/begin", methods=["POST"])
def begin_webauthn_login():
    """
    Begin WebAuthn passkey login.
    
    Request body:
        email: User email address
    
    Returns:
        200: PublicKeyCredentialRequestOptions (raw JSON, no wrapper)
        400: Validation error
        404: User not found
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Validate request data
        schema = WebAuthnLoginBeginSchema()
        data = schema.load(request.json)
        
        # Find user by email
        from gatehouse_app.models.user import User
        user = User.query.filter_by(
            email=data["email"].lower(),
            deleted_at=None
        ).first()
        
        if not user:
            logger.warning(f"WebAuthn login begin - user not found: {data['email']}")
            return api_response(
                success=False,
                message="User not found",
                status=404,
                error_type="NOT_FOUND",
            )
        
        # Check if user has any WebAuthn credentials
        if not user.has_webauthn_enabled():
            logger.warning(f"WebAuthn login begin - no credentials for user: {user.email}")
            return api_response(
                success=False,
                message="No passkeys found for this account",
                status=404,
                error_type="NOT_FOUND",
            )
        
        logger.info(f"WebAuthn login challenge generated for user: {user.email}")
        
        # Generate authentication challenge
        options = WebAuthnService.generate_authentication_challenge(user)
        
        # Store user_id in Flask session for WebAuthn verification
        session["webauthn_pending_user_id"] = user.id
        
        # Return unwrapped JSON for WebAuthn
        return jsonify(options), 200
        
    except ValidationError as e:
        logger.error(f"WebAuthn login begin validation error: {e.messages}")
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
    except Exception as e:
        logger.exception(f"WebAuthn login begin unexpected error: {e}")
        raise


@api_v1_bp.route("/auth/webauthn/login/complete", methods=["POST"])
def complete_webauthn_login():
    """
    Complete WebAuthn passkey login.
    
    Request body:
        id: Credential ID
        rawId: Base64URL-encoded credential ID
        type: "public-key"
        response: Assertion response data
    
    Returns:
        200: Login successful with session token
        400: Validation error
        401: Authentication failed
    """
    import logging
    import base64
    logger = logging.getLogger(__name__)
    
    try:
        # Get user from Flask session (stored by /begin endpoint)
        user_id = session.get("webauthn_pending_user_id")
        if not user_id:
            logger.error("WebAuthn login complete - no pending verification in session")
            return api_response(
                success=False,
                message="No pending WebAuthn verification. Please initiate login first.",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )
        
        # Validate request data
        schema = WebAuthnLoginCompleteSchema()
        data = schema.load(request.json)
        
        # Get user from database
        from gatehouse_app.models.user import User
        user = User.query.get(user_id)
        if not user:
            logger.error(f"WebAuthn login complete - user not found: {user_id}")
            return api_response(
                success=False,
                message="User not found",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )
        
        # Extract challenge from client data
        client_data = data.get("response", {}).get("clientDataJSON", "")
        
        client_data_json = base64.urlsafe_b64decode(client_data + "==")
        client_data_dict = json.loads(client_data_json)
        
        challenge = client_data_dict.get("challenge")
        
        if not challenge:
            logger.error(f"WebAuthn login complete - no challenge in client data for user: {user.email}")
            return api_response(
                success=False,
                message="Invalid challenge in client data",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        # Verify authentication response
        WebAuthnService.verify_authentication_response(
            user,
            data,
            challenge
        )
        
        # Evaluate MFA policy after primary authentication
        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me=False)
        
        # Determine if this should be a compliance-only session
        is_compliance_only = policy_result.create_compliance_only_session
        
        # Create session
        user_session = AuthService.create_session(user, is_compliance_only=is_compliance_only)
        
        # Clear pending session
        session.pop("webauthn_pending_user_id", None)
        
        logger.info(f"WebAuthn login completed successfully for user: {user.email}")
        
        # Build response data
        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z"
            if user_session.expires_at.isoformat()[-1] != "Z"
            else user_session.expires_at.isoformat(),
        }
        
        # Add MFA compliance information
        if policy_result.compliance_summary:
            response_data["mfa_compliance"] = {
                "overall_status": policy_result.compliance_summary.overall_status,
                "missing_methods": policy_result.compliance_summary.missing_methods,
                "deadline_at": policy_result.compliance_summary.deadline_at,
                "orgs": [
                    {
                        "organization_id": org.organization_id,
                        "organization_name": org.organization_name,
                        "status": org.status,
                        "deadline_at": org.deadline_at,
                    }
                    for org in policy_result.compliance_summary.orgs
                ],
            }
        
        # Add requires_mfa_enrollment flag if compliance-only session
        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True
        
        return api_response(
            data=response_data,
            message="Login successful",
        )
        
    except ValidationError as e:
        logger.error(f"WebAuthn login complete validation error: {e.messages}")
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
        
    except InvalidCredentialsError as e:
        logger.warning(f"WebAuthn login complete authentication failed: {e.message}")
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )
    
    except Exception as e:
        logger.exception(f"WebAuthn login complete unexpected error: {e}")
        raise


@api_v1_bp.route("/auth/webauthn/credentials", methods=["GET"])
@login_required
def list_webauthn_credentials():
    """
    List all WebAuthn passkey credentials for the current user.
    
    Returns:
        200: List of credentials
        401: Not authenticated
    """
    user = g.current_user
    credentials = WebAuthnService.get_user_credentials(user)
    
    return api_response(
        data={
            "credentials": [cred.to_webauthn_dict() for cred in credentials],
            "count": len(credentials),
        },
        message="Credentials retrieved successfully",
    )


@api_v1_bp.route("/auth/webauthn/credentials/<credential_id>", methods=["DELETE"])
@login_required
def delete_webauthn_credential(credential_id):
    """
    Delete a WebAuthn passkey credential.
    
    Args:
        credential_id: ID of the credential to delete
    
    Returns:
        200: Credential deleted successfully
        401: Not authenticated
        404: Credential not found
    """
    user = g.current_user
    
    # Check if this is the last credential
    credential_count = user.get_webauthn_credential_count()
    if credential_count <= 1:
        return api_response(
            success=False,
            message="Cannot delete the last passkey. Add another passkey first.",
            status=400,
            error_type="BAD_REQUEST",
        )
    
    # Delete the credential
    success = WebAuthnService.delete_credential(credential_id, user)
    
    if not success:
        return api_response(
            success=False,
            message="Credential not found",
            status=404,
            error_type="NOT_FOUND",
        )
    
    return api_response(
        message="Passkey deleted successfully",
    )


@api_v1_bp.route("/auth/webauthn/credentials/<credential_id>", methods=["PATCH"])
@login_required
def rename_webauthn_credential(credential_id):
    """
    Rename a WebAuthn passkey credential.
    
    Args:
        credential_id: ID of the credential to rename
    
    Request body:
        name: New name for the credential
    
    Returns:
        200: Credential renamed successfully
        400: Validation error
        401: Not authenticated
        404: Credential not found
    """
    try:
        # Validate request data
        schema = WebAuthnCredentialRenameSchema()
        data = schema.load(request.json)
        
        # Rename the credential
        success = WebAuthnService.rename_credential(
            credential_id,
            g.current_user,
            data["name"]
        )
        
        if not success:
            return api_response(
                success=False,
                message="Credential not found",
                status=404,
                error_type="NOT_FOUND",
            )
        
        # Get updated credential
        credential = WebAuthnService.get_credential_by_id(credential_id, g.current_user)
        
        return api_response(
            data={
                "credential": credential.to_webauthn_dict() if credential else None,
            },
            message="Passkey renamed successfully",
        )
        
    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/auth/webauthn/status", methods=["GET"])
@login_required
def get_webauthn_status():
    """
    Get WebAuthn status for the current user.
    
    Returns:
        200: WebAuthn status with webauthn_enabled and credential_count
        401: Not authenticated
    """
    user = g.current_user
    
    return api_response(
        data={
            "webauthn_enabled": user.has_webauthn_enabled(),
            "credential_count": user.get_webauthn_credential_count(),
        },
        message="WebAuthn status retrieved successfully",
    )

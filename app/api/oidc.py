"""OIDC (OpenID Connect) API endpoints - Root level blueprint."""
import base64
import json
import logging
import secrets
from urllib.parse import urlencode, urlparse, parse_qs

import bcrypt
from flask import Blueprint, request, redirect, jsonify, session, g, current_app, Response

logger = logging.getLogger(__name__)

from app.utils.response import api_response
from app.services.oidc_service import (
    OIDCService, InvalidClientError, InvalidGrantError, InvalidRequestError
)
from app.services.auth_service import AuthService
from app.extensions import db
from app.extensions import bcrypt as flask_bcrypt
from app.models import User, OIDCClient
from app.models.organization import Organization
from app.exceptions.auth_exceptions import InvalidCredentialsError


# Create OIDC blueprint registered at root level
oidc_bp = Blueprint("oidc", __name__)


# ============================================================================
# Helper Functions
# ============================================================================

def get_oidc_config():
    """Get OIDC configuration from app config."""
    base_url = current_app.config.get("OIDC_ISSUER_URL", "http://localhost:5000")
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oidc/authorize",
        "token_endpoint": f"{base_url}/oidc/token",
        "userinfo_endpoint": f"{base_url}/oidc/userinfo",
        "jwks_uri": f"{base_url}/oidc/jwks",
        "registration_endpoint": f"{base_url}/oidc/register",
        "revocation_endpoint": f"{base_url}/oidc/revoke",
        "introspection_endpoint": f"{base_url}/oidc/introspect",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub", "name", "email", "email_verified"],
    }


def authenticate_client(client_id, client_secret=None):
    """Authenticate an OIDC client.
    
    Args:
        client_id: The client ID
        client_secret: Optional client secret
    
    Returns:
        OIDCClient instance
    
    Raises:
        InvalidClientError: If authentication fails
    """
    # Debug logging for client validation (controlled by LOG_LEVEL)
    logger.debug(f"[OIDC] Client validation: client_id={client_id}, confidential={client_secret is not None}")
    
    client = OIDCClient.query.filter_by(client_id=client_id, is_active=True).first()
    if not client:
        logger.debug(f"[OIDC] Client validation: client_id={client_id}, exists=False")
        raise InvalidClientError("Invalid client")
    
    logger.debug(f"[OIDC] Client validation: client_id={client_id}, client_id_db={client.id}, exists=True")
    
    if client.is_confidential and client_secret:
        # Try Flask-Bcrypt first (new format)
        secret_match = _check_password_hash(client, client_secret)
        logger.debug(f"[OIDC] Client secret validation: client_id={client_id}, match={secret_match}")
        if not secret_match:
            raise InvalidClientError("Invalid client credentials")
    
    return client


def require_valid_token():
    """Validate Bearer token from Authorization header.
    
    Sets g.current_token and g.current_user on success.
    
    Raises:
        InvalidGrantError: If token is invalid
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise InvalidGrantError("Invalid token: Missing or invalid Authorization header")
    
    token = auth_header[7:]
    claims = OIDCService.validate_access_token(token)
    g.current_token = claims
    
    user = User.query.get(claims.get("sub"))
    if not user:
        raise InvalidGrantError("Invalid token: User not found")
    
    g.current_user = user


def _check_password_hash(client, password):
    """Check password hash with backward compatibility for old bcrypt format.
    
    Tries Flask-Bcrypt first (new format), then falls back to raw bcrypt (old format).
    If old format matches, re-hashes with new format for migration.
    """
    pw_hash = client.client_secret_hash
    
    # Try Flask-Bcrypt first (new format)
    try:
        return flask_bcrypt.check_password_hash(pw_hash, password)
    except ValueError:
        # Invalid salt - try raw bcrypt (old format)
        pass
    
    # Try raw bcrypt (old format) as fallback
    try:
        match = bcrypt.checkpw(
            pw_hash.encode('utf-8') if isinstance(pw_hash, str) else pw_hash,
            password.encode('utf-8') if isinstance(password, str) else password
        )
        if match:
            # Migrate to new format
            new_hash = flask_bcrypt.generate_password_hash(
                password.decode('utf-8') if isinstance(password, bytes) else password
            ).decode('utf-8')
            client.client_secret_hash = new_hash
            db.session.commit()
            logger.info(f"[OIDC] Migrated client secret hash to new format: client_id={client.client_id}")
        return match
    except Exception:
        return False


def parse_basic_auth():
    """Parse Basic authentication from Authorization header.
    
    Returns:
        Tuple of (client_id, client_secret) or (None, None)
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            encoded = auth_header[6:]
            decoded = base64.b64decode(encoded).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
            return client_id, client_secret
        except Exception:
            pass
    return None, None


# ============================================================================
# Discovery Endpoint
# ============================================================================

@oidc_bp.route("/.well-known/openid-configuration", methods=["GET"])
def oidc_discovery():
    """OpenID Connect Discovery endpoint.
    
    Returns the OIDC configuration as JSON.
    
    Cache-Control: max-age=86400
    No authentication required.
    
    Returns:
        200: OIDC discovery document
    """
    config = get_oidc_config()
    
    response = jsonify(config)
    response.headers["Cache-Control"] = "max-age=86400"
    return response, 200


# ============================================================================
# Authorization Endpoint
# ============================================================================

@oidc_bp.route("/oidc/authorize", methods=["GET", "POST"])
def oidc_authorize():
    """OpenID Connect Authorization endpoint.
    
    Initiates the OIDC authentication flow.
    
    GET Parameters:
        client_id: The client ID
        redirect_uri: The redirect URI
        response_type: Must be "code" for authorization code flow
        scope: Space-separated scopes (e.g., "openid profile email")
        state: Opaque state value for CSRF protection
        nonce: Nonce for ID token replay protection
        code_challenge: PKCE code challenge
        code_challenge_method: PKCE method ("S256" or "plain")
        prompt: "login", "consent", "select_account", "none"
        max_age: Maximum authentication age in seconds
        acr_values: Requested Authentication Context Class Reference
    
    POST Parameters:
        Same as GET, plus:
        email: User email
        password: User password
    
    Returns:
        302: Redirect with authorization code or error
        200: Login page (GET when not authenticated)
        400: Invalid request
    """
    logger.debug("[OIDC] oidc_authorize called")

    
    # Parse request parameters
    if request.method == "GET":
        params = request.args.to_dict()
    else:
        params = request.form.to_dict()
    
    logger.debug("[OIDC] Raw request params: %s", params)
    # Extract required parameters
    logger.debug("[OIDC] Extracting request parameters...")
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    response_type = params.get("response_type")
    scope = params.get("scope", "")
    state = params.get("state", "")
    nonce = params.get("nonce", "")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method")
    
    logger.debug("[OIDC] Extracted parameters: client_id=%s, redirect_uri=%s, response_type=%s", client_id, redirect_uri, response_type)
    logger.debug("[OIDC] Extracted parameters: scope=%s, state=%s, nonce=%s", scope, state, nonce)
    logger.debug("[OIDC] Extracted parameters: code_challenge=%s, code_challenge_method=%s", code_challenge, code_challenge_method)
    
    # Validate required parameters
    logger.debug("[OIDC] Validating required parameters...")
    errors = []
    if not client_id:
        errors.append("client_id is required")
    if not redirect_uri:
        errors.append("redirect_uri is required")
    if not response_type:
        errors.append("response_type is required")
    
    logger.debug("[OIDC] Parameter validation errors: %s", errors)
    if errors:
        logger.debug("[OIDC] Redirecting with error: invalid_request")
        return _redirect_with_error(redirect_uri, "invalid_request", "; ".join(errors), state)
    
    # Validate response_type
    logger.debug("[OIDC] Validating response_type: %s", response_type)
    if response_type != "code":
        logger.debug("[OIDC] Redirecting with error: unsupported_response_type")
        return _redirect_with_error(
            redirect_uri, "unsupported_response_type",
            "Only response_type=code is supported", state
        )
    logger.debug("[OIDC] response_type validation passed")
    
    # Validate client
    logger.debug("[OIDC] Validating client: client_id=%s", client_id)
    client = OIDCClient.query.filter_by(client_id=client_id, is_active=True).first()
    
    logger.debug("[OIDC] Client query result: client=%s", client)
    logger.debug("[OIDC] Client validation: client_id=%s, exists=%s, is_confidential=%s",
                 client_id, client is not None, client.is_confidential if client else None)
    
    if not client:
        logger.debug("[OIDC] Redirecting with error: unauthorized_client (client not found)")
        return _redirect_with_error(redirect_uri, "unauthorized_client", "Invalid client", state)
    logger.debug("[OIDC] Client validation passed")
    
    # Validate redirect URI
    logger.debug("[OIDC] Validating redirect_uri: %s", redirect_uri)
    logger.debug("[OIDC] Client allowed redirect_uris: %s", client.redirect_uris)
    is_redirect_allowed = client.is_redirect_uri_allowed(redirect_uri)
    logger.debug("[OIDC] Redirect URI validation result: %s", is_redirect_allowed)
    
    if not is_redirect_allowed:
        logger.debug("[OIDC] Redirecting with error: invalid_request (redirect_uri not allowed)")
        return _redirect_with_error(redirect_uri, "invalid_request", "Invalid redirect_uri", state)
    logger.debug("[OIDC] Redirect URI validation passed")
    
    # Validate scopes
    logger.debug("[OIDC] Validating scopes...")
    requested_scopes = scope.split() if scope else []
    allowed_scopes = client.scopes or []
    valid_scopes = [s for s in requested_scopes if s in allowed_scopes]
    
    logger.debug("[OIDC] Requested scopes: %s", requested_scopes)
    logger.debug("[OIDC] Allowed scopes: %s", allowed_scopes)
    logger.debug("[OIDC] Valid scopes: %s", valid_scopes)
    
    if not valid_scopes:
        logger.debug("[OIDC] Redirecting with error: invalid_scope (no valid scopes)")
        return _redirect_with_error(redirect_uri, "invalid_scope", "Invalid or no scopes requested", state)
    logger.debug("[OIDC] Scope validation passed")
    
    # Check if user is already authenticated via session
    logger.debug("[OIDC] Checking session for existing authentication...")
    user_id = session.get("oidc_user_id")
    logger.debug("[OIDC] Session oidc_user_id: %s", user_id)
    
    # Handle POST with credentials
    if request.method == "POST" and not user_id:
        logger.debug("[OIDC] POST request with credentials (user not authenticated)")
        email = params.get("email")
        password = params.get("password")
        
        logger.debug("[OIDC] Email provided: %s", email is not None)
        logger.debug("[OIDC] Password provided: %s", password is not None)
        
        if not email or not password:
            logger.debug("[OIDC] Showing login page: missing credentials")
            return _show_login_page(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                response_type=response_type,
                error="Invalid credentials"
            )
        
        logger.debug("[OIDC] Attempting user authentication for email: %s", email)
        try:
            user = AuthService.authenticate(email, password)
            user_id = user.id
            session["oidc_user_id"] = user_id
            
            logger.debug("[OIDC] User authentication successful: user_id=%s, email=%s", user_id, email)
        except InvalidCredentialsError:
            logger.debug("[OIDC] User authentication failed: invalid credentials for email=%s", email)
            return _show_login_page(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                response_type=response_type,
                error="Invalid email or password"
            )
    
    # If no user, show login page
    if not user_id:
        logger.debug("[OIDC] No authenticated user, showing login page")
        return _show_login_page(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            response_type=response_type
        )
    
    logger.debug("[OIDC] User authenticated: user_id=%s", user_id)
    
    # User is authenticated, generate authorization code
    logger.debug("[OIDC] User is authenticated, fetching user from database...")
    user = User.query.get(user_id)
    logger.debug("[OIDC] User query result: %s", user)
    
    if not user:
        logger.debug("[OIDC] Redirecting with error: server_error (user not found)")
        return _redirect_with_error(redirect_uri, "server_error", "User not found", state)
    
    logger.debug("[OIDC] Generating authorization code...")
    logger.debug("[OIDC] Authorization code params: client_id=%s, user_id=%s, redirect_uri=%s", client_id, user_id, redirect_uri)
    logger.debug("[OIDC] Authorization code params: scopes=%s, state=%s, nonce=%s", valid_scopes, state, nonce)
    logger.debug("[OIDC] Authorization code params: code_challenge=%s, code_challenge_method=%s", code_challenge, code_challenge_method)
    
    try:
        code = OIDCService.generate_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=valid_scopes,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
        logger.debug("[OIDC] Authorization code generated successfully: %s...", code[:20] if code else None)
    except Exception as e:
        logger.debug("[OIDC] Authorization code generation failed: %s", str(e))
        return _redirect_with_error(redirect_uri, "server_error", str(e), state)
    
    # Redirect with authorization code
    logger.debug("[OIDC] Redirecting with authorization code...")
    redirect_params = {"code": code}
    if state:
        redirect_params["state"] = state
    
    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
    logger.debug("[OIDC] Redirect URL: %s...", redirect_url[:100] if redirect_url else None)
    logger.debug("[OIDC] oidc_authorize completed successfully")
    logger.debug("[OIDC] ===========================================")
    
    return redirect(redirect_url)


def _redirect_with_error(redirect_uri, error, error_description, state=None):
    """Redirect to client with error parameters."""
    if not redirect_uri:
        return api_response(
            success=False,
            message=error_description,
            status=400,
            error_type=error.upper(),
            error_details={"error": error, "error_description": error_description},
        )
    
    params = {
        "error": error,
        "error_description": error_description,
    }
    if state:
        params["state"] = state
    
    return redirect(f"{redirect_uri}?{urlencode(params)}")


def _show_login_page(client_id, redirect_uri, scope, state, nonce, response_type, error=None):
    """Show the login page for authorization."""
    # Simple HTML login page
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sign In - OIDC Authorization</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #333; font-size: 24px; margin-bottom: 20px; }}
            .form-group {{ margin-bottom: 15px; }}
            label {{ display: block; margin-bottom: 5px; color: #555; font-weight: bold; }}
            input[type="email"], input[type="password"] {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
            button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
            button:hover {{ background: #0056b3; }}
            .error {{ color: #dc3545; margin-bottom: 15px; }}
            .cancel {{ text-align: center; margin-top: 15px; }}
            .cancel a {{ color: #666; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Sign In</h1>
            {"<p class='error'>" + error + "</p>" if error else ""}
            <form method="POST">
                <input type="hidden" name="client_id" value="{client_id}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="scope" value="{scope}">
                <input type="hidden" name="state" value="{state}">
                <input type="hidden" name="nonce" value="{nonce}">
                <input type="hidden" name="response_type" value="{response_type}">
                
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit">Sign In</button>
            </form>
            <p class="cancel">
                <a href="{redirect_uri}">Cancel</a>
            </p>
        </div>
    </body>
    </html>
    """
    return Response(html, mimetype="text/html"), 200


# ============================================================================
# Token Endpoint
# ============================================================================

@oidc_bp.route("/oidc/token", methods=["POST"])
def oidc_token():
    """OpenID Connect Token endpoint.
    
    Exchanges authorization code for tokens or refreshes tokens.
    
    Request body (application/x-www-form-urlencoded):
        grant_type: "authorization_code" or "refresh_token"
        
        For authorization_code:
            code: The authorization code
            redirect_uri: The redirect URI used in authorization
            client_id: The client ID
            client_secret: The client secret (optional if using Basic auth)
            code_verifier: PKCE code verifier (optional)
        
        For refresh_token:
            refresh_token: The refresh token
            scope: Optional scope override
            client_id: The client ID
            client_secret: The client secret (optional if using Basic auth)
    
    Authentication:
        - Basic auth with client_id:client_secret, or
        - client_id + client_secret in request body
    
    Returns:
        200: JSON with tokens
        400: Invalid request
        401: Invalid client
    """
    # Parse request body
    if request.content_type and "application/x-www-form-urlencoded" in request.content_type:
        data = request.form.to_dict()
    else:
        data = request.json or {}
    
    # Debug: Log all incoming request parameters
    logger.debug("[OIDC] oidc_token incoming request params:")
    logger.debug("[OIDC]   content_type: %s", request.content_type)
    logger.debug("[OIDC]   method: %s", request.method)
    logger.debug("[OIDC]   headers: %s", dict(request.headers))
    logger.debug("[OIDC]   data: %s", data)
    logger.debug("[OIDC]   raw_data: %s", request.get_data(as_text=True))
    
    grant_type = data.get("grant_type")
    
    # Debug: Log grant_type and client info
    logger.debug("[OIDC]   grant_type: %s", grant_type)
    
    # Validate grant_type
    if not grant_type:
        logger.error("[OIDC]   grant_type is requred")
        return api_response(
            success=False,
            message="grant_type is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "grant_type is required"},
        )
    
    # Authenticate client
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    
    # Try Basic auth if client_id not in body
    if not client_id:
        client_id, client_secret = parse_basic_auth()
    
    if not client_id:
        # Return 401 with WWW-Authenticate header for Basic auth
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Client authentication required"
        })
        response.headers["WWW-Authenticate"] = 'Basic realm="OIDC Token Endpoint"'
        return response, 401
    
    try:
        # Development-only debug logging for token endpoint client authentication
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token endpoint client authentication: client_id={client_id}")
        
        client = authenticate_client(client_id, client_secret)
        
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token endpoint client validation: client_id={client_id}, client_db_id={client.id}, success=True")
    except InvalidClientError:
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token endpoint client validation: client_id={client_id}, success=False")
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Invalid client credentials"
        })
        return response, 401
    
    # Handle authorization_code grant
    if grant_type == "authorization_code":
        logger.debug(f"[OIDC] Handling authorization_code")
        return _handle_authorization_code_grant(data, client)
    
    # Handle refresh_token grant
    elif grant_type == "refresh_token":
        return _handle_refresh_token_grant(data, client)
    
    # Unsupported grant type
    else:
        logger.error("[OIDC]   Unsupported grant_type")
        return api_response(
            success=False,
            message="Unsupported grant_type",
            status=400,
            error_type="UNSUPPORTED_GRANT_TYPE",
            error_details={"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' is not supported"},
        )


def _handle_authorization_code_grant(data, client):
    """Handle authorization_code grant type."""
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    code_verifier = data.get("code_verifier")
    
    if not code:
        logger.error("[OIDC]   code is required")
        return api_response(
            success=False,
            message="code is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "code is required"},
        )
    
    if not redirect_uri:
        logger.error("[OIDC]   redirect_uri is required")
        return api_response(
            success=False,
            message="redirect_uri is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "redirect_uri is required"},
        )
    
    try:
        # Development-only debug logging for authorization code validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Authorization code validation: client_id={client.client_id}, code_provided=True")
        
        claims, user = OIDCService.validate_authorization_code(
            code=code,
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except InvalidGrantError as e:
        logger.error(f"[OIDC]   INVALID_GRANT: {str(e)}")
        return api_response(
            success=False,
            message=str(e),
            status=400,
            error_type="INVALID_GRANT",
            error_details={"error": "invalid_grant", "error_description": str(e)},
        )
    except Exception as e:
        logger.error(f"[OIDC]   Authorization code validation error: {type(e).__name__}: {str(e)}")
        return api_response(
            success=False,
            message=str(e),
            status=400,
            error_type="INVALID_GRANT",
            error_details={"error": "invalid_grant", "error_description": str(e)},
        )
    
    # Generate tokens
    try:
        # Development-only debug logging for token generation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token generation: client_id={client.client_id}, user_id={claims['user_id']}, scope={claims['scope']}")
        
        tokens = OIDCService.generate_tokens(
            client_id=client.client_id,
            user_id=claims["user_id"],
            scope=claims["scope"],
            nonce=claims.get("nonce"),
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            auth_time=int(__import__("time").time()),
        )
    except Exception as e:
        logger.error(f"[OIDC]   Failed to generate tokens {str(e)}")
        return api_response(
            success=False,
            message="Failed to generate tokens",
            status=500,
            error_type="SERVER_ERROR",
            error_details={"error": "server_error", "error_description": str(e)},
        )
    
    return api_response(
        data=tokens,
        message="Tokens issued successfully",
        status=200,
    )


def _handle_refresh_token_grant(data, client):
    """Handle refresh_token grant type."""
    refresh_token = data.get("refresh_token")
    scope = data.get("scope")
    
    if not refresh_token:
        return api_response(
            success=False,
            message="refresh_token is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "refresh_token is required"},
        )
    
    # Parse scope if provided
    scope_list = scope.split() if scope else None
    
    try:
        tokens = OIDCService.refresh_access_token(
            refresh_token=refresh_token,
            client_id=client.client_id,
            scope=scope_list,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except InvalidGrantError as e:
        return api_response(
            success=False,
            message=str(e),
            status=400,
            error_type="INVALID_GRANT",
            error_details={"error": "invalid_grant", "error_description": str(e)},
        )
    
    return api_response(
        data=tokens,
        message="Tokens refreshed successfully",
        status=200,
    )


# ============================================================================
# UserInfo Endpoint
# ============================================================================

@oidc_bp.route("/oidc/userinfo", methods=["GET", "POST"])
def oidc_userinfo():
    """OpenID Connect UserInfo endpoint.
    
    Returns claims about the authenticated user.
    
    Authorization: Bearer {access_token}
    
    Returns claims based on granted scopes:
        - sub: User ID (always included)
        - name: User full name (if "profile" scope)
        - email: User email (if "email" scope)
        - email_verified: Email verification status (if "email" scope)
    
    Returns:
        200: User claims
        401: Invalid or insufficient token
    """
    try:
        require_valid_token()
    except InvalidGrantError as e:
        return api_response(
            success=False,
            message=str(e),
            status=401,
            error_type="INVALID_TOKEN",
            error_details={"error": "invalid_token", "error_description": str(e)},
        )
    
    # Get userinfo
    try:
        userinfo = OIDCService.get_userinfo(g.current_token.get("access_token", ""))
    except Exception as e:
        return api_response(
            success=False,
            message="Failed to get user info",
            status=500,
            error_type="SERVER_ERROR",
            error_details={"error": "server_error", "error_description": str(e)},
        )
    
    return api_response(
        data=userinfo,
        message="User info retrieved successfully",
        status=200,
    )


# ============================================================================
# JWKS Endpoint
# ============================================================================

@oidc_bp.route("/oidc/jwks", methods=["GET"])
def oidc_jwks():
    """OpenID Connect JSON Web Key Set endpoint.
    
    Returns the public keys used to sign tokens.
    
    Cache-Control: max-age=3600
    No authentication required.
    
    Returns:
        200: JWKS document
    """
    try:
        jwks = OIDCService.get_jwks()
    except Exception as e:
        return api_response(
            success=False,
            message="Failed to get JWKS",
            status=500,
            error_type="SERVER_ERROR",
            error_details={"error": "server_error", "error_description": str(e)},
        )
    
    response = jsonify(jwks)
    response.headers["Cache-Control"] = "max-age=3600"
    return response, 200


# ============================================================================
# Token Revocation Endpoint
# ============================================================================

@oidc_bp.route("/oidc/revoke", methods=["POST"])
def oidc_revoke():
    """OAuth2 Token Revocation endpoint.
    
    Revokes an access token or refresh token.
    
    Request body (application/x-www-form-urlencoded):
        token: The token to revoke
        token_type_hint: Optional hint ("access_token" or "refresh_token")
        client_id: The client ID
        client_secret: The client secret (optional if using Basic auth)
    
    Authentication:
        - Basic auth with client_id:client_secret, or
        - client_id + client_secret in request body
    
    Returns:
        200: Token revoked successfully
        400: Invalid request
        401: Invalid client
    """
    # Parse request body
    if request.content_type and "application/x-www-form-urlencoded" in request.content_type:
        data = request.form.to_dict()
    else:
        data = request.json or {}
    
    token = data.get("token")
    
    if not token:
        return api_response(
            success=False,
            message="token is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "token is required"},
        )
    
    # Authenticate client
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    
    if not client_id:
        client_id, client_secret = parse_basic_auth()
    
    if not client_id:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Client authentication required"
        })
        response.headers["WWW-Authenticate"] = 'Basic realm="OIDC Revoke Endpoint"'
        return response, 401
    
    try:
        client = authenticate_client(client_id, client_secret)
    except InvalidClientError:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Invalid client credentials"
        })
        return response, 401
    
    token_type_hint = data.get("token_type_hint")
    
    try:
        OIDCService.revoke_token(
            token=token,
            client_id=client.client_id,
            token_type_hint=token_type_hint,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception as e:
        # Revocation should succeed even if token is invalid
        pass
    
    return api_response(
        message="Token revoked successfully",
        status=200,
    )


# ============================================================================
# Token Introspection Endpoint
# ============================================================================

@oidc_bp.route("/oidc/introspect", methods=["POST"])
def oidc_introspect():
    """OAuth2 Token Introspection endpoint.
    
    Returns information about a token.
    
    Request body (application/x-www-form-urlencoded):
        token: The token to introspect
        token_type_hint: Optional hint ("access_token" or "refresh_token")
        client_id: The client ID
        client_secret: The client secret (optional if using Basic auth)
    
    Authentication:
        - Basic auth with client_id:client_secret, or
        - client_id + client_secret in request body
    
    Returns:
        200: Token status and claims
        400: Invalid request
        401: Invalid client
    """
    # Parse request body
    if request.content_type and "application/x-www-form-urlencoded" in request.content_type:
        data = request.form.to_dict()
    else:
        data = request.json or {}
    
    token = data.get("token")
    
    if not token:
        return api_response(
            success=False,
            message="token is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "token is required"},
        )
    
    # Authenticate client
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    
    if not client_id:
        client_id, client_secret = parse_basic_auth()
    
    if not client_id:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Client authentication required"
        })
        response.headers["WWW-Authenticate"] = 'Basic realm="OIDC Introspect Endpoint"'
        return response, 401
    
    try:
        client = authenticate_client(client_id, client_secret)
    except InvalidClientError:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Invalid client credentials"
        })
        return response, 401
    
    token_type_hint = data.get("token_type_hint")
    
    try:
        result = OIDCService.introspect_token(
            token=token,
            client_id=client.client_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception as e:
        return api_response(
            success=False,
            message="Failed to introspect token",
            status=500,
            error_type="SERVER_ERROR",
            error_details={"error": "server_error", "error_description": str(e)},
        )
    
    return api_response(
        data=result,
        message="Token introspection successful",
        status=200,
    )


# ============================================================================
# Client Registration Endpoint (Optional)
# ============================================================================

@oidc_bp.route("/oidc/register", methods=["POST"])
def oidc_register():
    """OpenID Connect Client Registration endpoint.
    
    Registers a new OIDC client.
    
    Request body (application/json):
        client_name: Name of the client
        redirect_uris: List of redirect URIs
        token_endpoint_auth_method: "client_secret_basic" or "client_secret_post"
        grant_types: List of grant types ["authorization_code", "refresh_token"]
        response_types: List of response types ["code"]
        scope: Space-separated scopes (default: "openid profile email")
    
    Returns:
        201: Client registered successfully
        400: Invalid request
    """
    data = request.json or {}
    
    # Validate required fields
    client_name = data.get("client_name")
    redirect_uris = data.get("redirect_uris", [])
    
    if not client_name:
        return api_response(
            success=False,
            message="client_name is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "client_name is required"},
        )
    
    if not redirect_uris:
        return api_response(
            success=False,
            message="redirect_uris is required",
            status=400,
            error_type="INVALID_REQUEST",
            error_details={"error": "invalid_request", "error_description": "redirect_uris is required"},
        )
    
    # Validate redirect_uris
    for uri in redirect_uris:
        try:
            parsed = urlparse(uri)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid redirect URI: {uri}")
        except Exception:
            return api_response(
                success=False,
                message=f"Invalid redirect_uri: {uri}",
                status=400,
                error_type="INVALID_REQUEST",
                error_details={"error": "invalid_request", "error_description": f"Invalid redirect_uri: {uri}"},
            )
    
    # Generate client credentials
    client_id = f"oidc_{secrets.token_urlsafe(16)}"
    client_secret = f"secret_{secrets.token_urlsafe(24)}"
    client_secret_hash = flask_bcrypt.generate_password_hash(client_secret).decode("utf-8")
    
    # Get organization from request or default
    org_id = data.get("organization_id")
    if org_id:
        organization = Organization.query.get(org_id)
    else:
        # Get first active organization or create a default one
        organization = Organization.query.filter_by(is_active=True).first()
    
    if not organization:
        # Create a default organization for the client
        organization = Organization(
            name=f"OIDC Clients",
            slug=f"oidc-clients-{secrets.token_urlsafe(8)}",
        )
        organization.save()
    
    # Create OIDC client
    client = OIDCClient(
        organization_id=organization.id,
        name=client_name,
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        redirect_uris=redirect_uris,
        grant_types=data.get("grant_types", ["authorization_code", "refresh_token"]),
        response_types=data.get("response_types", ["code"]),
        scopes=data.get("scope", "openid profile email").split(),
        token_endpoint_auth_method=data.get("token_endpoint_auth_method", "client_secret_basic"),
        is_active=True,
        is_confidential=True,
        require_pkce=True,
        logo_uri=data.get("logo_uri"),
        client_uri=data.get("client_uri"),
        policy_uri=data.get("policy_uri"),
        tos_uri=data.get("tos_uri"),
    )
    client.save()
    
    # Return client credentials
    return api_response(
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(__import__("time").time()),
            "client_secret_expires_at": 0,  # Never expires
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": data.get("token_endpoint_auth_method", "client_secret_basic"),
            "grant_types": client.grant_types,
            "response_types": client.response_types,
            "scope": " ".join(client.scopes),
        },
        message="Client registered successfully",
        status=201,
    )

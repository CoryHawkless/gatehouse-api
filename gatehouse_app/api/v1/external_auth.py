"""External authentication provider endpoints."""
import logging
from flask import request, g
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.services.external_auth_service import (
    ExternalAuthService,
    ExternalAuthError,
)
from gatehouse_app.services.oauth_flow_service import (
    OAuthFlowService,
    OAuthFlowError,
)
from gatehouse_app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


# Provider type mapping
PROVIDER_TYPE_MAP = {
    "google": AuthMethodType.GOOGLE,
    "github": AuthMethodType.GITHUB,
    "microsoft": AuthMethodType.MICROSOFT,
}


def get_provider_type(provider: str) -> AuthMethodType:
    """Get AuthMethodType from provider string."""
    provider_lower = provider.lower()
    if provider_lower not in PROVIDER_TYPE_MAP:
        raise ExternalAuthError(
            f"Unsupported provider: {provider}",
            "UNSUPPORTED_PROVIDER",
            400,
        )
    return PROVIDER_TYPE_MAP[provider_lower]


# =============================================================================
# Provider Configuration Endpoints (Admin)
# =============================================================================

@api_v1_bp.route("/auth/external/providers", methods=["GET"])
@login_required
def list_providers():
    """
    List available external authentication providers for current organization.

    Returns:
        200: List of providers with their configuration status
        401: Not authenticated
    """
    from gatehouse_app.models import Organization
    from gatehouse_app.services.external_auth_service import ExternalProviderConfig

    # Get user's primary organization
    user_orgs = g.current_user.get_organizations()
    if not user_orgs:
        return api_response(
            success=False,
            message="No organizations found for user",
            status=400,
            error_type="BAD_REQUEST",
        )

    organization_id = user_orgs[0].id

    # Get all configured providers for organization
    configs = ExternalProviderConfig.query.filter_by(
        organization_id=organization_id,
    ).all()

    configured_providers = {c.provider_type.lower(): c for c in configs}

    # Provider definitions
    providers = [
        {
            "id": "google",
            "name": "Google",
            "type": "google",
            "is_configured": "google" in configured_providers,
            "is_active": configured_providers.get("google", {}).is_active if "google" in configured_providers else False,
            "settings": {
                "requires_domain": False,
                "supports_refresh_tokens": True,
            },
        },
        {
            "id": "github",
            "name": "GitHub",
            "type": "github",
            "is_configured": "github" in configured_providers,
            "is_active": configured_providers.get("github", {}).is_active if "github" in configured_providers else False,
            "settings": {
                "requires_domain": False,
                "supports_refresh_tokens": True,
            },
        },
        {
            "id": "microsoft",
            "name": "Microsoft",
            "type": "microsoft",
            "is_configured": "microsoft" in configured_providers,
            "is_active": configured_providers.get("microsoft", {}).is_active if "microsoft" in configured_providers else False,
            "settings": {
                "requires_domain": False,
                "supports_refresh_tokens": True,
            },
        },
    ]

    return api_response(
        data={"providers": providers},
        message="Providers retrieved successfully",
    )


@api_v1_bp.route("/auth/external/providers/<provider>/config", methods=["GET"])
@login_required
def get_provider_config(provider: str):
    """
    Get provider configuration (admin only).

    Args:
        provider: Provider type (google, github, microsoft)

    Returns:
        200: Provider configuration
        401: Not authenticated
        403: Not authorized (not admin)
        404: Provider not configured
    """
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.services.external_auth_service import ExternalProviderConfig

    provider_type = get_provider_type(provider)

    # Get user's primary organization
    user_orgs = g.current_user.get_organizations()
    if not user_orgs:
        return api_response(
            success=False,
            message="No organizations found for user",
            status=400,
            error_type="BAD_REQUEST",
        )

    organization_id = user_orgs[0].id

    # Check if user is admin
    member = OrganizationMember.query.filter_by(
        user_id=g.current_user.id,
        organization_id=organization_id,
    ).first()

    if not member or member.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(
            success=False,
            message="Admin access required",
            status=403,
            error_type="FORBIDDEN",
        )

    # Get provider config
    config = ExternalProviderConfig.query.filter_by(
        organization_id=organization_id,
        provider_type=provider_type.value,
    ).first()

    if not config:
        return api_response(
            success=False,
            message=f"{provider.title()} OAuth is not configured",
            status=404,
            error_type="NOT_FOUND",
        )

    return api_response(
        data=config.to_dict(include_secrets=False),
        message="Provider configuration retrieved successfully",
    )


@api_v1_bp.route("/auth/external/providers/<provider>/config", methods=["POST"])
@login_required
def create_or_update_provider_config(provider: str):
    """
    Create or update provider configuration (admin only).

    Args:
        provider: Provider type (google, github, microsoft)

    Request body:
        client_id: OAuth client ID
        client_secret: OAuth client secret
        scopes: List of OAuth scopes
        redirect_uris: List of allowed redirect URIs
        settings: Provider-specific settings
        is_active: Whether the provider is active

    Returns:
        200: Provider configuration updated
        201: Provider configuration created
        400: Validation error
        401: Not authenticated
        403: Not authorized (not admin)
    """
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.services.external_auth_service import ExternalProviderConfig

    provider_type = get_provider_type(provider)

    # Get user's primary organization
    user_orgs = g.current_user.get_organizations()
    if not user_orgs:
        return api_response(
            success=False,
            message="No organizations found for user",
            status=400,
            error_type="BAD_REQUEST",
        )

    organization_id = user_orgs[0].id

    # Check if user is admin
    member = OrganizationMember.query.filter_by(
        user_id=g.current_user.id,
        organization_id=organization_id,
    ).first()

    if not member or member.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(
            success=False,
            message="Admin access required",
            status=403,
            error_type="FORBIDDEN",
        )

    # Validate request data
    data = request.json or {}
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    if not client_id:
        return api_response(
            success=False,
            message="client_id is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    # Get or create config
    config = ExternalProviderConfig.query.filter_by(
        organization_id=organization_id,
        provider_type=provider_type.value,
    ).first()

    is_new = config is None

    if config:
        # Update existing
        config.client_id = client_id
        if client_secret:
            config.set_client_secret(client_secret)
        config.scopes = data.get("scopes", ["openid", "profile", "email"])
        config.redirect_uris = data.get("redirect_uris", [])
        config.settings = data.get("settings", {})
        config.is_active = data.get("is_active", True)
        config.save()

        # Audit log - config update
        AuditService.log_external_auth_config_update(
            user_id=g.current_user.id,
            organization_id=organization_id,
            provider_type=provider_type.value,
            config_id=config.id,
            changes={
                "client_id": "updated",
                "client_secret": "updated" if client_secret else None,
                "scopes": data.get("scopes"),
                "redirect_uris": data.get("redirect_uris"),
                "is_active": config.is_active,
            },
        )
    else:
        # Create new - get provider endpoints
        auth_url, token_url, userinfo_url = _get_provider_endpoints(provider_type)

        config = ExternalProviderConfig(
            organization_id=organization_id,
            provider_type=provider_type.value,
            client_id=client_id,
            client_secret_encrypted=None,
            auth_url=auth_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            scopes=data.get("scopes", ["openid", "profile", "email"]),
            redirect_uris=data.get("redirect_uris", []),
            settings=data.get("settings", {}),
            is_active=data.get("is_active", True),
        )

        if client_secret:
            config.set_client_secret(client_secret)

        config.save()

        # Audit log - config create
        AuditService.log_external_auth_config_create(
            user_id=g.current_user.id,
            organization_id=organization_id,
            provider_type=provider_type.value,
            config_id=config.id,
        )

    return api_response(
        data=config.to_dict(include_secrets=False),
        message="Provider configuration saved successfully",
        status=201 if is_new else 200,
    )


@api_v1_bp.route("/auth/external/providers/<provider>/config", methods=["DELETE"])
@login_required
def delete_provider_config(provider: str):
    """
    Delete provider configuration (admin only).

    Args:
        provider: Provider type (google, github, microsoft)

    Returns:
        200: Provider configuration deleted
        401: Not authenticated
        403: Not authorized (not admin)
        404: Provider not configured
    """
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.services.external_auth_service import ExternalProviderConfig

    provider_type = get_provider_type(provider)

    # Get user's primary organization
    user_orgs = g.current_user.get_organizations()
    if not user_orgs:
        return api_response(
            success=False,
            message="No organizations found for user",
            status=400,
            error_type="BAD_REQUEST",
        )

    organization_id = user_orgs[0].id

    # Check if user is admin
    member = OrganizationMember.query.filter_by(
        user_id=g.current_user.id,
        organization_id=organization_id,
    ).first()

    if not member or member.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(
            success=False,
            message="Admin access required",
            status=403,
            error_type="FORBIDDEN",
        )

    # Get and delete config
    config = ExternalProviderConfig.query.filter_by(
        organization_id=organization_id,
        provider_type=provider_type.value,
    ).first()

    if not config:
        return api_response(
            success=False,
            message=f"{provider.title()} OAuth is not configured",
            status=404,
            error_type="NOT_FOUND",
        )

    config_id = config.id
    config.delete()

    # Audit log - config delete
    AuditService.log_external_auth_config_delete(
        user_id=g.current_user.id,
        organization_id=organization_id,
        provider_type=provider_type.value,
        config_id=config_id,
    )

    return api_response(
        message=f"{provider.title()} provider configuration deleted successfully",
    )


# =============================================================================
# Account Linking Endpoints
# =============================================================================

@api_v1_bp.route("/auth/external/linked-accounts", methods=["GET"])
@login_required
def list_linked_accounts():
    """
    List all linked external accounts for the current user.

    Returns:
        200: List of linked accounts
        401: Not authenticated
    """
    linked_accounts = ExternalAuthService.get_linked_accounts(g.current_user.id)

    # Check if user has other auth methods (for unlink availability)
    from gatehouse_app.models import AuthenticationMethod
    other_methods = AuthenticationMethod.query.filter_by(
        user_id=g.current_user.id,
    ).count()

    return api_response(
        data={
            "linked_accounts": linked_accounts,
            "unlink_available": other_methods > 1,
        },
        message="Linked accounts retrieved successfully",
    )


@api_v1_bp.route("/auth/external/<provider>/link", methods=["POST"])
@login_required
def initiate_link_account(provider: str):
    """
    Initiate OAuth flow to link an external account.

    Args:
        provider: Provider type (google, github, microsoft)

    Request body:
        redirect_uri: Optional redirect URI after linking

    Returns:
        302: Redirect to provider authorization page
        400: Validation error or provider not configured
        401: Not authenticated
    """
    provider_type = get_provider_type(provider)

    # Get user's organization
    user_orgs = g.current_user.get_organizations()
    organization_id = user_orgs[0].id if user_orgs else None

    # Get optional redirect URI
    data = request.json or {}
    redirect_uri = data.get("redirect_uri")

    try:
        # Initiate link flow
        auth_url, state = ExternalAuthService.initiate_link_flow(
            user_id=g.current_user.id,
            provider_type=provider_type,
            organization_id=organization_id,
            redirect_uri=redirect_uri,
        )

        return api_response(
            data={
                "authorization_url": auth_url,
                "state": state,
            },
            message="Link flow initiated. Redirect to authorization URL.",
        )

    except ExternalAuthError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/external/<provider>/unlink", methods=["DELETE"])
@login_required
def unlink_account(provider: str):
    """
    Unlink an external account from the user's profile.

    Args:
        provider: Provider type (google, github, microsoft)

    Returns:
        200: Account unlinked successfully
        400: Validation error or cannot unlink last method
        401: Not authenticated
        404: Provider not linked
    """
    provider_type = get_provider_type(provider)

    # Get user's organization
    user_orgs = g.current_user.get_organizations()
    organization_id = user_orgs[0].id if user_orgs else None

    try:
        ExternalAuthService.unlink_provider(
            user_id=g.current_user.id,
            provider_type=provider_type,
            organization_id=organization_id,
        )

        return api_response(
            message=f"{provider.title()} account unlinked successfully",
        )

    except ExternalAuthError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


# =============================================================================
# OAuth Flow Endpoints
# =============================================================================

@api_v1_bp.route("/auth/external/<provider>/authorize", methods=["GET"])
def initiate_oauth_authorize(provider: str):
    """
    Initiate OAuth authentication or account registration flow.
    
    This endpoint initiates OAuth flows without requiring organization_id upfront.
    The organization context is determined after successful authentication based on
    the user's memberships.

    Args:
        provider: Provider type (google, github, microsoft)

    Query parameters:
        flow: 'login' or 'register' (default: 'login')
        redirect_uri: Optional redirect URI after OAuth completion
        organization_id: Optional organization hint (for SSO discovery)

    Returns:
        200: Authorization URL and state token
        400: Validation error or provider not configured at application level
        
    Response:
        {
            "authorization_url": "https://...",
            "state": "state_token"
        }
    """
    provider_type = get_provider_type(provider)

    # Get query parameters - organization_id is now optional
    flow = request.args.get("flow", "login")
    redirect_uri = request.args.get("redirect_uri")
    organization_id = request.args.get("organization_id")  # Optional hint

    if flow not in ["login", "register"]:
        return api_response(
            success=False,
            message="Invalid flow type. Must be 'login' or 'register'",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    try:
        # Initiate flow - organization_id is now optional
        if flow == "login":
            auth_url, state = OAuthFlowService.initiate_login_flow(
                provider_type=provider_type,
                organization_id=organization_id,  # Optional hint
                redirect_uri=redirect_uri,
            )
        else:
            auth_url, state = OAuthFlowService.initiate_register_flow(
                provider_type=provider_type,
                organization_id=organization_id,  # Optional hint
                redirect_uri=redirect_uri,
            )

        return api_response(
            data={
                "authorization_url": auth_url,
                "state": state,
            },
            message=f"OAuth {flow} flow initiated",
        )

    except OAuthFlowError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/external/<provider>/callback", methods=["GET"])
def handle_oauth_callback(provider: str):
    """
    Handle OAuth callback from provider.
    
    This endpoint handles the redirect from the OAuth provider after authentication.
    It processes the response and handles different scenarios:
    - Successful login/register with redirect_uri: Redirects with authorization code
    - Successful login/register without redirect_uri: Returns session token
    - Login with multiple orgs: Returns list of organizations for user to select
    - Register with no org: Prompts for organization creation/selection

    Args:
        provider: Provider type (google, github, microsoft)

    Query parameters:
        code: Authorization code from provider
        state: State parameter from OAuth flow
        redirect_uri: Optional redirect URI for OAuth 2.0 Authorization Code flow
        error: Error code if auth failed at provider
        error_description: Human-readable error description

    Returns:
        302: Redirect with authorization code (if redirect_uri provided)
        200: OAuth flow completed successfully (JSON response)
        400: Validation error, OAuth error, or invalid state
        404: User account not found (for login flows)
        
    Response formats (when redirect_uri NOT provided):
        
        Success with session:
        {
            "token": "session_token",
            "expires_in": 86400,
            "token_type": "Bearer",
            "user": {...}
        }
        
        Requires organization selection (login flow):
        {
            "requires_org_selection": true,
            "user": {...},
            "available_organizations": [...],
            "state": "state_token"
        }
        
        Requires organization creation (register flow):
        {
            "requires_org_creation": true,
            "user": {...},
            "state": "state_token"
        }
    """
    provider_type = get_provider_type(provider)

    # Get callback parameters
    authorization_code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description = request.args.get("error_description")

    # Get redirect URI from query parameter (for OAuth 2.0 Authorization Code flow)
    redirect_uri = request.args.get("redirect_uri")

    try:
        result = OAuthFlowService.handle_callback(
            provider_type=provider_type,
            authorization_code=authorization_code,
            state=state,
            redirect_uri=redirect_uri,
            error=error,
            error_description=error_description,
        )

        if result.get("success"):
            flow_type = result.get("flow_type")
            
            # Check if we should redirect with authorization code
            if redirect_uri and flow_type in ["login", "register"]:
                # Generate authorization code for external application
                user_id = result.get("user", {}).get("id")
                if not user_id:
                    # For org selection/creation flows, we can't redirect
                    pass
                else:
                    # Determine organization_id
                    organization_id = result.get("user", {}).get("organization_id")
                    if not organization_id:
                        # Can't redirect without organization
                        pass
                    else:
                        # Generate authorization code
                        auth_code = OAuthFlowService.generate_authorization_code(
                            user_id=user_id,
                            client_id="external-app",
                            redirect_uri=redirect_uri,
                            scope=["openid", "profile", "email"],
                            ip_address=request.remote_addr,
                            user_agent=request.headers.get("User-Agent"),
                            lifetime_seconds=600,  # 10 minutes
                        )
                        
                        # Mark state as used
                        state_record = OAuthFlowService.validate_state(state)
                        if state_record:
                            state_record.mark_used()
                        
                        # Redirect with authorization code
                        return OAuthFlowService.create_redirect_response(
                            redirect_uri=redirect_uri,
                            authorization_code=auth_code,
                            state=state,
                        )
            
            # Handle login flow responses (no redirect_uri or org selection required)
            if flow_type == "login":
                # Check if organization selection is required
                if result.get("requires_org_selection"):
                    return api_response(
                        data={
                            "requires_org_selection": True,
                            "user": result["user"],
                            "available_organizations": result["available_organizations"],
                            "state": result["state"],
                        },
                        message="Please select an organization to continue",
                        status=200,
                    )
                
                # Normal login with session
                return api_response(
                    data={
                        "token": result["session"]["token"],
                        "expires_in": result["session"].get("expires_in", 86400),
                        "token_type": "Bearer",
                        "user": result["user"],
                    },
                    message="Login successful",
                )
            
            # Handle register flow responses
            elif flow_type == "register":
                # Check if organization creation is required
                if result.get("requires_org_creation"):
                    return api_response(
                        data={
                            "requires_org_creation": True,
                            "user": result["user"],
                            "state": result["state"],
                        },
                        message="Please create or select an organization to continue",
                        status=200,
                    )
                
                # Normal registration with session
                return api_response(
                    data={
                        "token": result["session"]["token"],
                        "expires_in": result["session"].get("expires_in", 86400),
                        "token_type": "Bearer",
                        "user": result["user"],
                    },
                    message="Registration successful",
                )
            
            # Handle link flow responses
            elif flow_type == "link":
                return api_response(
                    data={
                        "linked_account": result["linked_account"],
                    },
                    message="Account linked successfully",
                )

        # Fallback for unexpected result format
        return api_response(
            data=result,
            message="OAuth flow completed",
        )

    except OAuthFlowError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/external/select-organization", methods=["POST"])
def select_organization():
    """
    Complete OAuth flow by selecting an organization.
    
    This endpoint is called after OAuth callback when the user needs to select
    which organization to log in to (when user belongs to multiple orgs).

    Request body:
        state: The state token from the OAuth callback
        organization_id: The selected organization ID

    Returns:
        200: Session created successfully
        400: Invalid state or organization
        404: Organization not found or user not a member
        
    Response:
        {
            "token": "session_token",
            "expires_in": 86400,
            "token_type": "Bearer",
            "user": {
                "id": "...",
                "email": "...",
                "full_name": "...",
                "organization_id": "..."
            }
        }
    """
    data = request.json or {}
    state_token = data.get("state")
    organization_id = data.get("organization_id")

    if not state_token:
        return api_response(
            success=False,
            message="state is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    if not organization_id:
        return api_response(
            success=False,
            message="organization_id is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    try:
        # Validate state and get OAuth state record
        state_record = OAuthFlowService.validate_state(state_token)
        if not state_record or state_record.used:
            return api_response(
                success=False,
                message="Invalid or expired state token",
                status=400,
                error_type="INVALID_STATE",
            )

        # The state should have user information from the OAuth callback
        # We need to find the user that was authenticated
        from gatehouse_app.models import User, AuthenticationMethod, Organization, OrganizationMember
        
        # Find user by provider authentication
        # The state record should have provider info in extra_data if set by callback
        # Otherwise, we need to find the most recently created auth method
        auth_method = AuthenticationMethod.query.filter_by(
            method_type=state_record.provider_type,
        ).order_by(AuthenticationMethod.created_at.desc()).first()
        
        if not auth_method:
            return api_response(
                success=False,
                message="Authentication session not found",
                status=400,
                error_type="SESSION_NOT_FOUND",
            )

        user = auth_method.user
        
        # Verify user is member of selected organization
        org = Organization.query.get(organization_id)
        if not org:
            return api_response(
                success=False,
                message="Organization not found",
                status=404,
                error_type="NOT_FOUND",
            )

        member = OrganizationMember.query.filter_by(
            user_id=user.id,
            organization_id=organization_id,
        ).first()

        if not member:
            return api_response(
                success=False,
                message="You are not a member of this organization",
                status=403,
                error_type="FORBIDDEN",
            )

        # Create session for the selected organization
        from gatehouse_app.services.session_service import SessionService
        session = SessionService.create_session(
            user=user,
            organization_id=organization_id,
        )

        # Mark state as used
        state_record.mark_used()

        # Audit log - login success with org selection
        AuditService.log_external_auth_login(
            user_id=user.id,
            organization_id=organization_id,
            provider_type=state_record.provider_type.value if isinstance(state_record.provider_type, AuthMethodType) else state_record.provider_type,
            provider_user_id=auth_method.provider_user_id,
            auth_method_id=auth_method.id,
            session_id=session.id,
        )

        return api_response(
            data={
                "token": session.token,
                "expires_in": session.lifetime_seconds,
                "token_type": "Bearer",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "organization_id": organization_id,
                },
            },
            message="Organization selected and session created successfully",
        )

    except Exception as e:
        logger.error(f"Error in select_organization: {str(e)}", exc_info=True)
        return api_response(
            success=False,
            message="An error occurred while selecting organization",
            status=500,
            error_type="INTERNAL_ERROR",
        )


# =============================================================================
# Authorization Code Exchange Endpoint
# =============================================================================

@api_v1_bp.route("/auth/external/token", methods=["POST"])
def exchange_authorization_code():
    """
    Exchange an authorization code for a session token.
    
    This endpoint is used by external applications (like oauth2-proxy, BookStack)
    to exchange the authorization code received from the OAuth callback for a
    session token.
    
    Request body (form-encoded or JSON):
        grant_type: Must be "authorization_code"
        code: The authorization code from the callback
        redirect_uri: The redirect URI used in the original request
        client_id: The client ID (optional, defaults to "external-app")
    
    Returns:
        200: Session token exchanged successfully
        400: Invalid or expired authorization code
        404: User not found
        
    Response:
        {
            "token": "session_token",
            "expires_in": 86400,
            "token_type": "Bearer",
            "user": {
                "id": "...",
                "email": "...",
                "full_name": "...",
                "organization_id": "..."
            }
        }
    """
    # Support both JSON and form-encoded requests
    if request.is_json:
        data = request.json or {}
    else:
        data = request.form or {}
    
    grant_type = data.get("grant_type")
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    client_id = data.get("client_id", "external-app")
    
    # Validate required parameters
    if grant_type and grant_type != "authorization_code":
        return api_response(
            success=False,
            message="Invalid grant_type. Must be 'authorization_code'",
            status=400,
            error_type="INVALID_GRANT_TYPE",
        )
    
    if not code:
        return api_response(
            success=False,
            message="code is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )
    
    if not redirect_uri:
        return api_response(
            success=False,
            message="redirect_uri is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )
    
    try:
        result = OAuthFlowService.exchange_authorization_code(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            ip_address=request.remote_addr,
        )
        
        return api_response(
            data={
                "token": result["token"],
                "expires_in": result["expires_in"],
                "token_type": result["token_type"],
                "user": result["user"],
            },
            message="Token exchanged successfully",
        )
        
    except OAuthFlowError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


# =============================================================================
# Helper Functions
# =============================================================================

def _get_provider_endpoints(provider_type: AuthMethodType):
    """Get OAuth endpoints for a provider."""
    if provider_type == AuthMethodType.GOOGLE:
        return (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://www.googleapis.com/oauth2/v3/userinfo",
        )
    elif provider_type == AuthMethodType.GITHUB:
        return (
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
        )
    elif provider_type == AuthMethodType.MICROSOFT:
        return (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "https://graph.microsoft.com/oidc/userinfo",
        )
    else:
        raise ExternalAuthError(
            f"Unsupported provider: {provider_type}",
            "UNSUPPORTED_PROVIDER",
            400,
        )

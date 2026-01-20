"""External authentication provider endpoints."""
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

    Args:
        provider: Provider type (google, github, microsoft)

    Query parameters:
        flow: 'login' or 'register'
        redirect_uri: Optional redirect URI
        organization_id: Optional organization context

    Returns:
        302: Redirect to provider authorization page
        400: Validation error or provider not configured
    """
    provider_type = get_provider_type(provider)

    # Get query parameters
    flow = request.args.get("flow", "login")
    redirect_uri = request.args.get("redirect_uri")
    organization_id = request.args.get("organization_id")

    if flow not in ["login", "register"]:
        return api_response(
            success=False,
            message="Invalid flow type. Must be 'login' or 'register'",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    try:
        if flow == "login":
            auth_url, state = OAuthFlowService.initiate_login_flow(
                provider_type=provider_type,
                organization_id=organization_id,
                redirect_uri=redirect_uri,
            )
        else:
            auth_url, state = OAuthFlowService.initiate_register_flow(
                provider_type=provider_type,
                organization_id=organization_id,
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

    Args:
        provider: Provider type (google, github, microsoft)

    Query parameters:
        code: Authorization code from provider
        state: State parameter
        error: Error code if auth failed
        error_description: Human-readable error description

    Returns:
        200: OAuth flow completed successfully
        302: Redirect with error
        400: Validation error or OAuth error
    """
    provider_type = get_provider_type(provider)

    # Get callback parameters
    authorization_code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description = request.args.get("error_description")

    # Get redirect URI from state if available
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
            if result.get("flow_type") == "login":
                return api_response(
                    data={
                        "token": result["session"]["token"],
                        "expires_in": result["session"].get("expires_in", 86400),
                        "token_type": "Bearer",
                        "user": result["user"],
                    },
                    message="Login successful",
                )
            elif result.get("flow_type") == "register":
                return api_response(
                    data={
                        "token": result["session"]["token"],
                        "expires_in": result["session"].get("expires_in", 86400),
                        "token_type": "Bearer",
                        "user": result["user"],
                    },
                    message="Registration successful",
                )
            elif result.get("flow_type") == "link":
                return api_response(
                    data={
                        "linked_account": result["linked_account"],
                    },
                    message="Account linked successfully",
                )

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

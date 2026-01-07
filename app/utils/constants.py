"""Application constants and enums."""
from enum import Enum


class UserStatus(str, Enum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class OrganizationRole(str, Enum):
    """Organization member roles."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class AuthMethodType(str, Enum):
    """Authentication method types."""

    PASSWORD = "password"
    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    SAML = "saml"
    OIDC = "oidc"


class SessionStatus(str, Enum):
    """Session status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuditAction(str, Enum):
    """Audit log action types."""

    # User actions
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_REGISTER = "user.register"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    PASSWORD_CHANGE = "user.password_change"
    PASSWORD_RESET = "user.password_reset"

    # Organization actions
    ORG_CREATE = "org.create"
    ORG_UPDATE = "org.update"
    ORG_DELETE = "org.delete"
    ORG_MEMBER_ADD = "org.member.add"
    ORG_MEMBER_REMOVE = "org.member.remove"
    ORG_MEMBER_ROLE_CHANGE = "org.member.role_change"

    # Session actions
    SESSION_CREATE = "session.create"
    SESSION_REVOKE = "session.revoke"

    # Auth method actions
    AUTH_METHOD_ADD = "auth.method.add"
    AUTH_METHOD_REMOVE = "auth.method.remove"


class OIDCGrantType(str, Enum):
    """OIDC grant types."""

    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"


class OIDCResponseType(str, Enum):
    """OIDC response types."""

    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


# Error type constants
class ErrorType:
    """Error type constants for API responses."""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    BAD_REQUEST = "BAD_REQUEST"

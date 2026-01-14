"""Authentication and authorization exceptions."""
from gatehouse_app.exceptions.base import BaseAPIException


class UnauthorizedError(BaseAPIException):
    """Raised when authentication is required but not provided."""

    status_code = 401
    error_type = "AUTHENTICATION_ERROR"
    message = "Authentication required"


class ForbiddenError(BaseAPIException):
    """Raised when user lacks permissions for the requested action."""

    status_code = 403
    error_type = "AUTHORIZATION_ERROR"
    message = "You don't have permission to perform this action"


class InvalidCredentialsError(BaseAPIException):
    """Raised when login credentials are invalid."""

    status_code = 401
    error_type = "AUTHENTICATION_ERROR"
    message = "Invalid email or password"


class AccountSuspendedError(BaseAPIException):
    """Raised when user account is suspended."""

    status_code = 403
    error_type = "AUTHORIZATION_ERROR"
    message = "Your account has been suspended"


class AccountInactiveError(BaseAPIException):
    """Raised when user account is inactive."""

    status_code = 403
    error_type = "AUTHORIZATION_ERROR"
    message = "Your account is inactive"


class SessionExpiredError(BaseAPIException):
    """Raised when user session has expired."""

    status_code = 401
    error_type = "AUTHENTICATION_ERROR"
    message = "Your session has expired. Please log in again"


class InvalidTokenError(BaseAPIException):
    """Raised when authentication token is invalid."""

    status_code = 401
    error_type = "AUTHENTICATION_ERROR"
    message = "Invalid authentication token"

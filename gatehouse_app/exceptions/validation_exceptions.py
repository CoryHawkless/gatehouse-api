"""Validation and resource exceptions."""
from gatehouse_app.exceptions.base import BaseAPIException


class ValidationError(BaseAPIException):
    """Raised when request data validation fails."""

    status_code = 400
    error_type = "VALIDATION_ERROR"
    message = "Validation failed"


class NotFoundError(BaseAPIException):
    """Raised when a requested resource is not found."""

    status_code = 404
    error_type = "NOT_FOUND"
    message = "Resource not found"


class ConflictError(BaseAPIException):
    """Raised when a resource conflict occurs."""

    status_code = 409
    error_type = "CONFLICT"
    message = "Resource conflict"


class BadRequestError(BaseAPIException):
    """Raised when the request is malformed or invalid."""

    status_code = 400
    error_type = "BAD_REQUEST"
    message = "Bad request"


class RateLimitExceededError(BaseAPIException):
    """Raised when rate limit is exceeded."""

    status_code = 429
    error_type = "RATE_LIMIT_EXCEEDED"
    message = "Too many requests. Please try again later"


class EmailAlreadyExistsError(ConflictError):
    """Raised when attempting to register with an existing email."""

    message = "Email address already registered"


class OrganizationNotFoundError(NotFoundError):
    """Raised when organization is not found."""

    message = "Organization not found"


class UserNotFoundError(NotFoundError):
    """Raised when user is not found."""

    message = "User not found"

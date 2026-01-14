"""Exceptions package."""
from gatehouse_app.exceptions.base import BaseAPIException
from gatehouse_app.exceptions.auth_exceptions import (
    UnauthorizedError,
    ForbiddenError,
    InvalidCredentialsError,
    AccountSuspendedError,
    AccountInactiveError,
    SessionExpiredError,
    InvalidTokenError,
)
from gatehouse_app.exceptions.validation_exceptions import (
    ValidationError,
    NotFoundError,
    ConflictError,
    BadRequestError,
    RateLimitExceededError,
    EmailAlreadyExistsError,
    OrganizationNotFoundError,
    UserNotFoundError,
)

__all__ = [
    "BaseAPIException",
    "UnauthorizedError",
    "ForbiddenError",
    "InvalidCredentialsError",
    "AccountSuspendedError",
    "AccountInactiveError",
    "SessionExpiredError",
    "InvalidTokenError",
    "ValidationError",
    "NotFoundError",
    "ConflictError",
    "BadRequestError",
    "RateLimitExceededError",
    "EmailAlreadyExistsError",
    "OrganizationNotFoundError",
    "UserNotFoundError",
]

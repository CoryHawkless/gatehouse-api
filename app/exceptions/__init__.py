"""Exceptions package."""
from app.exceptions.base import BaseAPIException
from app.exceptions.auth_exceptions import (
    UnauthorizedError,
    ForbiddenError,
    InvalidCredentialsError,
    AccountSuspendedError,
    AccountInactiveError,
    SessionExpiredError,
    InvalidTokenError,
)
from app.exceptions.validation_exceptions import (
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

"""Testing environment configuration."""
from config.base import BaseConfig


class TestingConfig(BaseConfig):
    """Testing configuration."""

    TESTING = True
    DEBUG = True

    # Use in-memory SQLite for testing
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ECHO = False

    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False

    # Fast password hashing for tests
    BCRYPT_LOG_ROUNDS = 4

    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False

    # Use different Redis DB for testing
    REDIS_URL = "redis://localhost:6379/15"

"""Development environment configuration."""
from config.base import BaseConfig


class DevelopmentConfig(BaseConfig):
    """Development configuration."""

    DEBUG = True
    SQLALCHEMY_ECHO = True
    SESSION_COOKIE_SECURE = False

    # More verbose logging in development
    LOG_LEVEL = "DEBUG"
    LOG_TO_STDOUT = True

    # Reduced bcrypt rounds for faster dev cycles
    BCRYPT_LOG_ROUNDS = 4

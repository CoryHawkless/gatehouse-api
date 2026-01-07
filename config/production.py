"""Production environment configuration."""
import os
from config.base import BaseConfig


class ProductionConfig(BaseConfig):
    """Production configuration."""

    DEBUG = False
    TESTING = False

    # Enforce environment variables in production
    SECRET_KEY = os.environ["SECRET_KEY"]
    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]

    # Strict security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"

    # Production logging
    LOG_LEVEL = "WARNING"
    LOG_TO_STDOUT = True

    # Strong password hashing
    BCRYPT_LOG_ROUNDS = 13

    # Disable SQL echo in production
    SQLALCHEMY_ECHO = False

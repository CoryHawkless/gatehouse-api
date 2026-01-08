"""Development environment configuration."""
from config.base import BaseConfig
import os

class DevelopmentConfig(BaseConfig):
    """Development configuration."""

    DEBUG = True
    # Use environment variable like BaseConfig does
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() == "true"
    SESSION_COOKIE_SECURE = False

    # More verbose logging in development
    LOG_LEVEL = "DEBUG"
    LOG_TO_STDOUT = True

    # Reduced bcrypt rounds for faster dev cycles
    BCRYPT_LOG_ROUNDS = 4

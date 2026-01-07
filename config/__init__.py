"""Configuration package."""
import os
from config.base import BaseConfig
from config.development import DevelopmentConfig
from config.testing import TestingConfig
from config.production import ProductionConfig


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(config_name=None):
    """Get configuration object based on environment."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")
    return config_by_name.get(config_name, DevelopmentConfig)

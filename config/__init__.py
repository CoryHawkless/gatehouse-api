"""Configuration package."""
import os
from config.base import BaseConfig
from config.development import DevelopmentConfig
from config.testing import TestingConfig


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config(config_name=None):
    """Get configuration object based on environment."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")
    
    # Lazy import of ProductionConfig to avoid requiring SECRET_KEY in non-production environments
    if config_name == "production":
        from config.production import ProductionConfig
        config_by_name["production"] = ProductionConfig
        return ProductionConfig
    
    return config_by_name.get(config_name, DevelopmentConfig)

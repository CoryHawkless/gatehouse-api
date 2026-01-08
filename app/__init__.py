"""Application factory."""
import os
import logging
from flask import Flask
from config import get_config
from app.extensions import db, migrate, bcrypt, ma, limiter, session
from app.middleware import RequestIDMiddleware, SecurityHeadersMiddleware, setup_cors
from app.exceptions.base import BaseAPIException
from app.utils.response import api_response
import redis

# Configure SQLAlchemy logging BEFORE any database operations
# This must be done before db.init_app() to prevent verbose logging
_log_level_env = os.getenv("SQLALCHEMY_LOG_LEVEL", "WARNING").upper()
_sqlalchemy_log_level = getattr(logging, _log_level_env, logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(_sqlalchemy_log_level)
logging.getLogger('sqlalchemy.engine').setLevel(_sqlalchemy_log_level)
logging.getLogger('sqlalchemy.dialects').setLevel(_sqlalchemy_log_level)
logging.getLogger('sqlalchemy.pool').setLevel(_sqlalchemy_log_level)


def create_app(config_name=None):
    """
    Create and configure the Flask application.

    Args:
        config_name: Configuration name (development, testing, production)

    Returns:
        Flask application instance
    """
    app = Flask(__name__)

    # Load configuration
    config = get_config(config_name)
    app.config.from_object(config)

    # Initialize extensions
    initialize_extensions(app)

    # Setup middleware
    setup_middleware(app)

    # Register blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    # Setup logging
    setup_logging(app)

    return app


def initialize_extensions(app):
    """Initialize Flask extensions."""
    # Database
    db.init_app(app)
    migrate.init_app(app, db)

    # Security
    bcrypt.init_app(app)

    # CORS - using custom middleware only (see app/middleware/cors.py)
    # Flask-CORS disabled to avoid conflicts
    # cors.init_app(app)

    # Marshmallow
    ma.init_app(app)

    # Rate limiting
    if app.config.get("RATELIMIT_ENABLED"):
        limiter.init_app(app)

    # Redis for sessions
    try:
        redis_url = app.config.get("REDIS_URL")
        if redis_url:
            redis_client = redis.from_url(redis_url)
            app.config["SESSION_REDIS"] = redis_client
    except Exception as e:
        app.logger.warning(f"Redis connection failed: {e}")

    # Flask-Session
    session.init_app(app)


def setup_middleware(app):
    """Setup application middleware."""
    RequestIDMiddleware(app)
    SecurityHeadersMiddleware(app)
    setup_cors(app)


def register_blueprints(app):
    """Register application blueprints."""
    from app.api import register_api_blueprints
    from app.api.oidc import oidc_bp

    register_api_blueprints(app)

    # Register OIDC blueprint at root level
    app.register_blueprint(oidc_bp)


def register_error_handlers(app):
    """Register error handlers."""

    @app.errorhandler(BaseAPIException)
    def handle_api_exception(error):
        """Handle custom API exceptions."""
        return api_response(
            success=False,
            message=error.message,
            status=error.status_code,
            error_type=error.error_type,
            error_details=error.error_details,
        )

    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 errors."""
        return api_response(
            success=False,
            message="Resource not found",
            status=404,
            error_type="NOT_FOUND",
        )

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Handle 405 errors."""
        return api_response(
            success=False,
            message="Method not allowed",
            status=405,
            error_type="METHOD_NOT_ALLOWED",
        )

    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle 500 errors."""
        app.logger.error(f"Internal server error: {error}")
        return api_response(
            success=False,
            message="Internal server error",
            status=500,
            error_type="INTERNAL_ERROR",
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle unexpected errors."""
        app.logger.error(f"Unexpected error: {error}", exc_info=True)
        return api_response(
            success=False,
            message="An unexpected error occurred",
            status=500,
            error_type="INTERNAL_ERROR",
        )


def setup_logging(app):
    """Setup application logging."""
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"))

    # Create formatter
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )

    # Configure root logger
    if app.config.get("LOG_TO_STDOUT"):
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(log_level)
        app.logger.addHandler(stream_handler)

    app.logger.setLevel(log_level)

    # Configure SQLAlchemy logging level (also set at module level before DB init)
    sqlalchemy_log_level = getattr(logging, app.config.get("SQLALCHEMY_LOG_LEVEL", "WARNING"), logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(sqlalchemy_log_level)
    logging.getLogger('sqlalchemy.engine').setLevel(sqlalchemy_log_level)
    logging.getLogger('sqlalchemy.dialects').setLevel(sqlalchemy_log_level)
    logging.getLogger('sqlalchemy.pool').setLevel(sqlalchemy_log_level)

    app.logger.info("Application startup")

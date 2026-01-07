"""CORS middleware configuration."""
from flask import request


def setup_cors(app, cors):
    """
    Configure CORS for the application.

    Args:
        app: Flask application instance
        cors: Flask-CORS instance
    """
    # CORS is already initialized in extensions.py
    # This function provides additional configuration if needed

    @app.after_request
    def after_request_cors(response):
        """Add additional CORS headers if needed."""
        origin = request.headers.get("Origin")
        cors_origins = app.config.get("CORS_ORIGINS", [])

        # Allow all origins in development if CORS_ORIGINS is "*"
        if cors_origins == "*" or origin in cors_origins:
            response.headers["Access-Control-Allow-Origin"] = origin if cors_origins != "*" else "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Request-ID"
            response.headers["Access-Control-Max-Age"] = "3600"

        return response

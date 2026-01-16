"""CORS middleware configuration."""
from flask import request, make_response


def setup_cors(app):
    """
    Configure CORS for the application.

    Args:
        app: Flask application instance
    """

    @app.before_request
    def handle_preflight():
        """Handle CORS preflight OPTIONS requests."""
        if request.method == "OPTIONS":
            origin = request.headers.get("Origin")
            cors_origins = app.config.get("CORS_ORIGINS", [])
            
            # Allow all origins if CORS_ORIGINS is "*" (string) or ["*"] (list with wildcard)
            allow_all = cors_origins == "*" or (isinstance(cors_origins, list) and "*" in cors_origins)
            
            if allow_all:
                response = make_response("", 204)
                response.headers["Access-Control-Allow-Origin"] = "*"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma"
                response.headers["Access-Control-Max-Age"] = "3600"
                response.headers["Cache-Control"] = "no-cache, no-store"
                return response
            elif origin and origin in cors_origins:
                response = make_response("", 204)
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma, X-WebAuthn-Session-Token"
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["Access-Control-Max-Age"] = "3600"
                response.headers["Cache-Control"] = "no-cache, no-store"
                return response

    @app.after_request
    def after_request_cors(response):
        """Add additional CORS headers if needed."""
        origin = request.headers.get("Origin")
        cors_origins = app.config.get("CORS_ORIGINS", [])

        # Allow all origins if CORS_ORIGINS is "*" (string) or ["*"] (list with wildcard)
        allow_all = cors_origins == "*" or (isinstance(cors_origins, list) and "*" in cors_origins)
        
        if allow_all:
            # When allowing all origins, set header to "*"
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma"
            response.headers["Access-Control-Max-Age"] = "3600"
        elif origin and origin in cors_origins:
            # When allowing specific origins, echo the request origin
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma, X-WebAuthn-Session-Token"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Max-Age"] = "3600"

        return response

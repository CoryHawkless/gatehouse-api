"""Security headers middleware."""
from flask import request


class SecurityHeadersMiddleware:
    """Middleware to add security headers to responses."""

    def __init__(self, app=None):
        """Initialize middleware."""
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app."""
        app.after_request(self.add_security_headers)

    @staticmethod
    def add_security_headers(response):
        """Add security headers to response."""
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Strict Transport Security (HSTS)
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'"
        )

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # Cache-Control: Allow OIDC endpoints to set their own Cache-Control
        # Only set no-cache for API responses that haven't set their own cache headers
        if "Cache-Control" not in response.headers:
            # Check if this is a JSON API response (shouldn't be cached)
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                response.headers["Cache-Control"] = "no-cache, no-store"
            elif "text/html" not in content_type:
                # For non-HTML responses, add Pragma for HTTP/1.0 compatibility
                response.headers["Pragma"] = "no-cache"

        return response

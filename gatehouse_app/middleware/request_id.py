"""Request ID middleware for request tracing."""
import uuid
from flask import g, request


class RequestIDMiddleware:
    """Middleware to add unique request ID to each request."""

    def __init__(self, app=None):
        """Initialize middleware."""
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)

    @staticmethod
    def before_request():
        """Generate or extract request ID before request processing."""
        # Check if request already has an ID from client
        request_id = request.headers.get("X-Request-ID")

        # Generate new ID if not provided
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in Flask g object for access throughout request
        g.request_id = request_id

    @staticmethod
    def after_request(response):
        """Add request ID to response headers."""
        if hasattr(g, "request_id"):
            response.headers["X-Request-ID"] = g.request_id
        return response

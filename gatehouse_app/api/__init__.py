"""API package."""
from flask import Blueprint
from gatehouse_app.utils.response import api_response

# Create main API blueprint
api_bp = Blueprint("api", __name__)


@api_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return api_response(
        data={"status": "healthy", "service": "authy2-backend"},
        message="Service is running",
    )


def register_api_blueprints(app):
    """Register all API blueprints."""
    from gatehouse_app.api.v1 import api_v1_bp

    # Register versioned API blueprints
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")

"""Flask extensions initialization."""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
cors = CORS(
    supports_credentials=True,
    resources={r"/api/*": {"origins": "*"}},  # Apply CORS to all API routes
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    expose_headers=["X-Request-ID"],
)
ma = Marshmallow()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="memory://",  # Will be overridden by config
)
session = Session()

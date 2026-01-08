# Authy2 Backend - Authentication & Authorization API

Production-ready Flask/SQLAlchemy API for authentication and authorization services.

## Features

- 🔐 **Multi-method Authentication**: Password, OAuth (Google, GitHub, Microsoft), SAML, OIDC
- 👥 **Multi-tenancy**: Organization-based access control with roles
- 🔑 **Session Management**: Secure session handling with Redis
- 📝 **Audit Logging**: Comprehensive activity tracking
- 🛡️ **Security**: Bcrypt password hashing, CORS, security headers, rate limiting
- 📊 **API Response Envelope**: Consistent response format across all endpoints
- ✅ **Validation**: Marshmallow schemas for request/response validation
- 🧪 **Testing**: Comprehensive unit and integration tests
- 📚 **Documentation**: OpenAPI/Swagger compatible

## Tech Stack

- **Framework**: Flask 3.0
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Caching/Sessions**: Redis
- **Validation**: Marshmallow
- **Testing**: Pytest
- **Security**: Flask-Bcrypt, Flask-CORS
- **Migration**: Flask-Migrate (Alembic)

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 6+

### Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd authy2/backend
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements/development.txt
```

4. **Set up environment variables**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Initialize database**:
```bash
python scripts/init_db.py
```

6. **Seed sample data** (optional):
```bash
python scripts/seed_data.py
```

7. **Run the application**:
```bash
flask run
# Or using the WSGI file
python wsgi.py
```

The API will be available at `http://localhost:5000`

## Project Structure

```
backend/
├── app/
│   ├── __init__.py           # Application factory
│   ├── api/                  # API endpoints
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── auth.py       # Authentication endpoints
│   │       ├── users.py      # User endpoints
│   │       └── organizations.py
│   ├── exceptions/           # Custom exceptions
│   ├── middleware/           # Middleware components
│   ├── models/               # Database models
│   ├── schemas/              # Marshmallow schemas
│   ├── services/             # Business logic layer
│   └── utils/                # Utilities
├── config/                   # Configuration files
├── docs/                     # Documentation
├── migrations/               # Database migrations
├── scripts/                  # Utility scripts
├── tests/                    # Test suite
│   ├── integration/
│   └── unit/
├── requirements/             # Dependencies
├── .env.example             # Environment variables template
├── pytest.ini               # Pytest configuration
├── pyproject.toml           # Project metadata
└── wsgi.py                  # WSGI entry point
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/me` - Get current user
- `GET /api/v1/auth/sessions` - Get user sessions
- `DELETE /api/v1/auth/sessions/:id` - Revoke session

### Users
- `GET /api/v1/users/me` - Get current user profile
- `PATCH /api/v1/users/me` - Update profile
- `DELETE /api/v1/users/me` - Delete account
- `POST /api/v1/users/me/password` - Change password
- `GET /api/v1/users/me/organizations` - Get user organizations

### Organizations
- `POST /api/v1/organizations` - Create organization
- `GET /api/v1/organizations/:id` - Get organization
- `PATCH /api/v1/organizations/:id` - Update organization
- `DELETE /api/v1/organizations/:id` - Delete organization
- `GET /api/v1/organizations/:id/members` - Get members
- `POST /api/v1/organizations/:id/members` - Add member
- `DELETE /api/v1/organizations/:id/members/:userId` - Remove member
- `PATCH /api/v1/organizations/:id/members/:userId/role` - Update role

### Health
- `GET /api/health` - Health check

## API Response Format

All API responses follow the standardized envelope format:

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Success message",
  "request_id": "uuid-v4",
  "data": {},
  "meta": {}
}
```

Error responses:

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Error message",
  "request_id": "uuid-v4",
  "error": {
    "type": "VALIDATION_ERROR",
    "details": {}
  }
}
```

## Testing

Run all tests:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=app --cov-report=html
```

Run specific test types:
```bash
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests only
```

## Database Migrations

Create a new migration:
```bash
flask db migrate -m "Description of changes"
```

Apply migrations:
```bash
flask db upgrade
```

Rollback:
```bash
flask db downgrade
```

## Development

### Code Quality

Run linter:
```bash
flake8 app/ tests/
```

Format code:
```bash
black app/ tests/
isort app/ tests/
```

### Environment Configuration

- **Development**: `FLASK_ENV=development`
- **Testing**: `FLASK_ENV=testing`
- **Production**: `FLASK_ENV=production`

## Production Deployment

### Using Gunicorn

```bash
pip install -r requirements/production.txt
gunicorn -w 4 -b 0.0.0.0:8000 wsgi:app
```

### Docker (example)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements/production.txt .
RUN pip install -r production.txt
COPY . .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "wsgi:app"]
```

### Environment Variables

Required production environment variables:
- `SECRET_KEY` - Flask secret key (must be random)
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `FLASK_ENV=production`

## Security Considerations

- All passwords hashed with Bcrypt (12+ rounds in production)
- CORS configured for allowed origins
- Security headers enabled (CSP, HSTS, etc.)
- Rate limiting on sensitive endpoints
- SQL injection protection via SQLAlchemy ORM
- Session management with secure cookies
- Request ID tracking for audit trails

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run test suite
6. Submit a pull request

## Support

For issues and questions:
- GitHub Issues: [repository-url]/issues
- Documentation: See `docs/` directory


# Boostrap db
python manage.py db upgrade
python manage.py db migrate



## running seed
python -m scripts.seed_data

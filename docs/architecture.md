# Authy2 Backend - Architecture Documentation

## Overview

This document describes the architecture and design decisions for the Authy2 backend authentication and authorization API.

## Architecture Pattern

The application follows a **layered architecture pattern** with clear separation of concerns:

```
┌─────────────────────────────────────┐
│          API Layer (Routes)         │  Flask blueprints, request validation
├─────────────────────────────────────┤
│       Service Layer (Business)      │  Business logic, orchestration
├─────────────────────────────────────┤
│        Data Layer (Models)          │  ORM models, database access
├─────────────────────────────────────┤
│          Database (PostgreSQL)      │  Data persistence
└─────────────────────────────────────┘
```

### Key Principles

1. **Separation of Concerns**: Each layer has distinct responsibilities
2. **Dependency Injection**: Extensions initialized separately
3. **Factory Pattern**: Application factory for flexible configuration
4. **Repository Pattern**: Service layer abstracts data access
5. **Single Responsibility**: Each module has one reason to change

## Component Structure

### 1. Application Factory (`app/__init__.py`)

Implements the factory pattern for creating Flask applications with different configurations.

**Responsibilities**:
- Initialize Flask app
- Load configuration
- Initialize extensions
- Register blueprints
- Setup middleware
- Register error handlers

### 2. Models Layer (`app/models/`)

SQLAlchemy ORM models representing the database schema.

**Key Models**:
- `User`: User accounts
- `Organization`: Multi-tenant organizations
- `OrganizationMember`: User-organization membership
- `AuthenticationMethod`: Multi-method authentication
- `Session`: User session management
- `AuditLog`: Activity tracking
- `OIDCClient`: OAuth2/OIDC clients

**Base Model Features**:
- UUID primary keys
- Timestamps (created_at, updated_at)
- Soft delete (deleted_at)
- Common methods (save, delete, update, to_dict)

### 3. Service Layer (`app/services/`)

Contains business logic and orchestrates data access.

**Services**:
- `AuthService`: Authentication operations
- `UserService`: User management
- `OrganizationService`: Organization management
- `SessionService`: Session management
- `AuditService`: Audit logging

**Benefits**:
- Keeps controllers thin
- Testable business logic
- Reusable across endpoints
- Transaction management

### 4. API Layer (`app/api/`)

Flask blueprints defining HTTP endpoints.

**Structure**:
- Versioned blueprints (`v1/`, future `v2/`)
- RESTful design
- Request validation with Marshmallow
- Response formatting

**Endpoint Groups**:
- `auth.py`: Authentication endpoints
- `users.py`: User profile endpoints
- `organizations.py`: Organization CRUD

### 5. Schemas (`app/schemas/`)

Marshmallow schemas for validation and serialization.

**Types**:
- Input validation schemas
- Output serialization schemas
- Nested schemas for relationships

### 6. Middleware (`app/middleware/`)

Request/response middleware components.

**Components**:
- `RequestIDMiddleware`: Request tracing
- `SecurityHeadersMiddleware`: Security headers
- `CORS`: Cross-origin resource sharing

### 7. Exceptions (`app/exceptions/`)

Custom exception hierarchy for API errors.

**Hierarchy**:
```
BaseAPIException
├── UnauthorizedError (401)
├── ForbiddenError (403)
├── ValidationError (400)
├── NotFoundError (404)
└── ConflictError (409)
```

### 8. Utilities (`app/utils/`)

Shared utilities and helpers.

**Components**:
- `response.py`: Standardized API responses
- `constants.py`: Enums and constants
- `decorators.py`: Authentication decorators

## Data Models

### User Model

```python
User
├── id: UUID (PK)
├── email: String (unique)
├── email_verified: Boolean
├── full_name: String
├── status: Enum (active, inactive, suspended)
├── last_login_at: DateTime
└── relationships:
    ├── authentication_methods
    ├── sessions
    ├── organization_memberships
    └── audit_logs
```

### Organization Model

```python
Organization
├── id: UUID (PK)
├── name: String
├── slug: String (unique)
├── description: Text
├── is_active: Boolean
├── settings: JSON
└── relationships:
    ├── members (OrganizationMember)
    └── oidc_clients
```

### Authentication Method Model

```python
AuthenticationMethod
├── id: UUID (PK)
├── user_id: UUID (FK)
├── method_type: Enum (password, google, github, oidc)
├── password_hash: String (for password auth)
├── provider_user_id: String (for OAuth)
├── provider_data: JSON
└── is_primary: Boolean
```

## Security Architecture

### Authentication Flow

1. User submits credentials
2. `AuthService.authenticate()` validates credentials
3. Session created with secure token
4. Token stored in Redis
5. Session ID returned to client
6. Subsequent requests authenticated via session

### Authorization Flow

1. Request includes session token
2. `@login_required` decorator validates session
3. User loaded into `g.current_user`
4. `@require_role` checks organization permissions
5. Request proceeds or returns 403

### Password Security

- Bcrypt hashing (12+ rounds in production)
- Configurable rounds per environment
- No plain-text passwords stored
- Password strength validation

### Session Security

- Secure session tokens (32-byte random)
- Configurable expiration
- Session revocation support
- IP and user agent tracking

## API Response Format

All responses follow a standardized envelope:

```json
{
  "version": "1.0",
  "success": boolean,
  "code": number,
  "message": string,
  "request_id": string,
  "data": object | null,
  "error": {
    "type": string,
    "details": object
  } | null,
  "meta": object | null
}
```

**Benefits**:
- Consistent client parsing
- Request tracing
- Error handling
- Pagination metadata

## Database Design

### Multi-Tenancy

Organizations provide multi-tenancy:
- Each org is isolated
- Users can belong to multiple orgs
- Role-based access per org

### Audit Trail

Comprehensive logging:
- All mutations logged
- User context captured
- IP and user agent tracked
- Queryable history

### Soft Deletes

All models support soft delete:
- `deleted_at` timestamp
- Allows recovery
- Maintains referential integrity
- Audit trail preserved

## Configuration Management

### Environment-based Config

```
config/
├── base.py           # Common settings
├── development.py    # Dev overrides
├── testing.py        # Test config
└── production.py     # Production settings
```

### Configuration Hierarchy

1. Base configuration
2. Environment-specific overrides
3. Environment variables (highest priority)

## Testing Strategy

### Unit Tests

- Test individual functions/methods
- Mock external dependencies
- Fast execution
- High coverage target (>80%)

### Integration Tests

- Test API endpoints end-to-end
- Use test database
- Verify request/response flow
- Authentication flow testing

### Test Fixtures

- Reusable test data
- Database setup/teardown
- Authenticated clients
- Sample users/organizations

## Deployment Architecture

### Recommended Setup

```
┌─────────────┐
│  Load       │
│  Balancer   │
└──────┬──────┘
       │
   ┌───┴────┐
   │        │
┌──▼──┐  ┌──▼──┐
│ Web  │  │ Web  │  Gunicorn workers
│ App  │  │ App  │
└──┬───┘  └──┬───┘
   │         │
   └────┬────┘
        │
    ┌───▼────┐
    │ Redis  │  Session storage
    └────────┘
        │
    ┌───▼────────┐
    │ PostgreSQL │  Data persistence
    └────────────┘
```

### Scaling Considerations

- Stateless application (sessions in Redis)
- Horizontal scaling via load balancer
- Database connection pooling
- Redis for distributed sessions
- Celery for background tasks (future)

## Error Handling

### Exception Hierarchy

All exceptions inherit from `BaseAPIException`:
- Consistent error responses
- HTTP status codes
- Error type categorization
- Detailed error information

### Global Error Handlers

- Catch all exceptions
- Log errors appropriately
- Return standardized responses
- Never expose internals

## Logging & Monitoring

### Audit Logging

- User actions tracked
- Organization changes logged
- Authentication events
- Queryable audit trail

### Application Logging

- Structured logging
- Request/response logging
- Error logging
- Performance metrics

## Future Enhancements

1. **OAuth Provider**: Implement full OAuth2/OIDC provider
2. **MFA**: Multi-factor authentication
3. **Email Service**: Email verification and notifications
4. **Webhooks**: Event-driven notifications
5. **API Keys**: Service account authentication
6. **Rate Limiting**: Per-user/org rate limits
7. **Background Jobs**: Celery integration
8. **Monitoring**: Prometheus/Grafana metrics

## Best Practices

1. **Always use service layer** for business logic
2. **Validate all inputs** with Marshmallow schemas
3. **Use decorators** for authentication/authorization
4. **Log important events** to audit log
5. **Follow RESTful conventions** for endpoints
6. **Write tests** for all new features
7. **Use transactions** for multi-step operations
8. **Never return sensitive data** without filtering
9. **Keep controllers thin** - logic goes in services
10. **Version the API** for backward compatibility

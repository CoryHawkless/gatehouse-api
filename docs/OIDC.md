# OpenID Connect (OIDC) Provider Documentation

This document provides comprehensive documentation for the Authy2 OIDC (OpenID Connect) provider implementation. Use this as the main reference for integrating with the OIDC provider.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [API Endpoints Reference](#api-endpoints-reference)
4. [OIDC Client Configuration](#oidc-client-configuration)
5. [Integration Examples](#integration-examples)
6. [Security Considerations](#security-considerations)
7. [Deployment Checklist](#deployment-checklist)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### What is OIDC?

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0 that allows clients to verify the identity of end-users and obtain basic profile information. It enables single sign-on (SSO) capabilities across applications.

### Why Use OIDC?

- **Standardized Authentication**: Industry-standard protocol with broad client library support
- **User Identity Verification**: Verifies user identity through ID tokens (JWTs)
- **Scoped Access**: Request specific user information with granular permissions
- **Security**: Built-in support for PKCE, token rotation, and secure token handling
- **Interoperability**: Works with numerous identity providers and client applications

### Integration with Authy2

The OIDC provider integrates with the existing Authy2 authentication system:

```
┌─────────────────────────────────────────────────────────────┐
│                     OIDC Provider                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Discovery   │  │ Authorization│  │ Token Endpoint      │  │
│  │ Endpoint    │  │  Endpoint    │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ UserInfo    │  │ JWKS        │  │ Revocation/Introspect│ │
│  │ Endpoint    │  │ Endpoint    │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Authy2 Core Services                            │
├─────────────────────────────────────────────────────────────┤
│  • User Service       • Session Service    • Audit Service  │
│  • Auth Service       • OIDC Token Service                   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                        │
├─────────────────────────────────────────────────────────────┤
│  • Users    • OIDC Clients    • OIDC Authorization Codes    │
│  • Sessions • Refresh Tokens  • Token Metadata & Audit Logs │
└─────────────────────────────────────────────────────────────┘
```

### Supported OIDC Flows

| Flow | Support | Description |
|------|---------|-------------|
| Authorization Code with PKCE | ✅ Full | Recommended for all clients |
| Authorization Code | ⚠️ Deprecated | PKCE required for new clients |
| Refresh Token | ✅ Full | Token rotation supported |

---

## Quick Start

### Prerequisites

1. **Python 3.9+** with pip
2. **PostgreSQL 13+** database
3. **Redis** (optional, for session storage)
4. **OIDC Client Library** for your platform

### Installation

1. Clone the repository and install dependencies:

```bash
git clone <repository-url>
cd backend
pip install -r requirements/base.txt
```

2. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Run database migrations:

```bash
python manage.py db upgrade
```

### Database Setup

The OIDC provider requires the following tables (automatically created via migrations):

- `oidc_clients` - Registered OIDC clients
- `oidc_authorization_codes` - Temporary authorization codes
- `oidc_refresh_tokens` - Refresh tokens with rotation support
- `oidc_sessions` - OIDC session tracking
- `oidc_token_metadata` - Token metadata for revocation
- `oidc_audit_logs` - Audit trail for all OIDC operations

### Basic Configuration

Configure the following environment variables:

```bash
# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/authy2

# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# OIDC
OIDC_ISSUER_URL=http://localhost:5000

# Security
SECRET_KEY=your-secure-secret-key-min-32-chars
BCRYPT_LOG_ROUNDS=12

# Logging
LOG_LEVEL=INFO
```

### Creating Your First OIDC Client

Register a new OIDC client using the registration endpoint:

```bash
curl -X POST http://localhost:5000/oidc/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["http://localhost:8080/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

**Response:**

```json
{
  "version": "1.0",
  "success": true,
  "code": 201,
  "message": "Client registered successfully",
  "request_id": "...",
  "data": {
    "client_id": "oidc_abc123...",
    "client_secret": "secret_xyz789...",
    "client_id_issued_at": 1704067200,
    "client_secret_expires_at": 0,
    "client_name": "My Application",
    "redirect_uris": ["http://localhost:8080/callback"],
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email"
  }
}
```

**Important:** Save the `client_id` and `client_secret` securely. The `client_secret` will not be shown again.

---

## API Endpoints Reference

All endpoints follow the standard API response format documented in [`docs/architecture.md`](docs/architecture.md).

### 1. Discovery Endpoint

**URL:** `GET /.well-known/openid-configuration`

Returns the OIDC provider configuration as JSON.

**Request:**

```bash
curl http://localhost:5000/.well-known/openid-configuration
```

**Response:**

```json
{
  "issuer": "http://localhost:5000",
  "authorization_endpoint": "http://localhost:5000/oidc/authorize",
  "token_endpoint": "http://localhost:5000/oidc/token",
  "userinfo_endpoint": "http://localhost:5000/oidc/userinfo",
  "jwks_uri": "http://localhost:5000/oidc/jwks",
  "registration_endpoint": "http://localhost:5000/oidc/register",
  "revocation_endpoint": "http://localhost:5000/oidc/revoke",
  "introspection_endpoint": "http://localhost:5000/oidc/introspect",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "claims_supported": ["sub", "name", "email", "email_verified"]
}
```

**Headers:**
- `Cache-Control: max-age=86400` (cached for 24 hours)

**Status Codes:**
- `200` - Success
- `500` - Server error

---

### 2. Authorization Endpoint

**URL:** `GET/POST /oidc/authorize`

Initiates the OIDC authentication flow. Supports both GET (browser redirect) and POST (direct API) requests.

**Request Parameters (GET/POST):**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client_id` | string | Yes | The client ID |
| `redirect_uri` | string | Yes | Redirect URI after authorization |
| `response_type` | string | Yes | Must be `"code"` |
| `scope` | string | Yes | Space-separated scopes (e.g., `"openid profile email"`) |
| `state` | string | Recommended | Opaque state for CSRF protection |
| `nonce` | string | Recommended | Nonce for ID token replay protection |
| `code_challenge` | string | For PKCE | PKCE code challenge |
| `code_challenge_method` | string | For PKCE | `"S256"` or `"plain"` |
| `prompt` | string | No | `"login"`, `"consent"`, `"select_account"`, `"none"` |
| `max_age` | integer | No | Maximum authentication age in seconds |
| `acr_values` | string | No | Requested Authentication Context Class Reference |

**POST-only Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | string | Yes* | User email (for direct authentication) |
| `password` | string | Yes* | User password (for direct authentication) |

*Required for POST requests without session

**Request (GET - Browser):**

```
http://localhost:5000/oidc/authorize?\
  client_id=YOUR_CLIENT_ID&\
  redirect_uri=http://localhost:8080/callback&\
  response_type=code&\
  scope=openid%20profile%20email&\
  state=YOUR_STATE&\
  nonce=YOUR_NONCE&\
  code_challenge=YOUR_CODE_CHALLENGE&\
  code_challenge_method=S256
```

**Request (POST - Direct API):**

```bash
curl -X POST http://localhost:5000/oidc/authorize \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "response_type=code" \
  -d "scope=openid profile email" \
  -d "state=YOUR_STATE" \
  -d "nonce=YOUR_NONCE" \
  -d "code_challenge=YOUR_CODE_CHALLENGE" \
  -d "code_challenge_method=S256" \
  -d "email=user@example.com" \
  -d "password=UserPassword123!"
```

**Success Response (302 Redirect):**

```http
HTTP/1.1 302 Found
Location: http://localhost:8080/callback?code=AUTHORIZATION_CODE&state=YOUR_STATE
```

**Error Response (302 Redirect with Error):**

```http
HTTP/1.1 302 Found
Location: http://localhost:8080/callback?error=invalid_request&error_description=Invalid+client_id&state=YOUR_STATE
```

**Error Codes:**

| Error Code | Description |
|------------|-------------|
| `invalid_request` | Missing or invalid required parameter |
| `unauthorized_client` | Client not authorized for this flow |
| `unsupported_response_type` | `response_type` not supported |
| `invalid_scope` | Invalid or disallowed scope |
| `invalid_request` | Invalid `redirect_uri` |

**Status Codes:**
- `302` - Redirect to callback URL
- `200` - Login page (GET when not authenticated)
- `400` - Invalid request

---

### 3. Token Endpoint

**URL:** `POST /oidc/token`

Exchanges authorization codes for tokens or refreshes tokens.

**Request Headers:**
- `Content-Type: application/x-www-form-urlencoded`

**Request Body:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | `"authorization_code"` or `"refresh_token"` |
| `client_id` | string | Yes* | The client ID |
| `client_secret` | string | Yes* | The client secret |

*Required if not using Basic authentication

**For `authorization_code` grant:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `code` | string | Yes | The authorization code |
| `redirect_uri` | string | Yes | The redirect URI used in authorization |
| `code_verifier` | string | For PKCE | PKCE code verifier |

**For `refresh_token` grant:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `refresh_token` | string | Yes | The refresh token |
| `scope` | string | No | Optional scope override |

**Request (Authorization Code):**

```bash
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=YOUR_CODE_VERIFIER"
```

**Request (Refresh Token):**

```bash
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

**Success Response:**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Tokens issued successfully",
  "request_id": "...",
  "data": {
    "access_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "id_token": "eyJ...",
    "refresh_token": "..."
  }
}
```

**Token Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | string | JWT access token |
| `token_type` | string | Always `"Bearer"` |
| `expires_in` | integer | Token lifetime in seconds |
| `id_token` | string | JWT ID token |
| `refresh_token` | string | Opaque refresh token (if granted) |

**Error Response:**

```json
{
  "version": "1.0",
  "success": false,
  "code": 400,
  "message": "Invalid authorization code",
  "error": {
    "type": "INVALID_GRANT",
    "details": {
      "error": "invalid_grant",
      "error_description": "Invalid or expired authorization code"
    }
  }
}
```

**Status Codes:**
- `200` - Tokens issued successfully
- `400` - Invalid request or grant
- `401` - Invalid client credentials
- `500` - Server error

---

### 4. UserInfo Endpoint

**URL:** `GET/POST /oidc/userinfo`

Returns claims about the authenticated user.

**Request Headers:**
- `Authorization: Bearer {access_token}`

**Request:**

```bash
curl -X GET http://localhost:5000/oidc/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "User info retrieved successfully",
  "request_id": "...",
  "data": {
    "sub": "user-uuid",
    "name": "John Doe",
    "email": "john@example.com",
    "email_verified": true
  }
}
```

**Claims by Scope:**

| Scope | Claims |
|-------|--------|
| `openid` | `sub` |
| `profile` | `name`, `preferred_username`, `picture` |
| `email` | `email`, `email_verified` |

**Status Codes:**
- `200` - User info returned
- `401` - Invalid or expired token
- `500` - Server error

---

### 5. JWKS Endpoint

**URL:** `GET /oidc/jwks`

Returns the JSON Web Key Set containing public keys for token verification.

**Request:**

```bash
curl http://localhost:5000/oidc/jwks
```

**Response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-id-123",
      "use": "sig",
      "alg": "RS256",
      "n": "base64-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

**Key Properties:**

| Property | Description |
|----------|-------------|
| `kty` | Key type (always `"RSA"`) |
| `kid` | Key ID for key selection |
| `use` | Key usage (`"sig"` for signature) |
| `alg` | Algorithm (`"RS256"`) |
| `n` | RSA modulus (base64url encoded) |
| `e` | RSA exponent (base64url encoded) |

**Headers:**
- `Cache-Control: max-age=3600` (cached for 1 hour)

**Status Codes:**
- `200` - JWKS returned
- `500` - Server error

---

### 6. Token Revocation Endpoint

**URL:** `POST /oidc/revoke`

Revokes an access token or refresh token.

**Request Headers:**
- `Content-Type: application/x-www-form-urlencoded`

**Request Body:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to revoke |
| `token_type_hint` | string | No | `"access_token"` or `"refresh_token"` |
| `client_id` | string | Yes* | The client ID |
| `client_secret` | string | Yes* | The client secret |

*Required if not using Basic authentication

**Request:**

```bash
curl -X POST http://localhost:5000/oidc/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_TOKEN" \
  -d "token_type_hint=access_token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

**Response:**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Token revoked successfully",
  "request_id": "..."
}
```

**Notes:**
- Revocation always returns 200, even if token is invalid
- Both access tokens and refresh tokens can be revoked
- Revoking a refresh token also invalidates associated access tokens

**Status Codes:**
- `200` - Token revoked (or no-op)
- `400` - Invalid request
- `401` - Invalid client credentials
- `500` - Server error

---

### 7. Token Introspection Endpoint

**URL:** `POST /oidc/introspect`

Returns information about a token's status and claims.

**Request Headers:**
- `Content-Type: application/x-www-form-urlencoded`

**Request Body:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to introspect |
| `token_type_hint` | string | No | `"access_token"` or `"refresh_token"` |
| `client_id` | string | Yes* | The client ID |
| `client_secret` | string | Yes* | The client secret |

*Required if not using Basic authentication

**Request:**

```bash
curl -X POST http://localhost:5000/oidc/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

**Response (Active Token):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Token introspection successful",
  "request_id": "...",
  "data": {
    "active": true,
    "iss": "http://localhost:5000",
    "sub": "user-uuid",
    "aud": "YOUR_CLIENT_ID",
    "exp": 1704070800,
    "iat": 1704067200,
    "nbf": 1704067200,
    "jti": "token-jti",
    "client_id": "YOUR_CLIENT_ID",
    "scope": "openid profile email",
    "token_type": "Bearer"
  }
}
```

**Response (Inactive/Expired Token):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Token introspection successful",
  "request_id": "...",
  "data": {
    "active": false
  }
}
```

**Status Codes:**
- `200` - Introspection complete
- `400` - Invalid request
- `401` - Invalid client credentials
- `500` - Server error

---

### 8. Client Registration Endpoint

**URL:** `POST /oidc/register`

Registers a new OIDC client dynamically.

**Request Headers:**
- `Content-Type: application/json`

**Request Body:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client_name` | string | Yes | Display name for the client |
| `redirect_uris` | array | Yes | Array of redirect URIs |
| `grant_types` | array | No | Array of grant types (default: `["authorization_code", "refresh_token"]`) |
| `response_types` | array | No | Array of response types (default: `["code"]`) |
| `scope` | string | No | Space-separated scopes (default: `"openid profile email"`) |
| `token_endpoint_auth_method` | string | No | `"client_secret_basic"` or `"client_secret_post"` |
| `logo_uri` | string | No | Client logo URL |
| `client_uri` | string | No | Client homepage URL |
| `policy_uri` | string | No | Privacy policy URL |
| `tos_uri` | string | No | Terms of service URL |
| `organization_id` | string | No | Organization ID for client ownership |

**Request:**

```bash
curl -X POST http://localhost:5000/oidc/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["http://localhost:8080/callback", "https://myapp.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email",
    "token_endpoint_auth_method": "client_secret_basic",
    "logo_uri": "https://myapp.com/logo.png",
    "client_uri": "https://myapp.com",
    "policy_uri": "https://myapp.com/privacy",
    "tos_uri": "https://myapp.com/terms"
  }'
```

**Success Response (201 Created):**

```json
{
  "version": "1.0",
  "success": true,
  "code": 201,
  "message": "Client registered successfully",
  "request_id": "...",
  "data": {
    "client_id": "oidc_abc123...",
    "client_secret": "secret_xyz789...",
    "client_id_issued_at": 1704067200,
    "client_secret_expires_at": 0,
    "client_name": "My Application",
    "redirect_uris": ["http://localhost:8080/callback", "https://myapp.com/callback"],
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email"
  }
}
```

**Validation Rules:**
- `redirect_uris` must contain valid URIs with scheme and netloc
- `grant_types` must be a subset of `["authorization_code", "refresh_token"]`
- `response_types` must be a subset of `["code"]`
- `scope` must be a subset of `["openid", "profile", "email"]`

**Status Codes:**
- `201` - Client registered successfully
- `400` - Invalid request or validation error
- `500` - Server error

---

## OIDC Client Configuration

### Client Registration Parameters

#### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `client_name` | string | Human-readable client name |
| `redirect_uris` | array | Array of valid redirect URIs |

#### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `grant_types` | array | `["authorization_code", "refresh_token"]` | Supported grant types |
| `response_types` | array | `["code"]` | Supported response types |
| `scope` | string | `"openid profile email"` | Space-separated scopes |
| `token_endpoint_auth_method` | string | `"client_secret_basic"` | Client authentication method |
| `logo_uri` | string | - | Client logo URL |
| `client_uri` | string | - | Client homepage URL |
| `policy_uri` | string | - | Privacy policy URL |
| `tos_uri` | string | - | Terms of service URL |

### Redirect URI Validation

The OIDC provider validates redirect URIs according to RFC 6749:

1. **Exact Matching**: Redirect URIs are matched exactly (no wildcards)
2. **Scheme Required**: Must have `http://`, `https://`, or custom scheme
3. **No Fragments**: Fragment components (`#`) are not allowed
4. **Query Parameters**: Allowed but must match exactly

**Valid Redirect URIs:**
```
https://myapp.com/callback
http://localhost:8080/callback
myapp://oauth/callback
```

**Invalid Redirect URIs:**
```
# Fragment not allowed
https://myapp.com/callback#fragment

# Wildcard not allowed
https://*.myapp.com/callback

# Missing netloc
myapp:callback
```

### Client Authentication Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| `client_secret_basic` | Basic auth with `client_id:client_secret` | Server-side applications |
| `client_secret_post` | Credentials in request body | Server-side applications |
| `none` | No authentication (public clients) | Mobile/SPA applications |

#### Example: Basic Authentication

```bash
# With client credentials in body
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"

# With Basic authentication header
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'YOUR_CLIENT_ID:YOUR_CLIENT_SECRET' | base64)" \
  -d "grant_type=authorization_code" \
  -d "code=CODE"
```

---

## Integration Examples

### OAuth2-Proxy Integration

See [`docs/oauth2-proxy-config.yaml`](docs/oauth2-proxy-config.yaml) for complete configuration.

**Quick Setup:**

1. Register an OIDC client:

```bash
curl -X POST http://localhost:5000/oidc/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "oauth2-proxy",
    "redirect_uris": ["http://localhost:4180/oauth2/callback"],
    "scope": "openid profile email"
  }'
```

2. Create `oauth2-proxy.yaml`:

```yaml
provider: "oidc"
oidc_issuer_url: "http://localhost:5000"
client_id: "your-client-id"
client_secret: "your-client-secret"
cookie_secret: "your-random-cookie-secret-min-32-chars"
cookie_name: "_oauth2_proxy"
http_address: "0.0.0.0:4180"
upstream: "http://127.0.0.1:8080/"
redirect_url: "http://localhost:4180/oauth2/callback"
scope: "openid profile email"
```

3. Start oauth2-proxy:

```bash
oauth2-proxy -config oauth2-proxy.yaml
```

### Generic OIDC Client Integration

#### Python Example

```python
import requests
import base64
import secrets
import hashlib

class OIDCClient:
    def __init__(self, issuer_url, client_id, client_secret):
        self.issuer_url = issuer_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        
        # Fetch discovery document
        disc_url = f"{self.issuer_url}/.well-known/openid-configuration"
        self.discovery = requests.get(disc_url).json()
    
    def generate_pkce(self):
        """Generate PKCE code verifier and challenge."""
        code_verifier = secrets.token_urlsafe(43)
        code_challenge = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode().rstrip('=')
        return code_verifier, code_challenge
    
    def authorize_url(self, redirect_uri, scopes, state=None, nonce=None):
        """Generate authorization URL."""
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'state': state or secrets.token_hex(16),
            'nonce': nonce or secrets.token_hex(16),
        }
        
        code_verifier, code_challenge = self.generate_pkce()
        params['code_challenge'] = code_challenge
        params['code_challenge_method'] = 'S256'
        
        # Build URL
        query = '&'.join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
        return f"{self.discovery['authorization_endpoint']}?{query}", code_verifier
    
    def token(self, code, redirect_uri, code_verifier=None):
        """Exchange authorization code for tokens."""
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        if code_verifier:
            data['code_verifier'] = code_verifier
        
        response = requests.post(
            self.discovery['token_endpoint'],
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        return response.json()
    
    def userinfo(self, access_token):
        """Get user info."""
        response = requests.get(
            self.discovery['userinfo_endpoint'],
            headers={'Authorization': f'Bearer {access_token}'}
        )
        return response.json()
    
    def refresh(self, refresh_token):
        """Refresh access token."""
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        response = requests.post(
            self.discovery['token_endpoint'],
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        return response.json()

# Usage
client = OIDCClient(
    issuer_url="http://localhost:5000",
    client_id="your-client-id",
    client_secret="your-client-secret"
)

# Get authorization URL
auth_url, code_verifier = client.authorize_url(
    redirect_uri="http://localhost:8080/callback",
    scopes=["openid", "profile", "email"]
)

# After user authorizes, exchange code for tokens
tokens = client.token("AUTHORIZATION_CODE", "http://localhost:8080/callback", code_verifier)

# Get user info
userinfo = client.userinfo(tokens['access_token'])

# Refresh token
new_tokens = client.refresh(tokens['refresh_token'])
```

### Example cURL Commands

#### Complete Authorization Code Flow with PKCE

```bash
#!/bin/bash
set -e

BASE_URL="http://localhost:5000"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
EMAIL="user@example.com"
PASSWORD="UserPassword123!"
REDIRECT_URI="http://localhost:8080/callback"

echo "=== OIDC Authorization Code Flow ==="

# Step 1: Generate PKCE parameters
echo "1. Generating PKCE parameters..."
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-' | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')
STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)
echo "   Code verifier: ${CODE_VERIFIER:0:20}..."
echo "   Code challenge: $CODE_CHALLENGE"

# Step 2: Get authorization code
echo "2. Getting authorization code..."
AUTH_RESPONSE=$(curl -s -D - -X POST "$BASE_URL/oidc/authorize" \
  -d "client_id=$CLIENT_ID" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "response_type=code" \
  -d "scope=openid profile email" \
  -d "state=$STATE" \
  -d "nonce=$NONCE" \
  -d "code_challenge=$CODE_CHALLENGE" \
  -d "code_challenge_method=S256" \
  -d "email=$EMAIL" \
  -d "password=$PASSWORD")

AUTH_CODE=$(echo "$AUTH_RESPONSE" | grep -i "Location:" | cut -d'?' -f2 | cut -d'=' -f2 | tr -d '\r')
echo "   Authorization code: ${AUTH_CODE:0:20}..."

# Step 3: Exchange code for tokens
echo "3. Exchanging code for tokens..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oidc/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "code_verifier=$CODE_VERIFIER")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.data.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.data.refresh_token')
echo "   Access token received: ${ACCESS_TOKEN:0:20}..."

# Step 4: Get user info
echo "4. Getting user info..."
USERINFO=$(curl -s -X GET "$BASE_URL/oidc/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "   User: $(echo "$USERINFO" | jq -r '.data.name')"

# Step 5: Introspect token
echo "5. Introspecting token..."
INTROSPECT=$(curl -s -X POST "$BASE_URL/oidc/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")
echo "   Token active: $(echo "$INTROSPECT" | jq -r '.data.active')"

# Step 6: Refresh token
echo "6. Refreshing token..."
REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/oidc/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")
echo "   Token refreshed successfully"

# Step 7: Revoke tokens
echo "7. Revoking tokens..."
curl -s -X POST "$BASE_URL/oidc/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$REFRESH_TOKEN" \
  -d "token_type_hint=refresh_token" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" > /dev/null
echo "   Tokens revoked"

echo ""
echo "=== Flow Complete ==="
```

---

## Security Considerations

### PKCE Requirements

Proof Key for Code Exchange (PKCE) is **strongly recommended** for all clients, including confidential clients.

**Why PKCE?**
- Protects against authorization code interception attacks
- Required for public clients (SPA, mobile)
- Recommended for all clients per OAuth 2.1

**Implementation:**
1. Generate `code_verifier` (43-128 characters)
2. Create `code_challenge` from verifier (SHA256)
3. Send `code_challenge` and `code_challenge_method` in authorization request
4. Send `code_verifier` in token request

```python
import hashlib
import base64
import secrets

# Generate code verifier
code_verifier = secrets.token_urlsafe(43)

# Generate code challenge
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')
```

### Token Lifetimes

| Token Type | Default | Maximum | Description |
|------------|---------|---------|-------------|
| Access Token | 3600s (1 hour) | 86400s (24h) | Short-lived token for API access |
| ID Token | 3600s (1 hour) | 86400s (24h) | Identity token |
| Refresh Token | 2592000s (30 days) | 31536000s (1 year) | Long-lived token for refresh |

**Configuration:**
Configure token lifetimes per client in the database or during registration.

### Redirect URI Validation

Strict redirect URI validation is critical for security:

1. **Exact Matching**: Use exact string matching (no wildcards)
2. **HTTPS Required**: Require HTTPS in production
3. **No Wildcards**: Never allow wildcards in domains
4. **Validate All URIs**: Validate each registered redirect URI
5. **Case Sensitivity**: Consider case sensitivity in path components

**Example Validation:**

```python
from urllib.parse import urlparse

def validate_redirect_uri(uri):
    parsed = urlparse(uri)
    
    # Check for required components
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid redirect URI: missing scheme or netloc")
    
    # Require HTTPS in production
    if parsed.scheme != 'https' and parsed.netloc not in ('localhost', '127.0.0.1'):
        raise ValueError("HTTPS required for redirect URI in production")
    
    # No fragments
    if parsed.fragment:
        raise ValueError("Redirect URI must not contain fragment")
    
    return True
```

### Client Secrets Management

1. **Secure Storage**: Store secrets in environment variables or secrets manager
2. **Hash Storage**: Secrets are hashed (bcrypt) in the database
3. **Rotation**: Support secret rotation without service interruption
4. **Scope**: Limit client permissions to minimum required scopes

**Environment Variables:**

```bash
# Don't commit secrets to version control
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
```

### Additional Security Measures

1. **HTTPS/TLS**: Always use HTTPS in production
2. **State Parameter**: Always validate state parameter to prevent CSRF
3. **Nonce Validation**: Validate nonce in ID token to prevent replay attacks
4. **Token Binding**: Consider token binding for high-security scenarios
5. **Audit Logging**: Enable comprehensive audit logging
6. **Rate Limiting**: Implement rate limiting for all endpoints

---

## Deployment Checklist

### Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@localhost:5432/authy2
SECRET_KEY=your-secure-secret-key-min-32-chars
OIDC_ISSUER_URL=https://your-oidc-provider.com

# Recommended
BCRYPT_LOG_ROUNDS=12
LOG_LEVEL=INFO
REDIS_URL=redis://localhost:6379/0

# Optional
CORS_ORIGINS=https://yourapp.com
RATELIMIT_ENABLED=true
```

### Database Migrations

1. **Run migrations before deployment:**

```bash
python manage.py db upgrade
```

2. **Verify migration:**

```bash
python manage.py db current
python manage.py db history
```

3. **Backup database before migration:**

```bash
pg_dump -h localhost -U postgres authy2 > backup.sql
```

### SSL/TLS Requirements

**Production Requirements:**

1. **TLS 1.2+**: Use TLS 1.2 or higher
2. **Valid Certificate**: Use certificates from trusted CA
3. **HSTS Header**: Enable HTTP Strict Transport Security
4. **No Mixed Content**: Ensure all resources load over HTTPS

**Example Nginx Configuration:**

```nginx
server {
    listen 443 ssl;
    server_name oidc.example.com;
    
    ssl_certificate /etc/ssl/certs/oidc.crt;
    ssl_certificate_key /etc/ssl/private/oidc.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name oidc.example.com;
    return 301 https://$host$request_uri;
}
```

### Monitoring and Logging

**Recommended Metrics:**

1. **Token Issuance Rate**: Tokens per minute/hour
2. **Error Rate**: 4xx and 5xx response codes
3. **Token Validation Failures**: Invalid token attempts
4. **Authorization Code Usage**: Single-use validation
5. **Client Activity**: Active clients and usage patterns

**Log Format:**

```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "level": "INFO",
  "event_type": "token_issued",
  "client_id": "oidc_...",
  "user_id": "user-uuid",
  "scope": "openid profile email",
  "ip_address": "192.168.1.1",
  "request_id": "req-uuid"
}
```

### Pre-Deployment Checklist

- [ ] Database migrations applied
- [ ] SSL/TLS certificates installed
- [ ] Environment variables configured
- [ ] Logging configured and tested
- [ ] Monitoring/alerting set up
- [ ] Backup procedures tested
- [ ] Load balancing configured
- [ ] Rate limiting enabled
- [ ] CORS configured for allowed origins
- [ ] Security headers enabled
- [ ] Performance tested under load

---

## Troubleshooting

### Common Errors and Solutions

#### Error: `invalid_client`

**Cause:** Client authentication failed.

**Solutions:**
1. Verify `client_id` and `client_secret` are correct
2. Check if client is active (not disabled)
3. Ensure client authentication method matches

```bash
# Test client authentication
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

#### Error: `invalid_grant`

**Cause:** Authorization code is invalid, expired, or already used.

**Solutions:**
1. Authorization codes expire after 10 minutes
2. Each code can only be used once
3. Ensure `redirect_uri` matches original request

```bash
# Check authorization code validity
# Codes expire quickly and are single-use
```

#### Error: `invalid_request` - `code_verifier required`

**Cause:** PKCE required but `code_verifier` not provided.

**Solutions:**
1. Generate code verifier and challenge
2. Include `code_verifier` in token request
3. Ensure `code_challenge_method` is `S256`

#### Error: `invalid_request` - `Invalid redirect_uri`

**Cause:** Redirect URI doesn't match registered URIs.

**Solutions:**
1. Verify exact redirect URI matches
2. Check for trailing slashes or whitespace
3. Ensure HTTPS in production

```python
# Debug redirect URI validation
client = OIDCClient.query.filter_by(client_id=client_id).first()
allowed_uris = client.redirect_uris
is_valid = client.is_redirect_uri_allowed(redirect_uri)
```

#### Error: `invalid_scope`

**Cause:** Requested scope not allowed for client.

**Solutions:**
1. Client must request only allowed scopes
2. Check client configuration for allowed scopes

```python
# Verify allowed scopes
client = OIDCClient.query.filter_by(client_id=client_id).first()
allowed_scopes = client.scopes  # ["openid", "profile", "email"]
```

### Debug Logging

**Enable Debug Logging:**

```bash
export LOG_LEVEL=DEBUG
```

**Example Log Output:**

```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "level": "DEBUG",
  "event_type": "authorization_code_issued",
  "message": "Authorization code generated",
  "client_id": "oidc_abc123",
  "user_id": "user-uuid",
  "scope": ["openid", "profile", "email"],
  "redirect_uri": "http://localhost:8080/callback",
  "code_challenge_method": "S256",
  "ip_address": "192.168.1.1",
  "request_id": "req-uuid"
}
```

### Token Validation Issues

#### Token Expired

```json
{
  "data": {
    "active": false
  }
}
```

**Solution:** Use refresh token to get new access token.

#### Invalid Signature

**Cause:** Token signed with different key.

**Solutions:**
1. Fetch latest JWKS
2. Verify key ID (kid) matches
3. Check key rotation

```python
import jwt

# Fetch JWKS
jwks = requests.get("http://localhost:5000/oidc/jwks").json()

# Get signing key
for key in jwks["keys"]:
    if key["kid"] == token_header["kid"]:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        break
```

#### Audience Mismatch

**Cause:** Token audience doesn't match client ID.

**Solution:** Ensure `aud` claim matches your `client_id`.

### Database Issues

#### Connection Failed

```bash
# Test database connection
export DATABASE_URL="postgresql://user:pass@localhost:5432/authy2"
python -c "create_app create_app; app = create_app(); app.test_request_context().push()"
```

#### Migration Issues

```bash
# Check migration status
python manage.py db current

# Show migration history
python manage.py db history

# Stamp to specific version
python manage.py db stamp 001
```

### Performance Issues

#### Slow Token Issuance

1. Check database connection pooling
2. Verify Redis connection (if used)
3. Monitor database query performance
4. Check for N+1 queries in token generation

#### High Memory Usage

1. Monitor JWKS caching
2. Check token metadata cleanup
3. Verify audit log rotation

### Getting Help

1. **Check Logs**: Review application logs for detailed error messages
2. **Test Endpoints**: Use [`docs/OIDC_TESTING.md`](docs/OIDC_TESTING.md) for manual testing
3. **Verify Configuration**: Check [`config/base.py`](config/base.py) for configuration options
4. **Run Tests**: Execute test suite to verify functionality:

```bash
pytest tests/integration/test_oidc_flow.py -v
```

---

## Related Documentation

- [Architecture Documentation](docs/architecture.md) - Overall system architecture
- [OIDC Testing Guide](docs/OIDC_TESTING.md) - Manual testing procedures
- [OAuth2-Proxy Configuration](docs/oauth2-proxy-config.yaml) - Example oauth2-proxy config
- [API Response Format](docs/architecture.md#api-response-format) - Standard response envelope
- [Configuration Reference](config/base.py) - Complete configuration options

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-01 | Initial OIDC provider documentation |


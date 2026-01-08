# OIDC Testing Guide

This guide provides step-by-step instructions for manually testing the OIDC implementation using curl commands.

## Prerequisites

1. A running instance of the authy2 backend
2. curl installed
3. A test user account
4. A registered OIDC client

## Setup

### Start the Backend

```bash
# Development mode
python -m flask run --host=0.0.0.0 --port=5000

# Or using the manage.py script
python manage.py runserver --host=0.0.0.0 --port=5000
```

### Register a Test User (if needed)

```bash
curl -X POST http://localhost:5000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "password_confirm": "TestPassword123!",
    "full_name": "Test User"
  }'
```

### Register an OIDC Client

```bash
# Register a new OIDC client
curl -X POST http://localhost:5000/oidc/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:8080/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

**Save the `client_id` and `client_secret` from the response for later use.**

## Testing Endpoints

### 1. Discovery Endpoint

**Purpose:** Verify OIDC discovery configuration is accessible and correct.

```bash
curl -s http://localhost:5000/.well-known/openid-configuration | jq
```

**Expected Response:**
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

**Verification:**
- All endpoints are present and use the correct base URL
- Cache-Control header is set: `curl -I http://localhost:5000/.well-known/openid-configuration`

### 2. JWKS Endpoint

**Purpose:** Verify JWKS is accessible and contains valid signing keys.

```bash
curl -s http://localhost:5000/oidc/jwks | jq
```

**Expected Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "...",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "..."
    }
  ]
}
```

**Verification:**
- At least one key is present
- Key has `kty: "RSA"`, `alg: "RS256"`
- Cache-Control header is set

### 3. Authorization Code Flow with PKCE

This is the complete OAuth2/OIDC authentication flow.

#### Step 1: Generate PKCE Parameters

```bash
# Generate code verifier (43-128 characters)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-' | cut -c1-43)

# Generate code challenge from verifier
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')

# Generate state parameter
STATE=$(openssl rand -hex 16)

# Generate nonce for ID token
NONCE=$(openssl rand -hex 16)

echo "Code Verifier: $CODE_VERIFIER"
echo "Code Challenge: $CODE_CHALLENGE"
echo "State: $STATE"
echo "Nonce: $NONCE"
```

#### Step 2: Request Authorization Code

**Option A: Browser-based flow (redirect flow)**
```
# Open this URL in a browser
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

**Option B: POST-based flow (for testing with curl)**
```bash
curl -v -X POST http://localhost:5000/oidc/authorize \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "response_type=code" \
  -d "scope=openid profile email" \
  -d "state=$STATE" \
  -d "nonce=$NONCE" \
  -d "code_challenge=$CODE_CHALLENGE" \
  -d "code_challenge_method=S256" \
  -d "email=test@example.com" \
  -d "password=TestPassword123!"
```

**Expected Response:** 302 Redirect with `code` parameter

```http
HTTP/1.1 302 Found
Location: http://localhost:8080/callback?code=AUTHORIZATION_CODE&state=YOUR_STATE
```

**Extract the authorization code:**
```bash
# From the Location header
AUTH_CODE=$(curl -v -X POST http://localhost:5000/oidc/authorize \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "response_type=code" \
  -d "scope=openid profile email" \
  -d "state=$STATE" \
  -d "nonce=$NONCE" \
  -d "code_challenge=$CODE_CHALLENGE" \
  -d "code_challenge_method=S256" \
  -d "email=test@example.com" \
  -d "password=TestPassword123!" 2>&1 | grep -i "Location:" | cut -d' ' -f2 | cut -d'?' -f2 | cut -d'=' -f2)
```

#### Step 3: Exchange Authorization Code for Tokens

```bash
# Using client_id and client_secret
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=$CODE_VERIFIER"
```

**Expected Response:**
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

**Verification:**
- `access_token` is a JWT (check at jwt.io)
- `token_type` is "Bearer"
- `expires_in` indicates token lifetime
- `id_token` contains expected claims (sub, iss, aud, etc.)

### 4. UserInfo Endpoint

**Purpose:** Retrieve user information using the access token.

```bash
curl -X GET http://localhost:5000/oidc/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "User info retrieved successfully",
  "request_id": "...",
  "data": {
    "sub": "user-id",
    "name": "Test User",
    "email": "test@example.com",
    "email_verified": true
  }
}
```

**Verification:**
- `sub` matches the user ID
- `email` and `email_verified` are present if email scope was requested
- `name` is present if profile scope was requested

### 5. Token Refresh

**Purpose:** Obtain a new access token using a refresh token.

```bash
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

**Expected Response:**
```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Tokens refreshed successfully",
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

**Verification:**
- New `access_token` is returned
- New `refresh_token` is returned (token rotation)
- Old refresh token is now invalid

### 6. Token Revocation

**Purpose:** Revoke a token to invalidate it.

```bash
# Revoke access token
curl -X POST http://localhost:5000/oidc/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN" \
  -d "token_type_hint=access_token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"

# Revoke refresh token
curl -X POST http://localhost:5000/oidc/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_REFRESH_TOKEN" \
  -d "token_type_hint=refresh_token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

**Expected Response:**
```json
{
  "version": "1.0",
  "success": true,
  "code": 200,
  "message": "Token revoked successfully",
  "request_id": "..."
}
```

**Verification:**
- Revoked refresh token cannot be used for refresh
- Revoked access token cannot be used for UserInfo

### 7. Token Introspection

**Purpose:** Check if a token is active and get its claims.

```bash
curl -X POST http://localhost:5000/oidc/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

**Expected Response (active token):**
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
    "sub": "user-id",
    "aud": "YOUR_CLIENT_ID",
    "exp": 1234567890,
    "iat": 1234564290,
    "scope": "openid profile email",
    "token_type": "Bearer"
  }
}
```

**Expected Response (invalid/expired token):**
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

## Complete Flow Test Script

Here's a comprehensive script that tests the complete OIDC flow:

```bash
#!/bin/bash
set -e

BASE_URL="http://localhost:5000"
CLIENT_ID="YOUR_CLIENT_ID"
CLIENT_SECRET="YOUR_CLIENT_SECRET"
EMAIL="test@example.com"
PASSWORD="TestPassword123!"
REDIRECT_URI="http://localhost:8080/callback"

echo "=== OIDC Complete Flow Test ==="

# 1. Discovery
echo -e "\n1. Testing Discovery Endpoint..."
curl -s "$BASE_URL/.well-known/openid-configuration" | jq . > /dev/null
echo "   ✓ Discovery endpoint working"

# 2. JWKS
echo -e "\n2. Testing JWKS Endpoint..."
curl -s "$BASE_URL/oidc/jwks" | jq . > /dev/null
echo "   ✓ JWKS endpoint working"

# 3. Generate PKCE parameters
echo -e "\n3. Generating PKCE parameters..."
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-' | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')
STATE=$(openssl rand -hex 16)
echo "   ✓ PKCE parameters generated"

# 4. Get Authorization Code
echo -e "\n4. Getting Authorization Code..."
AUTH_RESPONSE=$(curl -s -D - -X POST "$BASE_URL/oidc/authorize" \
  -d "client_id=$CLIENT_ID" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "response_type=code" \
  -d "scope=openid profile email" \
  -d "state=$STATE" \
  -d "code_challenge=$CODE_CHALLENGE" \
  -d "code_challenge_method=S256" \
  -d "email=$EMAIL" \
  -d "password=$PASSWORD")

AUTH_CODE=$(echo "$AUTH_RESPONSE" | grep -i "Location:" | cut -d'?' -f2 | cut -d'=' -f2 | tr -d '\r')
echo "   ✓ Authorization code received: ${AUTH_CODE:0:20}..."

# 5. Exchange Code for Tokens
echo -e "\n5. Exchanging Code for Tokens..."
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
echo "   ✓ Tokens received"

# 6. UserInfo
echo -e "\n6. Testing UserInfo Endpoint..."
USERINFO=$(curl -s -X GET "$BASE_URL/oidc/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "   ✓ UserInfo response: $(echo "$USERINFO" | jq -r '.data.sub')"

# 7. Token Refresh
echo -e "\n7. Testing Token Refresh..."
REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/oidc/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")

NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.data.access_token')
NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.data.refresh_token')
echo "   ✓ Token refresh successful"

# 8. Token Introspection
echo -e "\n8. Testing Token Introspection..."
INTROSPECT=$(curl -s -X POST "$BASE_URL/oidc/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$NEW_ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")
IS_ACTIVE=$(echo "$INTROSPECT" | jq -r '.data.active')
echo "   ✓ Token introspection: active=$IS_ACTIVE"

# 9. Token Revocation
echo -e "\n9. Testing Token Revocation..."
curl -s -X POST "$BASE_URL/oidc/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$NEW_REFRESH_TOKEN" \
  -d "token_type_hint=refresh_token" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" > /dev/null
echo "   ✓ Token revoked"

# 10. Verify Revoked Token
echo -e "\n10. Verifying Revoked Token..."
REVOKE_VERIFY=$(curl -s -X POST "$BASE_URL/oidc/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$NEW_REFRESH_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")
IS_INVALID=$(echo "$REVOKE_VERIFY" | jq -r '.success')
echo "   ✓ Revoked token is invalid: success=$IS_INVALID"

echo -e "\n=== OIDC Flow Test Complete ==="
echo "All endpoints tested successfully!"
```

## Error Handling Tests

### Invalid Client

```bash
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=invalid" \
  -d "client_id=invalid_client" \
  -d "client_secret=invalid_secret"
```

### Invalid Authorization Code

```bash
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=INVALID_CODE" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=YOUR_CLIENT_ID"
```

### Expired Authorization Code

Authorization codes expire after 10 minutes. Wait 10+ minutes and try to use the code again.

### Invalid PKCE Verifier

Use an incorrect `code_verifier` during token exchange:
```bash
curl -X POST http://localhost:5000/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "code_verifier=wrong_verifier"
```

## Troubleshooting

### Connection Refused

Ensure the backend is running:
```bash
ps aux | grep flask
lsof -i :5000
```

### Authentication Failures

1. Verify user credentials are correct
2. Check that the user exists in the database
3. Ensure the client is active and has correct redirect URIs

### Token Errors

1. Verify access token hasn't expired
2. Check that the token was signed by the OIDC provider
3. Ensure the audience (client_id) matches

### Redirect URI Mismatch

Ensure the `redirect_uri` used in authorization and token exchange exactly matches a registered redirect URI.

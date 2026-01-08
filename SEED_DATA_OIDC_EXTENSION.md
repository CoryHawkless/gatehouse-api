# OIDC Extension to Seed Data Script

## Summary

Extended [`scripts/seed_data.py`](scripts/seed_data.py) to include OIDC client seeding functionality.

## Changes Made

### 1. Added Imports
- `import secrets` - For generating secure random values
- `import hashlib` - For hashing client secrets
- `from app.models.oidc_client import OIDCClient` - OIDC client model

### 2. New Helper Function: `create_or_get_oidc_client()`
Creates OIDC clients with proper configuration or returns existing ones. Features:
- Checks for existing clients by `client_id`
- Hashes client secrets using SHA256
- Supports all OIDC client configuration options
- Proper error handling and logging

### 3. New Seed Step: Step 5 - Create OIDC Clients

Added 4 OIDC clients across the 3 seeded organizations:

#### Acme Corporation (2 clients)
1. **Acme Internal Portal** (`acme-portal-001`)
   - Confidential client
   - Grant types: authorization_code, refresh_token
   - Scopes: openid, profile, email, offline_access
   - PKCE required
   - Redirect URIs for production and localhost

2. **Acme Mobile App** (`acme-mobile-001`)
   - Public client (mobile app)
   - Shorter token lifetimes for security
   - PKCE required
   - Custom URL scheme for mobile redirect

#### Tech Startup Inc (1 client)
3. **Tech Startup Dashboard** (`tech-dashboard-001`)
   - Confidential client
   - Standard OIDC configuration
   - PKCE required

#### Data Systems Inc (1 client)
4. **Data Systems API Client** (`data-api-001`)
   - Confidential server-to-server client
   - Additional grant type: client_credentials
   - Custom scopes: api:read, api:write
   - PKCE not required (server-to-server)

## OIDC Client Test Credentials

All clients are configured with test credentials for development:

| Client | Client ID | Client Secret |
|--------|-----------|---------------|
| Acme Portal | `acme-portal-001` | `acme_secret_portal_2024` |
| Acme Mobile | `acme-mobile-001` | `acme_secret_mobile_2024` |
| Tech Dashboard | `tech-dashboard-001` | `tech_secret_dashboard_2024` |
| Data API | `data-api-001` | `data_secret_api_2024` |

## Enhanced Summary Output

The seed script now displays:
- Total count of OIDC clients created
- Detailed information for each client including:
  - Client name and ID
  - Organization
  - Configured grant types
  - Configured scopes
  - Number of redirect URIs
- Complete test credentials table

## Example Output

```
[Step 5] Creating OIDC Clients...

  Acme Corporation OIDC Clients:
  → Created OIDC client: Acme Internal Portal
  → Created OIDC client: Acme Mobile App

  Tech Startup OIDC Clients:
  → Created OIDC client: Tech Startup Dashboard

  Data Systems OIDC Clients:
  → Created OIDC client: Data Systems API Client

  Created 4 OIDC clients

============================================================
Seed Complete!
============================================================

📊 Summary:
  Organizations: 3
  Admin Users: 2
  Regular Users: 9
  OIDC Clients: 4

🔐 OIDC Clients:
  Acme Internal Portal
    Client ID: acme-portal-001
    Organization: Acme Corporation
    Grant Types: authorization_code, refresh_token
    Scopes: openid, profile, email, offline_access
    Redirect URIs: 2 configured
  ...
```

## Features

- **Idempotent**: Running the script multiple times won't create duplicate clients
- **Comprehensive**: Creates diverse client types (confidential, public, server-to-server)
- **Production-ready**: Includes proper secret hashing and security configurations
- **Developer-friendly**: Includes localhost URLs and clear test credentials
- **Well-documented**: Clear console output showing what was created

## Usage

Run the seed script as usual:

```bash
python scripts/seed_data.py
```

The OIDC clients will be automatically created along with users and organizations.

## Security Notes

- Client secrets are hashed using SHA256 before storage
- Test credentials are clearly marked and should **not** be used in production
- PKCE is enabled by default for web and mobile clients
- Token lifetimes are configured appropriately for each client type

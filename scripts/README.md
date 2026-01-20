# Gatehouse Scripts

This directory contains utility scripts for managing and configuring Gatehouse.

## OAuth Provider Configuration Script

The [`configure_oauth_provider.py`](configure_oauth_provider.py:1) script allows administrators to easily configure OAuth providers at the application level.

### Overview

This script manages application-wide OAuth provider configurations using the new [`ApplicationProviderConfig`](../gatehouse_app/models/authentication_method.py:99) architecture. Unlike the deprecated organization-specific configuration, this allows users to authenticate with OAuth providers without needing to specify an organization first.

### Prerequisites

- Python 3.8+
- Virtual environment with dependencies installed
- Flask app must be properly configured (`.env` or environment variables)

### Quick Start

```bash
# Activate virtual environment
cd gatehouse-api
source .venv/bin/activate

# Create Google OAuth configuration
python scripts/configure_oauth_provider.py create google \
  --client-id "YOUR_CLIENT_ID" \
  --client-secret "YOUR_CLIENT_SECRET" \
  --redirect-url "http://localhost:5173/auth/callback"

# List all configured providers
python scripts/configure_oauth_provider.py list

# Show provider details
python scripts/configure_oauth_provider.py show google
```

### Commands

#### `create` - Create a New Provider

Create a new OAuth provider configuration at the application level.

```bash
python scripts/configure_oauth_provider.py create PROVIDER [OPTIONS]
```

**Arguments:**
- `PROVIDER`: Provider type (google, github, microsoft)

**Options:**
- `--client-id TEXT`: OAuth client ID (required, or via environment)
- `--client-secret TEXT`: OAuth client secret (required, or via environment)
- `--redirect-url TEXT`: Default redirect URL for callbacks
- `--disabled`: Create provider in disabled state
- `--settings KEY=VALUE`: Custom settings (can be specified multiple times)

**Examples:**

```bash
# Basic Google configuration
python scripts/configure_oauth_provider.py create google \
  --client-id "xxx.apps.googleusercontent.com" \
  --client-secret "GOCSPX-xxx"

# With redirect URL
python scripts/configure_oauth_provider.py create google \
  --client-id "xxx" \
  --client-secret "yyy" \
  --redirect-url "https://app.example.com/auth/callback"

# Create disabled initially
python scripts/configure_oauth_provider.py create github \
  --client-id "xxx" \
  --client-secret "yyy" \
  --disabled

# With custom settings
python scripts/configure_oauth_provider.py create google \
  --client-id "xxx" \
  --client-secret "yyy" \
  --settings "hosted_domain=example.com" \
  --settings "prompt=consent"
```

#### `update` - Update Existing Provider

Update an existing OAuth provider configuration.

```bash
python scripts/configure_oauth_provider.py update PROVIDER [OPTIONS]
```

**Arguments:**
- `PROVIDER`: Provider type to update

**Options:**
- `--client-id TEXT`: New OAuth client ID
- `--client-secret TEXT`: New OAuth client secret
- `--redirect-url TEXT`: New default redirect URL
- `--enabled true|false`: Enable or disable the provider
- `--settings KEY=VALUE`: Custom settings to update

**Examples:**

```bash
# Update client credentials
python scripts/configure_oauth_provider.py update google \
  --client-id "new-client-id" \
  --client-secret "new-secret"

# Enable/disable provider
python scripts/configure_oauth_provider.py update google --enabled false
python scripts/configure_oauth_provider.py update google --enabled true

# Update redirect URL
python scripts/configure_oauth_provider.py update google \
  --redirect-url "https://new-domain.com/auth/callback"
```

#### `list` - List All Providers

List all configured OAuth providers with their status.

```bash
python scripts/configure_oauth_provider.py list
```

**Example Output:**
```
Configured OAuth Providers

  google - enabled
    Client ID: 972920496362-xxx.apps.googleusercontent.com
    Redirect URL: https://app.example.com/auth/callback
    Created: 2026-01-20T13:00:00
    Auth URL: https://accounts.google.com/o/oauth2/v2/auth
    Scopes: openid, profile, email

  github - disabled
    Client ID: Iv1.xxx
    Created: 2026-01-19T10:00:00
    Auth URL: https://github.com/login/oauth/authorize
    Scopes: read:user, user:email
```

#### `show` - Show Provider Details

Display detailed information about a specific OAuth provider.

```bash
python scripts/configure_oauth_provider.py show PROVIDER
```

**Arguments:**
- `PROVIDER`: Provider type to display

**Example:**

```bash
python scripts/configure_oauth_provider.py show google
```

**Example Output:**
```
Google OAuth Provider Details

Basic Information:
  Provider Type: google
  Provider ID: 123e4567-e89b-12d3-a456-426614174000
  Client ID: 972920496362-xxx.apps.googleusercontent.com
  Status: enabled
  Default Redirect URL: https://app.example.com/auth/callback

Timestamps:
  Created: 2026-01-20T13:00:00
  Updated: 2026-01-20T14:30:00

OAuth Configuration:
  Authorization URL: https://accounts.google.com/o/oauth2/v2/auth
  Token URL: https://oauth2.googleapis.com/token
  User Info URL: https://openidconnect.googleapis.com/v1/userinfo
  JWKS URL: https://www.googleapis.com/oauth2/v3/certs
  Scopes: openid, profile, email
```

#### `delete` - Delete Provider Configuration

Remove an OAuth provider configuration.

```bash
python scripts/configure_oauth_provider.py delete PROVIDER [OPTIONS]
```

**Arguments:**
- `PROVIDER`: Provider type to delete

**Options:**
- `--yes`, `-y`: Skip confirmation prompt

**Examples:**

```bash
# Delete with confirmation prompt
python scripts/configure_oauth_provider.py delete google

# Delete without confirmation
python scripts/configure_oauth_provider.py delete google --yes
```

### Environment Variables

The script supports loading OAuth credentials from environment variables, which is useful for automation and CI/CD pipelines.

**Supported Variables:**
- `{PROVIDER}_CLIENT_ID`: OAuth client ID
- `{PROVIDER}_CLIENT_SECRET`: OAuth client secret
- `{PROVIDER}_REDIRECT_URL`: Default redirect URL

**Example:**

```bash
# Export environment variables
export GOOGLE_CLIENT_ID="xxx.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="GOCSPX-xxx"
export GOOGLE_REDIRECT_URL="https://app.example.com/auth/callback"

# Create provider using environment variables
python scripts/configure_oauth_provider.py create google

# You can still override with command-line arguments
python scripts/configure_oauth_provider.py create google \
  --redirect-url "https://different.com/callback"
```

### Supported Providers

The script comes with pre-configured endpoint information for:

- **Google** (`google`)
  - Authorization: `https://accounts.google.com/o/oauth2/v2/auth`
  - Token: `https://oauth2.googleapis.com/token`
  - User Info: `https://openidconnect.googleapis.com/v1/userinfo`
  - Default Scopes: `openid, profile, email`

- **GitHub** (`github`)
  - Authorization: `https://github.com/login/oauth/authorize`
  - Token: `https://github.com/login/oauth/access_token`
  - User Info: `https://api.github.com/user`
  - Default Scopes: `read:user, user:email`

- **Microsoft** (`microsoft`)
  - Authorization: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`
  - Token: `https://login.microsoftonline.com/common/oauth2/v2.0/token`
  - User Info: `https://graph.microsoft.com/oidc/userinfo`
  - Default Scopes: `openid, profile, email`

### Error Handling

The script provides clear error messages and appropriate exit codes:

- **Exit Code 0**: Success
- **Exit Code 1**: Error occurred

**Common Errors:**

1. **Provider Already Exists**
   ```
   ✗ Failed to create provider: Provider google already exists
   ℹ Use 'update' command to modify existing provider configuration.
   ```

2. **Provider Not Found**
   ```
   ✗ Failed to update provider: Provider google not found
   ℹ Use 'create' command to add a new provider configuration.
   ```

3. **Missing Credentials**
   ```
   ✗ Client ID is required. Provide via --client-id or GOOGLE_CLIENT_ID environment variable.
   ```

### Integration with Shell Scripts

The [`configure-google-auth.sh`](../../docs/configure-google-auth.sh:1) script demonstrates how to integrate the Python script into a shell script for easier deployment:

```bash
#!/bin/bash

# Set credentials
GOOGLE_CLIENT_ID="xxx"
GOOGLE_CLIENT_SECRET="yyy"
REDIRECT_URL="https://app.example.com/callback"

# Call Python script
cd gatehouse-api
python3 scripts/configure_oauth_provider.py create google \
  --client-id "$GOOGLE_CLIENT_ID" \
  --client-secret "$GOOGLE_CLIENT_SECRET" \
  --redirect-url "$REDIRECT_URL"
```

### API Service Methods

The script uses the following [`ExternalAuthService`](../gatehouse_app/services/external_auth_service.py:1) methods:

- [`create_app_provider_config()`](../gatehouse_app/services/external_auth_service.py:308) - Create provider configuration
- [`update_app_provider_config()`](../gatehouse_app/services/external_auth_service.py:369) - Update provider configuration
- [`get_app_provider_config()`](../gatehouse_app/services/external_auth_service.py:427) - Get single provider
- [`list_app_provider_configs()`](../gatehouse_app/services/external_auth_service.py:454) - List all providers
- [`delete_app_provider_config()`](../gatehouse_app/services/external_auth_service.py:465) - Delete provider configuration

### Security Considerations

1. **Client Secret Storage**: Client secrets are encrypted using the application's encryption key before storage in the database
2. **Environment Variables**: Be cautious when using environment variables in shared environments
3. **Secret Exposure**: The `show` command never displays the client secret (it's always excluded)
4. **Confirmation Prompts**: The `delete` command requires confirmation unless `--yes` flag is used

### Troubleshooting

**Database Connection Issues:**
- Ensure PostgreSQL is running and accessible
- Check `.env` file for correct `DATABASE_URL`
- Verify virtual environment is activated

**Import Errors:**
- Activate the virtual environment: `source .venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`

**Permission Issues:**
- Ensure script is executable: `chmod +x scripts/configure_oauth_provider.py`

### Related Documentation

- [External Auth Architecture](../../docs/external-auth-architecture.md)
- [Application-Wide OAuth Design](../../docs/external-auth-application-wide-design.md)
- [OAuth API Changes](../../docs/oauth-api-changes.md)

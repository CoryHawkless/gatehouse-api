"""Database migration: Add WebAuthn support.

Revision ID: 002
Revises: 001
Create Date: 2024-01-15 00:00:00

This migration adds support for WebAuthn passkey authentication by:
- Adding WEBAUTHN to the AuthMethodType enum (handled in application code)
- No schema changes required (uses existing provider_data JSON field)
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade():
    """Add WebAuthn support - no schema changes needed."""
    # WebAuthn credentials are stored in the existing provider_data JSON field
    # of the authentication_methods table. No schema changes are required.
    
    # Create an index for faster lookups of WebAuthn credentials by user
    # This is optional but recommended for performance
    # op.create_index(
    #     'ix_authentication_methods_webauthn_user',
    #     'authentication_methods',
    #     ['user_id'],
    #     postgresql_where=(sa.text("method_type = 'webauthn'")),
    #     if_not_exists=True
    # )
    
    pass


def downgrade():
    """Remove WebAuthn support - no schema changes needed."""
    # No schema changes to revert
    pass
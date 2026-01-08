"""Database migration: Create OIDC tables.

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00

This migration creates all OIDC-related tables for the authorization code flow,
refresh token management, OIDC session tracking, token metadata, and audit logging.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create OIDC tables."""
    
    # OIDC Authorization Codes table
    op.create_table(
        'oidc_authorization_codes',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('client_id', sa.String(255), sa.ForeignKey('oidc_clients.id'), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('code_hash', sa.String(255), nullable=False),
        sa.Column('redirect_uri', sa.String(512), nullable=False),
        sa.Column('scope', postgresql.JSON, nullable=True),
        sa.Column('nonce', sa.String(255), nullable=True),
        sa.Column('code_verifier', sa.String(255), nullable=True),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('used_at', sa.DateTime, nullable=True),
        sa.Column('is_used', sa.Boolean, default=False, nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
    )
    op.create_index('ix_oidc_authorization_codes_client_id', 'oidc_authorization_codes', ['client_id'])
    op.create_index('ix_oidc_authorization_codes_user_id', 'oidc_authorization_codes', ['user_id'])
    op.create_index('ix_oidc_authorization_codes_expires_at', 'oidc_authorization_codes', ['expires_at'])

    # OIDC Refresh Tokens table
    op.create_table(
        'oidc_refresh_tokens',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('client_id', sa.String(255), sa.ForeignKey('oidc_clients.id'), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_hash', sa.String(255), nullable=False),
        sa.Column('access_token_id', sa.String(36), sa.ForeignKey('sessions.id'), nullable=True),
        sa.Column('scope', postgresql.JSON, nullable=True),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('revoked_at', sa.DateTime, nullable=True),
        sa.Column('revoked_reason', sa.String(255), nullable=True),
        sa.Column('previous_token_hash', sa.String(255), nullable=True),
        sa.Column('rotation_count', sa.Integer, default=0, nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
    )
    op.create_index('ix_oidc_refresh_tokens_client_id', 'oidc_refresh_tokens', ['client_id'])
    op.create_index('ix_oidc_refresh_tokens_user_id', 'oidc_refresh_tokens', ['user_id'])
    op.create_index('ix_oidc_refresh_tokens_token_hash', 'oidc_refresh_tokens', ['token_hash'], unique=True)
    op.create_index('ix_oidc_refresh_tokens_access_token_id', 'oidc_refresh_tokens', ['access_token_id'])
    op.create_index('ix_oidc_refresh_tokens_expires_at', 'oidc_refresh_tokens', ['expires_at'])

    # OIDC Sessions table
    op.create_table(
        'oidc_sessions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('client_id', sa.String(255), sa.ForeignKey('oidc_clients.id'), nullable=False),
        sa.Column('state', sa.String(255), nullable=False),
        sa.Column('nonce', sa.String(255), nullable=True),
        sa.Column('redirect_uri', sa.String(512), nullable=False),
        sa.Column('scope', postgresql.JSON, nullable=True),
        sa.Column('code_challenge', sa.String(255), nullable=True),
        sa.Column('code_challenge_method', sa.String(10), nullable=True),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('authenticated_at', sa.DateTime, nullable=True),
    )
    op.create_index('ix_oidc_sessions_user_id', 'oidc_sessions', ['user_id'])
    op.create_index('ix_oidc_sessions_client_id', 'oidc_sessions', ['client_id'])
    op.create_index('ix_oidc_sessions_state', 'oidc_sessions', ['state'])
    op.create_index('ix_oidc_sessions_expires_at', 'oidc_sessions', ['expires_at'])

    # OIDC Token Metadata table
    op.create_table(
        'oidc_token_metadata',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('client_id', sa.String(255), sa.ForeignKey('oidc_clients.id'), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_type', sa.String(50), nullable=False),
        sa.Column('token_jti', sa.String(255), nullable=False),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('revoked_at', sa.DateTime, nullable=True),
        sa.Column('revoked_reason', sa.String(255), nullable=True),
    )
    op.create_index('ix_oidc_token_metadata_client_id', 'oidc_token_metadata', ['client_id'])
    op.create_index('ix_oidc_token_metadata_user_id', 'oidc_token_metadata', ['user_id'])
    op.create_index('ix_oidc_token_metadata_token_jti', 'oidc_token_metadata', ['token_jti'])
    op.create_index('ix_oidc_token_metadata_expires_at', 'oidc_token_metadata', ['expires_at'])

    # OIDC Audit Logs table
    op.create_table(
        'oidc_audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('client_id', sa.String(255), sa.ForeignKey('oidc_clients.id'), nullable=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('success', sa.Boolean, default=True, nullable=False),
        sa.Column('error_code', sa.String(100), nullable=True),
        sa.Column('error_description', sa.Text, nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
        sa.Column('request_id', sa.String(36), nullable=True),
        sa.Column('event_metadata', postgresql.JSON, nullable=True),
    )
    op.create_index('ix_oidc_audit_logs_event_type', 'oidc_audit_logs', ['event_type'])
    op.create_index('ix_oidc_audit_logs_client_id', 'oidc_audit_logs', ['client_id'])
    op.create_index('ix_oidc_audit_logs_user_id', 'oidc_audit_logs', ['user_id'])
    op.create_index('ix_oidc_audit_logs_success', 'oidc_audit_logs', ['success'])
    op.create_index('ix_oidc_audit_logs_ip_address', 'oidc_audit_logs', ['ip_address'])
    op.create_index('ix_oidc_audit_logs_request_id', 'oidc_audit_logs', ['request_id'])


def downgrade():
    """Drop OIDC tables."""
    op.drop_table('oidc_audit_logs')
    op.drop_table('oidc_token_metadata')
    op.drop_table('oidc_sessions')
    op.drop_table('oidc_refresh_tokens')
    op.drop_table('oidc_authorization_codes')

"""OIDC Token Service for JWT token generation and validation."""
import hashlib
import base64
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Any

import jwt
from flask import current_app, g

from app.models import User, OIDCClient
from app.services.oidc_jwks_service import OIDCJWKSService


class OIDCTokenService:
    """Service for generating and validating OIDC tokens.
    
    This service handles:
    - Access token creation (JWT)
    - ID token creation (JWT)
    - Refresh token creation (opaque)
    - Token signature verification
    - Hash generation for PKCE claims (at_hash, c_hash)
    """
    
    @staticmethod
    def _generate_jti() -> str:
        """Generate a unique JWT ID."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def _generate_opaque_token(length: int = 43) -> str:
        """Generate an opaque token (for refresh tokens).
        
        Args:
            length: Length of the token
        
        Returns:
            URL-safe base64 encoded token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash a token for secure storage.
        
        Args:
            token: Token to hash
        
        Returns:
            SHA256 hash of the token
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """Encode bytes to base64url format without padding.
        
        Args:
            data: Bytes to encode
        
        Returns:
            Base64url encoded string
        """
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
    
    @staticmethod
    def create_at_hash(access_token: str) -> str:
        """Create the at_hash claim for ID token.
        
        Implements OIDC spec for access token hash generation.
        Hash is the left-most half of the hash of the ASCII representation
        of the access token.
        
        Args:
            access_token: The access token string
        
        Returns:
            Base64url encoded hash
        """
        # Hash the access token using SHA256
        hash_digest = hashlib.sha256(access_token.encode()).digest()
        
        # Take left-most half of the hash
        half_length = len(hash_digest) // 2
        left_half = hash_digest[:half_length]
        
        # Base64url encode
        return OIDCTokenService._base64url_encode(left_half)
    
    @staticmethod
    def create_c_hash(code: str) -> str:
        """Create the c_hash claim for ID token.
        
        Implements OIDC spec for authorization code hash generation.
        
        Args:
            code: The authorization code string
        
        Returns:
            Base64url encoded hash
        """
        # Hash the code using SHA256
        hash_digest = hashlib.sha256(code.encode()).digest()
        
        # Take left-most half of the hash
        half_length = len(hash_digest) // 2
        left_half = hash_digest[:half_length]
        
        # Base64url encode
        return OIDCTokenService._base64url_encode(left_half)
    
    @staticmethod
    def _get_issuer() -> str:
        """Get the OIDC issuer URL."""
        return current_app.config.get("OIDC_ISSUER_URL", "http://localhost:5000")
    
    @staticmethod
    def _get_token_lifetime(client: OIDCClient, token_type: str) -> int:
        """Get the token lifetime in seconds for a client.
        
        Args:
            client: OIDCClient instance
            token_type: Type of token ("access_token", "refresh_token", "id_token")
        
        Returns:
            Lifetime in seconds
        """
        lifetimes = {
            "access_token": client.access_token_lifetime or 3600,
            "refresh_token": client.refresh_token_lifetime or 2592000,
            "id_token": client.id_token_lifetime or 3600,
        }
        return lifetimes.get(token_type, 3600)
    
    @classmethod
    def create_access_token(cls, client_id: str, user_id: str, scope: list, 
                           jti: str = None) -> str:
        """Create a JWT access token.
        
        Args:
            client_id: The OIDC client ID
            user_id: The user ID (subject)
            scope: List of granted scopes
            jti: Optional JWT ID (generated if not provided)
        
        Returns:
            JWT access token string
        """
        jti = jti or cls._generate_jti()
        now = datetime.utcnow()
        
        # Get client for token lifetime
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        lifetime = cls._get_token_lifetime(client, "access_token") if client else 3600
        
        claims = {
            "iss": cls._get_issuer(),
            "sub": user_id,
            "aud": client_id,
            "exp": int((now + timedelta(seconds=lifetime)).timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": jti,
            "client_id": client_id,
            "scope": " ".join(scope) if isinstance(scope, list) else scope,
        }
        
        # Get signing key
        jwks_service = OIDCJWKSService()
        signing_key = jwks_service.get_signing_key()
        
        if not signing_key:
            raise ValueError("No signing key available")
        
        # Sign with RS256
        token = jwt.encode(
            claims,
            signing_key.private_key,
            algorithm="RS256",
            headers={"kid": signing_key.kid}
        )
        
        return token
    
    @classmethod
    def create_id_token(cls, client_id: str, user_id: str, nonce: str = None,
                       scope: list = None, access_token: str = None,
                       auth_time: int = None) -> str:
        """Create a JWT ID token.
        
        Args:
            client_id: The OIDC client ID
            user_id: The user ID (subject)
            nonce: Nonce for replay protection
            scope: Requested/Granted scopes
            access_token: Associated access token (for at_hash)
            auth_time: Authentication time (Unix timestamp)
        
        Returns:
            JWT ID token string
        """
        now = datetime.utcnow()
        auth_time = auth_time or int(now.timestamp())
        
        # Get client for token lifetime
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        lifetime = cls._get_token_lifetime(client, "id_token") if client else 3600
        
        # Get user for claims
        user = User.query.get(user_id)
        
        claims = {
            "iss": cls._get_issuer(),
            "sub": user_id,
            "aud": client_id,
            "exp": int((now + timedelta(seconds=lifetime)).timestamp()),
            "iat": int(now.timestamp()),
            "auth_time": auth_time,
        }
        
        # Add nonce if provided
        if nonce:
            claims["nonce"] = nonce
        
        # Add at_hash if access token provided
        if access_token:
            claims["at_hash"] = cls.create_at_hash(access_token)
        
        # Add standard claims if user exists
        if user:
            if user.email:
                claims["email"] = user.email
            claims["email_verified"] = user.email_verified
            if user.full_name:
                claims["name"] = user.full_name
        
        # Add scope if provided
        if scope:
            claims["scope"] = " ".join(scope) if isinstance(scope, list) else scope
        
        # Get signing key
        jwks_service = OIDCJWKSService()
        signing_key = jwks_service.get_signing_key()
        
        if not signing_key:
            raise ValueError("No signing key available")
        
        # Sign with RS256
        token = jwt.encode(
            claims,
            signing_key.private_key,
            algorithm="RS256",
            headers={"kid": signing_key.kid}
        )
        
        return token
    
    @classmethod
    def create_refresh_token(cls, client_id: str, user_id: str, 
                            scope: list = None, access_token_id: str = None) -> str:
        """Create an opaque refresh token.
        
        Args:
            client_id: The OIDC client ID
            user_id: The user ID
            scope: List of granted scopes
            access_token_id: Associated access token ID
        
        Returns:
            Opaque refresh token string
        """
        token = cls._generate_opaque_token()
        
        # Hash for storage
        token_hash = cls._hash_token(token)
        
        return token, token_hash
    
    @classmethod
    def verify_token_signature(cls, token: str) -> Dict:
        """Verify the signature of a JWT token.
        
        Args:
            token: JWT token string
        
        Returns:
            Decoded token claims
        
        Raises:
            jwt.InvalidSignatureError: If signature verification fails
            jwt.ExpiredSignatureError: If token is expired
            jwt.InvalidTokenError: If token is invalid
        """
        # Get the JWKS with public keys
        jwks_service = OIDCJWKSService()
        jwks = jwks_service.get_jwks()
        
        # Get the key ID from token header
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.DecodeError:
            raise jwt.InvalidTokenError("Invalid token header")
        
        kid = unverified_header.get("kid")
        
        # Find the matching public key
        public_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                try:
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.backends import default_backend
                    
                    public_key = serialization.load_pem_public_key(
                        key["public_key"].encode() if isinstance(key["public_key"], str) 
                        else key["public_key"],
                        backend=default_backend()
                    )
                    break
                except (ImportError, Exception):
                    continue
        
        if not public_key:
            raise jwt.InvalidSignatureError(f"Key with kid={kid} not found")
        
        # Verify the signature
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=None,  # We'll validate audience separately
            issuer=cls._get_issuer(),
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": False,  # Handle audience manually
                "verify_iss": False,  # Handle issuer manually
            }
        )
        
        return claims
    
    @classmethod
    def decode_token(cls, token: str, verify: bool = False) -> Dict:
        """Decode a JWT token without verification (for debugging).
        
        Args:
            token: JWT token string
            verify: Whether to verify signature
        
        Returns:
            Decoded token claims
        """
        if verify:
            return cls.verify_token_signature(token)
        
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
            }
        )
    
    @classmethod
    def validate_access_token(cls, token: str, client_id: str = None) -> Dict:
        """Validate an access token and return its claims.
        
        Args:
            token: JWT access token
            client_id: Optional client ID to validate audience
        
        Returns:
            Token claims dictionary
        
        Raises:
            jwt.InvalidTokenError: If token is invalid
            ValueError: If token is expired or audience mismatch
        """
        claims = cls.verify_token_signature(token)
        
        # Check expiration
        if claims.get("exp", 0) < datetime.utcnow().timestamp():
            raise ValueError("Token has expired")
        
        # Validate audience if client_id provided
        if client_id:
            if claims.get("aud") != client_id:
                raise ValueError("Invalid audience")
        
        return claims
    
    @classmethod
    def introspect_token(cls, token: str, client_id: str = None) -> Dict:
        """Introspect a token and return its status and claims.
        
        Args:
            token: JWT token to introspect
            client_id: Client ID for audience validation
        
        Returns:
            Dictionary with active status and claims
        """
        result = {
            "active": False,
        }
        
        try:
            claims = cls.validate_access_token(token, client_id)
            
            # Calculate remaining time
            now = datetime.utcnow().timestamp()
            exp = claims.get("exp", 0)
            iat = claims.get("iat", 0)
            
            result["active"] = exp > now
            result.update({
                "iss": claims.get("iss"),
                "sub": claims.get("sub"),
                "aud": claims.get("aud"),
                "exp": exp,
                "iat": iat,
                "nbf": claims.get("nbf"),
                "jti": claims.get("jti"),
                "client_id": claims.get("client_id"),
                "scope": claims.get("scope"),
                "token_type": "Bearer",
            })
            
            # Add expiry in seconds
            if exp > now:
                result["exp"] = int(exp - now)
            
        except (jwt.InvalidTokenError, ValueError) as e:
            result["active"] = False
            result["error"] = str(e)
        
        return result

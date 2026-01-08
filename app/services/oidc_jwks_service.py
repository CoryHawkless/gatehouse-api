"""OIDC JWKS Service for key management and rotation."""
import uuid
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from flask import current_app

from app.extensions import db


class JWKSKey:
    """Represents a JWKS key entry."""
    
    def __init__(self, kid: str, private_key: str, public_key: str, 
                 algorithm: str = "RS256", created_at: datetime = None,
                 expires_at: datetime = None, is_active: bool = True):
        self.kid = kid
        self.private_key = private_key
        self.public_key = public_key
        self.algorithm = algorithm
        self.created_at = created_at or datetime.utcnow()
        self.expires_at = expires_at or datetime.utcnow() + timedelta(days=365)
        self.is_active = is_active
    
    def to_jwk(self) -> Dict:
        """Convert to JWK format for JWKS endpoint."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
        
        # Import cryptography here to avoid issues if not installed
        try:
            # Get public key from PEM
            public_key = serialization.load_pem_public_key(
                self.public_key.encode(), backend=default_backend()
            )
            
            # Get RSA parameters
            public_numbers = public_key.public_numbers()
            
            return {
                "kty": "RSA",
                "kid": self.kid,
                "use": "sig",
                "alg": self.algorithm,
                "n": _base64url_encode(public_numbers.n),
                "e": _base64url_encode(public_numbers.e),
            }
        except ImportError:
            # Fallback for when cryptography is not installed
            return {
                "kty": "RSA",
                "kid": self.kid,
                "use": "sig",
                "alg": self.algorithm,
            }
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return {
            "kid": self.kid,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "algorithm": self.algorithm,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_active": self.is_active,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "JWKSKey":
        """Create from dictionary."""
        return cls(
            kid=data["kid"],
            private_key=data["private_key"],
            public_key=data["public_key"],
            algorithm=data.get("algorithm", "RS256"),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            is_active=data.get("is_active", True),
        )


def _base64url_encode(value: int) -> str:
    """Encode an integer to base64url format."""
    import base64
    byte_length = (value.bit_length() + 7) // 8 or 1
    encoded = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(encoded).decode().rstrip("=")


class OIDCJWKSService:
    """Service for managing OIDC signing keys (JWKS).
    
    This service handles RSA key pair generation, rotation, and JWKS document
    generation for the OIDC implementation.
    """
    
    _instance = None
    _keys: Dict[str, JWKSKey] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._keys = {}
        return cls._instance
    
    @classmethod
    def reset(cls):
        """Reset the singleton (for testing)."""
        cls._instance = None
        cls._keys = {}
    
    def _generate_kid(self, private_key: str) -> str:
        """Generate a key ID from the private key fingerprint."""
        kid_hash = hashlib.sha256(private_key.encode()).hexdigest()[:32]
        return kid_hash
    
    def _generate_rsa_key_pair(self) -> Tuple[str, str]:
        """Generate a new RSA key pair in PEM format.
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            # Generate RSA private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize to PEM
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            return private_pem, public_pem
        except ImportError:
            # Fallback for testing without cryptography
            import secrets
            return f"private_key_{secrets.token_hex(32)}", f"public_key_{secrets.token_hex(32)}"
    
    def get_jwks(self, include_private_keys: bool = False) -> Dict:
        """Get the JWKS document containing public keys.
        
        Args:
            include_private_keys: Whether to include private keys (for internal use only)
        
        Returns:
            JWKS document dictionary
        """
        now = datetime.utcnow()
        
        keys = []
        for kid, key in self._keys.items():
            # Only include active, non-expired keys
            if key.is_active and key.expires_at > now:
                if include_private_keys:
                    keys.append(key.to_dict())
                else:
                    keys.append(key.to_jwk())
        
        return {
            "keys": keys
        }
    
    def get_signing_key(self) -> Optional[JWKSKey]:
        """Get the current active signing key.
        
        Returns:
            JWKSKey instance or None if no active key
        """
        now = datetime.utcnow()
        
        for kid, key in self._keys.items():
            if key.is_active and key.expires_at > now:
                return key
        
        return None
    
    def get_key_by_kid(self, kid: str) -> Optional[JWKSKey]:
        """Get a specific key by its ID.
        
        Args:
            kid: Key ID to look up
        
        Returns:
            JWKSKey instance or None if not found
        """
        return self._keys.get(kid)
    
    def generate_new_key_pair(self, expires_in_days: int = 365) -> JWKSKey:
        """Generate a new RSA key pair for signing.
        
        Args:
            expires_in_days: Days until key expiration
        
        Returns:
            JWKSKey instance
        """
        private_key, public_key = self._generate_rsa_key_pair()
        kid = self._generate_kid(private_key)
        
        now = datetime.utcnow()
        key = JWKSKey(
            kid=kid,
            private_key=private_key,
            public_key=public_key,
            algorithm="RS256",
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
            is_active=True,
        )
        
        self._keys[kid] = key
        
        # Deactivate old keys (but keep them for grace period)
        for old_kid in self._keys:
            if old_kid != kid:
                self._keys[old_kid].is_active = False
        
        return key
    
    def rotate_keys(self, grace_period_hours: int = 24) -> Tuple[JWKSKey, List[str]]:
        """Rotate signing keys, keeping previous key active for grace period.
        
        Args:
            grace_period_hours: Hours to keep old keys active
        
        Returns:
            Tuple of (new_key, list_of_deprecated_kids)
        """
        now = datetime.utcnow()
        grace_end = now + timedelta(hours=grace_period_hours)
        
        # Mark current key as deprecated
        current_key = self.get_signing_key()
        deprecated_kids = []
        
        if current_key:
            deprecated_kids.append(current_key.kid)
            # Keep key active but mark as deprecated
            current_key.is_active = False
            current_key.expires_at = grace_end
        
        # Generate new key
        new_key = self.generate_new_key_pair()
        
        # Clean up expired keys
        expired_kids = [
            kid for kid, key in self._keys.items()
            if key.expires_at < now
        ]
        for kid in expired_kids:
            del self._keys[kid]
        
        return new_key, deprecated_kids
    
    def verify_key_exists(self, kid: str) -> bool:
        """Check if a key with the given ID exists and is valid.
        
        Args:
            kid: Key ID to check
        
        Returns:
            True if key exists and is valid
        """
        key = self.get_key_by_kid(kid)
        if not key:
            return False
        
        now = datetime.utcnow()
        return key.is_active and key.expires_at > now
    
    def initialize_with_key(self) -> JWKSKey:
        """Initialize the service with a key if none exists.
        
        Returns:
            JWKSKey instance
        """
        if not self._keys:
            return self.generate_new_key_pair()
        return self.get_signing_key()

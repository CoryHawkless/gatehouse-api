"""Encryption utilities for sensitive data."""
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Encryption key derivation settings
SALT_LENGTH = 16
KEY_ITERATIONS = 480000


def _get_fernet_key(secret_key: str, salt: bytes = None) -> bytes:
    """
    Derive a Fernet key from a secret key using PBKDF2.
    
    Args:
        secret_key: The master secret key
        salt: Optional salt bytes (will be generated if not provided)
    
    Returns:
        32-byte key suitable for Fernet encryption
    """
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KEY_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
    return key


def encrypt(plaintext: str, secret_key: str = None) -> str:
    """
    Encrypt a string using Fernet symmetric encryption.
    
    Args:
        plaintext: The string to encrypt
        secret_key: The encryption key (uses app config if not provided)
    
    Returns:
        Base64-encoded encrypted string with salt prepended
    """
    from flask import current_app
    
    if not plaintext:
        return ""
    
    # Get secret key from app config or use provided key
    if secret_key is None:
        secret_key = current_app.config.get("ENCRYPTION_KEY", "")
    
    if not secret_key:
        raise ValueError("Encryption key not configured")
    
    # Generate a random salt for this encryption
    salt = os.urandom(SALT_LENGTH)
    fernet_key = _get_fernet_key(secret_key, salt)
    fernet = Fernet(fernet_key)
    
    # Encrypt the plaintext
    encrypted_bytes = fernet.encrypt(plaintext.encode())
    
    # Combine salt + encrypted data and base64 encode
    combined = salt + encrypted_bytes
    return base64.urlsafe_b64encode(combined).decode()


def decrypt(encrypted_data: str, secret_key: str = None) -> str:
    """
    Decrypt a string that was encrypted with the encrypt function.
    
    Args:
        encrypted_data: Base64-encoded encrypted string with salt prepended
        secret_key: The encryption key (uses app config if not provided)
    
    Returns:
        The original plaintext string
    """
    from flask import current_app
    
    if not encrypted_data:
        return ""
    
    # Get secret key from app config or use provided key
    if secret_key is None:
        secret_key = current_app.config.get("ENCRYPTION_KEY", "")
    
    if not secret_key:
        raise ValueError("Encryption key not configured")
    
    try:
        # Decode from base64
        combined = base64.urlsafe_b64decode(encrypted_data.encode())
        
        # Extract salt and encrypted data
        salt = combined[:SALT_LENGTH]
        encrypted_bytes = combined[SALT_LENGTH:]
        
        # Derive the key and decrypt
        fernet_key = _get_fernet_key(secret_key, salt)
        fernet = Fernet(fernet_key)
        plaintext = fernet.decrypt(encrypted_bytes)
        
        return plaintext.decode()
    except (InvalidToken, ValueError):
        raise ValueError("Failed to decrypt data - invalid key or corrupted data")

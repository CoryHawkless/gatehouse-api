"""Unit tests for TOTPService."""
import base64
import pytest
from app.services.totp_service import TOTPService


@pytest.mark.unit
class TestTOTPService:
    """Tests for TOTPService."""

    # Test generate_secret()
    def test_generate_secret_returns_string(self):
        """Test that generate_secret returns a string."""
        secret = TOTPService.generate_secret()
        assert isinstance(secret, str)

    def test_generate_secret_length(self):
        """Test that generate_secret returns a 32-character string."""
        secret = TOTPService.generate_secret()
        assert len(secret) == 32

    def test_generate_secret_base32_encoded(self):
        """Test that generate_secret returns a base32 encoded string."""
        secret = TOTPService.generate_secret()
        # Base32 characters are A-Z and 2-7
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        assert all(c in valid_chars for c in secret)

    def test_generate_secret_unique(self):
        """Test that generate_secret produces unique secrets."""
        secret1 = TOTPService.generate_secret()
        secret2 = TOTPService.generate_secret()
        assert secret1 != secret2

    # Test generate_provisioning_uri()
    def test_generate_provisioning_uri_format(self):
        """Test that provisioning URI is generated correctly."""
        email = "user@example.com"
        secret = "JBSWY3DPEHPK3PXP"
        issuer = "Gatehouse"

        uri = TOTPService.generate_provisioning_uri(email, secret, issuer)

        assert isinstance(uri, str)
        assert uri.startswith("otpauth://totp/")

    def test_generate_provisioning_uri_contains_email(self):
        """Test that provisioning URI contains the user email."""
        email = "user@example.com"
        secret = "JBSWY3DPEHPK3PXP"
        issuer = "Gatehouse"

        uri = TOTPService.generate_provisioning_uri(email, secret, issuer)

        assert email in uri

    def test_generate_provisioning_uri_contains_secret(self):
        """Test that provisioning URI contains the secret."""
        email = "user@example.com"
        secret = "JBSWY3DPEHPK3PXP"
        issuer = "Gatehouse"

        uri = TOTPService.generate_provisioning_uri(email, secret, issuer)

        assert secret in uri

    def test_generate_provisioning_uri_contains_issuer(self):
        """Test that provisioning URI contains the issuer."""
        email = "user@example.com"
        secret = "JBSWY3DPEHPK3PXP"
        issuer = "Gatehouse"

        uri = TOTPService.generate_provisioning_uri(email, secret, issuer)

        assert issuer in uri

    def test_generate_provisioning_uri_custom_issuer(self):
        """Test that provisioning URI uses custom issuer."""
        email = "user@example.com"
        secret = "JBSWY3DPEHPK3PXP"
        custom_issuer = "MyApp"

        uri = TOTPService.generate_provisioning_uri(email, secret, custom_issuer)

        assert custom_issuer in uri

    # Test verify_code()
    def test_verify_code_valid(self):
        """Test that a valid TOTP code is accepted."""
        secret = TOTPService.generate_secret()
        # Generate a valid code using pyotp
        import pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        result = TOTPService.verify_code(secret, valid_code)

        assert result is True

    def test_verify_code_invalid(self):
        """Test that an invalid TOTP code is rejected."""
        secret = TOTPService.generate_secret()
        invalid_code = "000000"

        result = TOTPService.verify_code(secret, invalid_code)

        assert result is False

    def test_verify_code_window_parameter(self):
        """Test that the time window parameter works correctly."""
        secret = TOTPService.generate_secret()
        import pyotp
        totp = pyotp.TOTP(secret)

        # Get current code
        current_code = totp.now()

        # Verify with window=1 (default) - should accept current code
        result = TOTPService.verify_code(secret, current_code, window=1)
        assert result is True

        # Verify with window=0 - should only accept exact time match
        result = TOTPService.verify_code(secret, current_code, window=0)
        assert result is True

    def test_verify_code_wrong_length(self):
        """Test that codes with wrong length are rejected."""
        secret = TOTPService.generate_secret()
        wrong_length_code = "12345"  # 5 digits instead of 6

        result = TOTPService.verify_code(secret, wrong_length_code)

        assert result is False

    # Test generate_backup_codes()
    def test_generate_backup_codes_default_count(self):
        """Test that generate_backup_codes generates 10 codes by default."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes()

        assert len(plain_codes) == 10
        assert len(hashed_codes) == 10

    def test_generate_backup_codes_custom_count(self):
        """Test that generate_backup_codes generates the specified number of codes."""
        count = 5
        plain_codes, hashed_codes = TOTPService.generate_backup_codes(count)

        assert len(plain_codes) == count
        assert len(hashed_codes) == count

    def test_generate_backup_codes_plain_are_strings(self):
        """Test that plain backup codes are strings."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes()

        assert all(isinstance(code, str) for code in plain_codes)

    def test_generate_backup_codes_plain_length(self):
        """Test that plain backup codes are 16 characters long."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes()

        assert all(len(code) == 16 for code in plain_codes)

    def test_generate_backup_codes_hashed_different_from_plain(self):
        """Test that hashed codes are different from plain codes."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes()

        for plain, hashed in zip(plain_codes, hashed_codes):
            assert plain != hashed

    def test_generate_backup_codes_are_bcrypt_hashes(self):
        """Test that hashed codes are bcrypt hashes."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes()

        # Bcrypt hashes start with $2a$, $2b$, or $2y$
        for hashed in hashed_codes:
            assert hashed.startswith("$2")

    def test_generate_backup_codes_unique(self):
        """Test that generated backup codes are unique."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes()

        assert len(set(plain_codes)) == len(plain_codes)
        assert len(set(hashed_codes)) == len(hashed_codes)

    # Test verify_backup_code()
    def test_verify_backup_code_valid(self):
        """Test that a valid backup code is accepted and removed."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes(count=3)
        code_to_verify = plain_codes[0]

        is_valid, remaining_codes = TOTPService.verify_backup_code(hashed_codes, code_to_verify)

        assert is_valid is True
        assert len(remaining_codes) == 2

    def test_verify_backup_code_invalid(self):
        """Test that an invalid backup code is rejected."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes(count=3)
        invalid_code = "INVALIDCODE1234"

        is_valid, remaining_codes = TOTPService.verify_backup_code(hashed_codes, invalid_code)

        assert is_valid is False
        assert len(remaining_codes) == 3

    def test_verify_backup_code_remaining_updated(self):
        """Test that the remaining codes list is updated correctly."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes(count=5)
        code_to_verify = plain_codes[2]

        is_valid, remaining_codes = TOTPService.verify_backup_code(hashed_codes, code_to_verify)

        assert is_valid is True
        # The verified code should be removed
        assert len(remaining_codes) == 4
        # The remaining codes should not include the verified code's hash
        assert hashed_codes[2] not in remaining_codes

    def test_verify_backup_code_case_sensitive(self):
        """Test that backup code verification is case sensitive."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes(count=1)
        code_to_verify = plain_codes[0].lower()  # Convert to lowercase

        is_valid, remaining_codes = TOTPService.verify_backup_code(hashed_codes, code_to_verify)

        assert is_valid is False
        assert len(remaining_codes) == 1

    def test_verify_backup_code_single_use(self):
        """Test that a backup code can only be used once."""
        plain_codes, hashed_codes = TOTPService.generate_backup_codes(count=1)
        code_to_verify = plain_codes[0]

        # First use - should succeed
        is_valid1, remaining1 = TOTPService.verify_backup_code(hashed_codes, code_to_verify)
        assert is_valid1 is True
        assert len(remaining1) == 0

        # Second use - should fail (code already consumed)
        is_valid2, remaining2 = TOTPService.verify_backup_code(remaining1, code_to_verify)
        assert is_valid2 is False
        assert len(remaining2) == 0

    # Test generate_qr_code_data_uri()
    def test_generate_qr_code_data_uri_format(self):
        """Test that a data URI is generated."""
        provisioning_uri = "otpauth://totp/Gatehouse:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Gatehouse"

        data_uri = TOTPService.generate_qr_code_data_uri(provisioning_uri)

        assert isinstance(data_uri, str)

    def test_generate_qr_code_data_uri_starts_with_prefix(self):
        """Test that the data URI starts with the correct prefix."""
        provisioning_uri = "otpauth://totp/Gatehouse:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Gatehouse"

        data_uri = TOTPService.generate_qr_code_data_uri(provisioning_uri)

        assert data_uri.startswith("data:image/png;base64,")

    def test_generate_qr_code_data_uri_contains_base64(self):
        """Test that the data URI contains base64 encoded data."""
        provisioning_uri = "otpauth://totp/Gatehouse:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Gatehouse"

        data_uri = TOTPService.generate_qr_code_data_uri(provisioning_uri)

        # Extract the base64 part (after the prefix)
        base64_part = data_uri.split("data:image/png;base64,")[1]

        # Verify it's valid base64
        try:
            base64.b64decode(base64_part)
            assert True
        except Exception:
            assert False, "Data URI does not contain valid base64 data"

    def test_generate_qr_code_data_uri_different_uris(self):
        """Test that different provisioning URIs generate different QR codes."""
        uri1 = "otpauth://totp/Gatehouse:user1@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Gatehouse"
        uri2 = "otpauth://totp/Gatehouse:user2@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Gatehouse"

        data_uri1 = TOTPService.generate_qr_code_data_uri(uri1)
        data_uri2 = TOTPService.generate_qr_code_data_uri(uri2)

        assert data_uri1 != data_uri2

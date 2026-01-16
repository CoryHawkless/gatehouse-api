"""Authentication schemas for validation."""
from marshmallow import Schema, fields, validate, validates_schema, ValidationError


class RegisterSchema(Schema):
    """Schema for user registration."""

    email = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128),
    )
    password_confirm = fields.Str(required=True)
    full_name = fields.Str(allow_none=True, validate=validate.Length(max=255))

    @validates_schema
    def validate_passwords_match(self, data, **kwargs):
        """Validate that passwords match."""
        if data.get("password") != data.get("password_confirm"):
            raise ValidationError("Passwords do not match", field_name="password_confirm")


class LoginSchema(Schema):
    """Schema for user login."""

    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=1))
    remember_me = fields.Bool(missing=False)


class RefreshTokenSchema(Schema):
    """Schema for token refresh."""

    refresh_token = fields.Str(required=True)


class ForgotPasswordSchema(Schema):
    """Schema for forgot password request."""

    email = fields.Email(required=True)


class ResetPasswordSchema(Schema):
    """Schema for password reset."""

    token = fields.Str(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128),
    )
    password_confirm = fields.Str(required=True)

    @validates_schema
    def validate_passwords_match(self, data, **kwargs):
        """Validate that passwords match."""
        if data.get("password") != data.get("password_confirm"):
            raise ValidationError("Passwords do not match", field_name="password_confirm")


class TOTPVerifyEnrollmentSchema(Schema):
    """Schema for TOTP enrollment verification."""

    code = fields.Str(
        required=True,
        validate=validate.Regexp(
            r"^\d{6}$",
            error="Code must be a 6-digit number",
        ),
    )
    client_timestamp = fields.Int(
        required=False,
        allow_none=True,
        metadata={"description": "Client UTC timestamp in seconds since epoch for TOTP verification"},
    )


class TOTPVerifySchema(Schema):
    """Schema for TOTP code verification during login."""

    code = fields.Str(required=True)
    is_backup_code = fields.Bool(missing=False)
    client_timestamp = fields.Int(
        required=False,
        allow_none=True,
        metadata={"description": "Client UTC timestamp in seconds since epoch for TOTP verification"},
    )


class TOTPDisableSchema(Schema):
    """Schema for disabling TOTP."""

    password = fields.Str(required=True, validate=validate.Length(min=1))


class TOTPRegenerateBackupCodesSchema(Schema):
    """Schema for regenerating backup codes."""

    password = fields.Str(required=True, validate=validate.Length(min=1))

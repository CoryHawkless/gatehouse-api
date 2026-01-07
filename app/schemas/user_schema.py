"""User schemas for validation and serialization."""
from marshmallow import Schema, fields, validate, validates, ValidationError
from app.utils.constants import UserStatus


class UserSchema(Schema):
    """Schema for User model."""

    id = fields.Str(dump_only=True)
    email = fields.Email(required=True)
    email_verified = fields.Bool(dump_only=True)
    full_name = fields.Str(allow_none=True, validate=validate.Length(max=255))
    avatar_url = fields.Url(allow_none=True, validate=validate.Length(max=512))
    status = fields.Str(dump_only=True)
    last_login_at = fields.DateTime(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)


class UserUpdateSchema(Schema):
    """Schema for updating user profile."""

    full_name = fields.Str(allow_none=True, validate=validate.Length(max=255))
    avatar_url = fields.Url(allow_none=True, validate=validate.Length(max=512))


class ChangePasswordSchema(Schema):
    """Schema for changing password."""

    current_password = fields.Str(required=True, validate=validate.Length(min=1))
    new_password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128),
    )
    new_password_confirm = fields.Str(required=True)

    @validates("new_password")
    def validate_password_strength(self, value):
        """Validate password strength."""
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        if not any(char.isdigit() for char in value):
            raise ValidationError("Password must contain at least one digit")
        if not any(char.isupper() for char in value):
            raise ValidationError("Password must contain at least one uppercase letter")
        if not any(char.islower() for char in value):
            raise ValidationError("Password must contain at least one lowercase letter")

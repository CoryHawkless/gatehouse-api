"""Organization schemas for validation."""
from marshmallow import Schema, fields, validate


class OrganizationSchema(Schema):
    """Schema for Organization model."""

    id = fields.Str(dump_only=True)
    name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    slug = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True)
    logo_url = fields.Url(allow_none=True, validate=validate.Length(max=512))
    is_active = fields.Bool(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)


class OrganizationCreateSchema(Schema):
    """Schema for creating an organization."""

    name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    slug = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True)
    logo_url = fields.Url(allow_none=True, validate=validate.Length(max=512))


class OrganizationUpdateSchema(Schema):
    """Schema for updating an organization."""

    name = fields.Str(validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True)
    logo_url = fields.Url(allow_none=True, validate=validate.Length(max=512))


class OrganizationMemberSchema(Schema):
    """Schema for Organization Member."""

    id = fields.Str(dump_only=True)
    user_id = fields.Str(dump_only=True)
    organization_id = fields.Str(dump_only=True)
    role = fields.Str(dump_only=True)
    joined_at = fields.DateTime(dump_only=True)
    created_at = fields.DateTime(dump_only=True)


class InviteMemberSchema(Schema):
    """Schema for inviting a member to an organization."""

    email = fields.Email(required=True)
    role = fields.Str(
        required=True,
        validate=validate.OneOf(["owner", "admin", "member", "guest"])
    )


class UpdateMemberRoleSchema(Schema):
    """Schema for updating a member's role."""

    role = fields.Str(
        required=True,
        validate=validate.OneOf(["owner", "admin", "member", "guest"])
    )

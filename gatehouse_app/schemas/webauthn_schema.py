"""WebAuthn schemas for validation."""
from marshmallow import Schema, fields, validate, validates_schema, ValidationError


class WebAuthnRegistrationBeginSchema(Schema):
    """Schema for beginning WebAuthn registration."""
    # No required fields - uses authenticated user
    pass


class WebAuthnRegistrationCompleteSchema(Schema):
    """Schema for completing WebAuthn registration."""
    
    id = fields.Str(required=True)
    rawId = fields.Str(required=True)
    type = fields.Str(
        required=True,
        validate=validate.OneOf(["public-key"])
    )
    response = fields.Dict(required=True)
    transports = fields.List(
        fields.Str(validate=validate.OneOf(["usb", "nfc", "ble", "hybrid", "internal", "platform"])),
        load_default=[]
    )
    
    @validates_schema
    def validate_response(self, data, **kwargs):
        """Validate response contains required fields."""
        response = data.get("response", {})
        required_fields = ["attestationObject", "clientDataJSON"]
        for field in required_fields:
            if field not in response:
                raise ValidationError(
                    f"Missing required field in response: {field}",
                    field_name=f"response.{field}"
                )


class WebAuthnLoginBeginSchema(Schema):
    """Schema for beginning WebAuthn login."""
    
    email = fields.Email(required=True)


class WebAuthnLoginCompleteSchema(Schema):
    """Schema for completing WebAuthn login."""
    
    id = fields.Str(required=True)
    rawId = fields.Str(required=True)
    type = fields.Str(
        required=True,
        validate=validate.OneOf(["public-key"])
    )
    response = fields.Dict(required=True)
    clientExtensionResults = fields.Dict(load_default={})
    
    @validates_schema
    def validate_response(self, data, **kwargs):
        """Validate response contains required fields."""
        response = data.get("response", {})
        required_fields = ["authenticatorData", "clientDataJSON", "signature"]
        for field in required_fields:
            if field not in response:
                raise ValidationError(
                    f"Missing required field in response: {field}",
                    field_name=f"response.{field}"
                )


class WebAuthnCredentialRenameSchema(Schema):
    """Schema for renaming a WebAuthn credential."""
    
    name = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=100)
    )


class WebAuthnCredentialDeleteSchema(Schema):
    """Schema for deleting a WebAuthn credential."""
    
    password = fields.Str(
        required=True,
        validate=validate.Length(min=1)
    )
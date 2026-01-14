"""User endpoints."""
from flask import g, request
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.schemas.user_schema import UserUpdateSchema, ChangePasswordSchema
from gatehouse_app.services.user_service import UserService
from gatehouse_app.services.auth_service import AuthService


@api_v1_bp.route("/users/me", methods=["GET"])
@login_required
def get_me():
    """
    Get current user profile.

    Returns:
        200: User profile data
        401: Not authenticated
    """
    user = g.current_user

    return api_response(
        data={"user": user.to_dict()},
        message="User profile retrieved successfully",
    )


@api_v1_bp.route("/users/me", methods=["PATCH"])
@login_required
def update_me():
    """
    Update current user profile.

    Request body:
        full_name: Optional full name
        avatar_url: Optional avatar URL

    Returns:
        200: User updated successfully
        400: Validation error
        401: Not authenticated
    """
    try:
        # Validate request data
        schema = UserUpdateSchema()
        data = schema.load(request.json)

        # Update user
        user = UserService.update_user(g.current_user, **data)

        return api_response(
            data={"user": user.to_dict()},
            message="Profile updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/users/me", methods=["DELETE"])
@login_required
def delete_me():
    """
    Delete current user account (soft delete).

    Returns:
        200: Account deleted successfully
        401: Not authenticated
    """
    UserService.delete_user(g.current_user, soft=True)

    return api_response(
        message="Account deleted successfully",
    )


@api_v1_bp.route("/users/me/password", methods=["POST"])
@login_required
def change_password():
    """
    Change current user password.

    Request body:
        current_password: Current password
        new_password: New password
        new_password_confirm: New password confirmation

    Returns:
        200: Password changed successfully
        400: Validation error
        401: Not authenticated or invalid current password
    """
    try:
        # Validate request data
        schema = ChangePasswordSchema()
        data = schema.load(request.json)

        # Verify passwords match
        if data["new_password"] != data["new_password_confirm"]:
            return api_response(
                success=False,
                message="New passwords do not match",
                status=400,
                error_type="VALIDATION_ERROR",
                error_details={"new_password_confirm": ["Passwords do not match"]},
            )

        # Change password
        AuthService.change_password(
            user=g.current_user,
            current_password=data["current_password"],
            new_password=data["new_password"],
        )

        return api_response(
            message="Password changed successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/users/me/organizations", methods=["GET"])
@login_required
def get_my_organizations():
    """
    Get all organizations current user is a member of.

    Returns:
        200: List of organizations
        401: Not authenticated
    """
    organizations = UserService.get_user_organizations(g.current_user)

    return api_response(
        data={
            "organizations": [org.to_dict() for org in organizations],
            "count": len(organizations),
        },
        message="Organizations retrieved successfully",
    )

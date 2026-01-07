"""User service."""
from app.extensions import db
from app.models.user import User
from app.exceptions.validation_exceptions import UserNotFoundError
from app.utils.constants import AuditAction
from app.services.audit_service import AuditService


class UserService:
    """Service for user operations."""

    @staticmethod
    def get_user_by_id(user_id):
        """
        Get user by ID.

        Args:
            user_id: User ID

        Returns:
            User instance

        Raises:
            UserNotFoundError: If user not found
        """
        user = User.query.filter_by(id=user_id, deleted_at=None).first()
        if not user:
            raise UserNotFoundError()
        return user

    @staticmethod
    def get_user_by_email(email):
        """
        Get user by email.

        Args:
            email: User email

        Returns:
            User instance or None
        """
        return User.query.filter_by(email=email.lower(), deleted_at=None).first()

    @staticmethod
    def update_user(user, **kwargs):
        """
        Update user profile.

        Args:
            user: User instance
            **kwargs: Fields to update

        Returns:
            Updated User instance
        """
        allowed_fields = ["full_name", "avatar_url"]
        update_data = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if update_data:
            user.update(**update_data)

            # Log user update
            AuditService.log_action(
                action=AuditAction.USER_UPDATE,
                user_id=user.id,
                resource_type="user",
                resource_id=user.id,
                metadata=update_data,
                description="User profile updated",
            )

        return user

    @staticmethod
    def delete_user(user, soft=True):
        """
        Delete user account.

        Args:
            user: User instance
            soft: If True, performs soft delete

        Returns:
            Deleted User instance
        """
        user.delete(soft=soft)

        # Log user deletion
        AuditService.log_action(
            action=AuditAction.USER_DELETE,
            user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            description=f"User account {'soft' if soft else 'hard'} deleted",
        )

        return user

    @staticmethod
    def get_user_organizations(user):
        """
        Get all organizations the user is a member of.

        Args:
            user: User instance

        Returns:
            List of organizations
        """
        return user.get_organizations()

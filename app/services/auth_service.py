"""Authentication service."""
import logging
import secrets
from datetime import datetime, timedelta
from flask import request, g, current_app
from app.extensions import db, bcrypt
from app.models.user import User
from app.models.authentication_method import AuthenticationMethod
from app.models.session import Session
from app.utils.constants import AuthMethodType, SessionStatus, UserStatus, AuditAction
from app.exceptions.auth_exceptions import InvalidCredentialsError, AccountSuspendedError, AccountInactiveError
from app.exceptions.validation_exceptions import EmailAlreadyExistsError
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class AuthService:
    """Service for authentication operations."""

    @staticmethod
    def register_user(email, password, full_name=None):
        """
        Register a new user with email/password.

        Args:
            email: User email address
            password: Plain text password
            full_name: Optional full name

        Returns:
            User instance

        Raises:
            EmailAlreadyExistsError: If email is already registered
        """
        # Check if email already exists
        existing_user = User.query.filter_by(email=email.lower()).first()
        if existing_user and existing_user.deleted_at is None:
            raise EmailAlreadyExistsError()

        # Create user
        user = User(
            email=email.lower(),
            full_name=full_name,
            status=UserStatus.ACTIVE,
        )
        user.save()

        # Create password authentication method
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        auth_method = AuthenticationMethod(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            password_hash=password_hash,
            is_primary=True,
            verified=True,
        )
        auth_method.save()

        # Log the registration
        AuditService.log_action(
            action=AuditAction.USER_REGISTER,
            user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            description=f"User registered with email: {email}",
        )

        return user

    @staticmethod
    def authenticate(email, password):
        """
        Authenticate user with email/password.

        Args:
            email: User email
            password: Plain text password

        Returns:
            User instance if authentication succeeds

        Raises:
            InvalidCredentialsError: If credentials are invalid
            AccountSuspendedError: If account is suspended
            AccountInactiveError: If account is inactive
        """
        # Find user
        user = User.query.filter_by(email=email.lower(), deleted_at=None).first()
        
        # Development-only debug logging for user existence check
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] User lookup: email={email}, exists={user is not None}")
        
        if not user:
            raise InvalidCredentialsError()
        
        # Check account status
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] Account status: user_id={user.id}, status={user.status}")
        
        if user.status == UserStatus.SUSPENDED:
            raise AccountSuspendedError()
        if user.status == UserStatus.INACTIVE:
            raise AccountInactiveError()
        
        # Find password auth method
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            deleted_at=None,
        ).first()
        
        # Development-only debug logging for auth method lookup
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] Auth method lookup: user_id={user.id}, has_password_auth={auth_method is not None and auth_method.password_hash is not None}")
        
        if not auth_method or not auth_method.password_hash:
            raise InvalidCredentialsError()
        
        # Verify password
        password_valid = bcrypt.check_password_hash(auth_method.password_hash, password)
        
        # Development-only debug logging for password validation (without logging actual password)
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] Password validation: user_id={user.id}, valid={password_valid}")
        
        if not password_valid:
            raise InvalidCredentialsError()

        # Update last login
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = request.remote_addr
        auth_method.last_used_at = datetime.utcnow()
        db.session.commit()

        return user

    @staticmethod
    def create_session(user, duration_seconds=86400):
        """
        Create a new session for the user.

        Args:
            user: User instance
            duration_seconds: Session duration in seconds

        Returns:
            Session instance
        """
        # Generate session token
        token = secrets.token_urlsafe(32)

        # Create session
        session = Session(
            user_id=user.id,
            token=token,
            status=SessionStatus.ACTIVE,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            expires_at=datetime.utcnow() + timedelta(seconds=duration_seconds),
            last_activity_at=datetime.utcnow(),
        )
        session.save()

        # Log session creation
        AuditService.log_action(
            action=AuditAction.SESSION_CREATE,
            user_id=user.id,
            resource_type="session",
            resource_id=session.id,
            description="User session created",
        )

        return session

    @staticmethod
    def change_password(user, current_password, new_password):
        """
        Change user password.

        Args:
            user: User instance
            current_password: Current password
            new_password: New password

        Raises:
            InvalidCredentialsError: If current password is incorrect
        """
        # Find password auth method
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            deleted_at=None,
        ).first()

        if not auth_method or not auth_method.password_hash:
            raise InvalidCredentialsError("No password authentication method found")

        # Verify current password
        if not bcrypt.check_password_hash(auth_method.password_hash, current_password):
            raise InvalidCredentialsError("Current password is incorrect")

        # Update password
        auth_method.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        # Log password change
        AuditService.log_action(
            action=AuditAction.PASSWORD_CHANGE,
            user_id=user.id,
            description="User changed password",
        )

    @staticmethod
    def revoke_session(session_id, reason=None):
        """
        Revoke a session.

        Args:
            session_id: Session ID to revoke
            reason: Optional revocation reason
        """
        session = Session.query.get(session_id)
        if session:
            session.revoke(reason=reason)

            # Log session revocation
            AuditService.log_action(
                action=AuditAction.SESSION_REVOKE,
                user_id=session.user_id,
                resource_type="session",
                resource_id=session.id,
                description=f"Session revoked: {reason or 'User logout'}",
            )

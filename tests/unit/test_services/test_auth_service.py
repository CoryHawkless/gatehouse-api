"""Unit tests for AuthService."""
import pytest
from app.services.auth_service import AuthService
from app.exceptions.auth_exceptions import InvalidCredentialsError
from app.exceptions.validation_exceptions import EmailAlreadyExistsError
from app.utils.constants import UserStatus, AuthMethodType


@pytest.mark.unit
class TestAuthService:
    """Tests for AuthService."""

    def test_register_user(self, db):
        """Test user registration."""
        email = "newuser@example.com"
        password = "SecurePassword123!"
        full_name = "New User"

        user = AuthService.register_user(
            email=email,
            password=password,
            full_name=full_name,
        )

        assert user.id is not None
        assert user.email == email.lower()
        assert user.full_name == full_name
        assert user.status == UserStatus.ACTIVE
        assert user.has_password_auth()

    def test_register_duplicate_email(self, db, test_user):
        """Test registering with duplicate email."""
        with pytest.raises(EmailAlreadyExistsError):
            AuthService.register_user(
                email=test_user.email,
                password="SomePassword123!",
            )

    def test_authenticate_success(self, db, test_user):
        """Test successful authentication."""
        user = AuthService.authenticate(
            email=test_user.email,
            password=test_user._test_password,
        )

        assert user.id == test_user.id
        assert user.last_login_at is not None

    def test_authenticate_wrong_password(self, db, test_user):
        """Test authentication with wrong password."""
        with pytest.raises(InvalidCredentialsError):
            AuthService.authenticate(
                email=test_user.email,
                password="WrongPassword123!",
            )

    def test_authenticate_nonexistent_user(self, db):
        """Test authentication with non-existent email."""
        with pytest.raises(InvalidCredentialsError):
            AuthService.authenticate(
                email="nonexistent@example.com",
                password="SomePassword123!",
            )

    def test_create_session(self, app, db, test_user):
        """Test creating a session."""
        with app.test_request_context():
            session = AuthService.create_session(test_user)

            assert session.id is not None
            assert session.user_id == test_user.id
            assert session.token is not None
            assert session.is_active()

    def test_change_password(self, app, db, test_user):
        """Test changing password."""
        with app.test_request_context():
            new_password = "NewPassword456!"

            AuthService.change_password(
                user=test_user,
                current_password=test_user._test_password,
                new_password=new_password,
            )

            # Verify can login with new password
            user = AuthService.authenticate(
                email=test_user.email,
                password=new_password,
            )

            assert user.id == test_user.id

    def test_change_password_wrong_current(self, app, db, test_user):
        """Test changing password with wrong current password."""
        with app.test_request_context():
            with pytest.raises(InvalidCredentialsError):
                AuthService.change_password(
                    user=test_user,
                    current_password="WrongPassword123!",
                    new_password="NewPassword456!",
                )

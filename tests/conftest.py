"""Pytest configuration and fixtures."""
import pytest
from gatehouse_app import create_app
from gatehouse_app.extensions import db as _db
from gatehouse_app.models import User, Organization, OrganizationMember
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.utils.constants import OrganizationRole


@pytest.fixture(scope="session")
def app():
    """Create application for testing."""
    app = create_app("testing")
    return app


@pytest.fixture(scope="function")
def db(app):
    """Create database for testing."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app, db):
    """Create test client."""
    return app.test_client()


@pytest.fixture(scope="function")
def test_user(db):
    """Create a test user."""
    email = "test@example.com"
    password = "TestPassword123!"
    full_name = "Test User"

    user = AuthService.register_user(
        email=email,
        password=password,
        full_name=full_name,
    )

    # Store password for testing
    user._test_password = password

    return user


@pytest.fixture(scope="function")
def test_organization(db, test_user):
    """Create a test organization."""
    from gatehouse_app.services.organization_service import OrganizationService

    org = OrganizationService.create_organization(
        name="Test Organization",
        slug="test-org",
        owner_user_id=test_user.id,
        description="A test organization",
    )

    return org


@pytest.fixture(scope="function")
def authenticated_client(client, test_user):
    """Create authenticated test client."""
    # Login
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": test_user.email,
            "password": test_user._test_password,
        },
    )

    assert response.status_code == 200

    return client


@pytest.fixture(scope="function")
def second_test_user(db):
    """Create a second test user."""
    email = "second@example.com"
    password = "TestPassword123!"
    full_name = "Second User"

    user = AuthService.register_user(
        email=email,
        password=password,
        full_name=full_name,
    )

    user._test_password = password

    return user

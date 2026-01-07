"""Unit tests for models."""
import pytest
from datetime import datetime
from app.models import User, Organization
from app.utils.constants import UserStatus


@pytest.mark.unit
class TestUserModel:
    """Tests for User model."""

    def test_create_user(self, db):
        """Test creating a user."""
        user = User(
            email="test@example.com",
            full_name="Test User",
            status=UserStatus.ACTIVE,
        )
        user.save()

        assert user.id is not None
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        assert user.status == UserStatus.ACTIVE
        assert user.created_at is not None
        assert user.deleted_at is None

    def test_user_to_dict(self, test_user):
        """Test user to_dict method."""
        user_dict = test_user.to_dict()

        assert "id" in user_dict
        assert "email" in user_dict
        assert user_dict["email"] == test_user.email
        assert "created_at" in user_dict

    def test_user_soft_delete(self, test_user):
        """Test soft deleting a user."""
        test_user.delete(soft=True)

        assert test_user.deleted_at is not None
        assert isinstance(test_user.deleted_at, datetime)


@pytest.mark.unit
class TestOrganizationModel:
    """Tests for Organization model."""

    def test_create_organization(self, db):
        """Test creating an organization."""
        org = Organization(
            name="Test Org",
            slug="test-org",
            description="Test organization",
        )
        org.save()

        assert org.id is not None
        assert org.name == "Test Org"
        assert org.slug == "test-org"
        assert org.is_active is True
        assert org.created_at is not None

    def test_organization_to_dict(self, test_organization):
        """Test organization to_dict method."""
        org_dict = test_organization.to_dict()

        assert "id" in org_dict
        assert "name" in org_dict
        assert org_dict["name"] == test_organization.name
        assert "slug" in org_dict

    def test_get_member_count(self, test_organization):
        """Test getting member count."""
        count = test_organization.get_member_count()
        assert count == 1  # Only the owner

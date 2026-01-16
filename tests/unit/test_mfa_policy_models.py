"""Unit tests for MFA policy models."""
import pytest
from datetime import datetime, timezone, timedelta
from gatehouse_app.models import (
    User,
    Organization,
    OrganizationMember,
    OrganizationSecurityPolicy,
    UserSecurityPolicy,
    MfaPolicyCompliance,
    Session,
)
from gatehouse_app.utils.constants import (
    UserStatus,
    MfaPolicyMode,
    MfaComplianceStatus,
    MfaRequirementOverride,
    SessionStatus,
    OrganizationRole,
)


@pytest.mark.unit
class TestOrganizationSecurityPolicyModel:
    """Tests for OrganizationSecurityPolicy model."""

    def test_create_org_security_policy(self, db, test_organization):
        """Test creating an organization security policy."""
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
            notify_days_before=7,
        )
        policy.save()

        assert policy.id is not None
        assert policy.organization_id == test_organization.id
        assert policy.mfa_policy_mode == MfaPolicyMode.OPTIONAL
        assert policy.mfa_grace_period_days == 14
        assert policy.notify_days_before == 7
        assert policy.policy_version == 1
        assert policy.created_at is not None

    def test_org_security_policy_to_dict(self, db, test_organization):
        """Test organization security policy to_dict method."""
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=7,
            notify_days_before=3,
        )
        policy.save()

        policy_dict = policy.to_dict()

        assert "id" in policy_dict
        assert "organization_id" in policy_dict
        assert policy_dict["organization_id"] == test_organization.id
        assert "mfa_policy_mode" in policy_dict
        assert "mfa_grace_period_days" in policy_dict

    def test_org_security_policy_relationships(self, db, test_organization):
        """Test organization security policy relationships."""
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
        )
        policy.save()

        # Test relationship
        assert policy.organization is not None
        assert policy.organization.id == test_organization.id


@pytest.mark.unit
class TestUserSecurityPolicyModel:
    """Tests for UserSecurityPolicy model."""

    def test_create_user_security_policy(self, db, test_user, test_organization):
        """Test creating a user security policy."""
        policy = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.INHERIT,
        )
        policy.save()

        assert policy.id is not None
        assert policy.user_id == test_user.id
        assert policy.organization_id == test_organization.id
        assert policy.mfa_override_mode == MfaRequirementOverride.INHERIT
        assert policy.force_totp is False
        assert policy.force_webauthn is False

    def test_user_security_policy_with_overrides(self, db, test_user, test_organization):
        """Test user security policy with override settings."""
        policy = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.REQUIRED,
            force_totp=True,
            force_webauthn=False,
        )
        policy.save()

        assert policy.mfa_override_mode == MfaRequirementOverride.REQUIRED
        assert policy.force_totp is True
        assert policy.force_webauthn is False

    def test_user_security_policy_exempt(self, db, test_user, test_organization):
        """Test user security policy with exempt override."""
        policy = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.EXEMPT,
        )
        policy.save()

        assert policy.mfa_override_mode == MfaRequirementOverride.EXEMPT

    def test_user_security_policy_relationships(self, db, test_user, test_organization):
        """Test user security policy relationships."""
        policy = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.INHERIT,
        )
        policy.save()

        # Test relationships
        assert policy.user is not None
        assert policy.user.id == test_user.id
        assert policy.organization is not None
        assert policy.organization.id == test_organization.id


@pytest.mark.unit
class TestMfaPolicyComplianceModel:
    """Tests for MfaPolicyCompliance model."""

    def test_create_mfa_policy_compliance(self, db, test_user, test_organization):
        """Test creating an MFA policy compliance record."""
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.NOT_APPLICABLE,
            policy_version=1,
        )
        compliance.save()

        assert compliance.id is not None
        assert compliance.user_id == test_user.id
        assert compliance.organization_id == test_organization.id
        assert compliance.status == MfaComplianceStatus.NOT_APPLICABLE
        assert compliance.policy_version == 1
        assert compliance.notification_count == 0

    def test_mfa_policy_compliance_in_grace(self, db, test_user, test_organization):
        """Test MFA compliance record in grace period."""
        now = datetime.now(timezone.utc)
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.IN_GRACE,
            policy_version=1,
            applied_at=now,
            deadline_at=now + timedelta(days=14),
        )
        compliance.save()

        assert compliance.status == MfaComplianceStatus.IN_GRACE
        assert compliance.applied_at is not None
        assert compliance.deadline_at is not None
        assert compliance.deadline_at > now

    def test_mfa_policy_compliance_compliant(self, db, test_user, test_organization):
        """Test MFA compliance record when compliant."""
        now = datetime.now(timezone.utc)
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.COMPLIANT,
            policy_version=1,
            applied_at=now - timedelta(days=30),
            deadline_at=now - timedelta(days=16),
            compliant_at=now - timedelta(days=16),
        )
        compliance.save()

        assert compliance.status == MfaComplianceStatus.COMPLIANT
        assert compliance.compliant_at is not None

    def test_mfa_policy_compliance_suspended(self, db, test_user, test_organization):
        """Test MFA compliance record when suspended."""
        now = datetime.now(timezone.utc)
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.SUSPENDED,
            policy_version=1,
            applied_at=now - timedelta(days=30),
            deadline_at=now - timedelta(days=16),
            suspended_at=now - timedelta(days=16),
        )
        compliance.save()

        assert compliance.status == MfaComplianceStatus.SUSPENDED
        assert compliance.suspended_at is not None

    def test_mfa_policy_compliance_relationships(self, db, test_user, test_organization):
        """Test MFA compliance relationships."""
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.NOT_APPLICABLE,
            policy_version=1,
        )
        compliance.save()

        # Test relationships
        assert compliance.user is not None
        assert compliance.user.id == test_user.id
        assert compliance.organization is not None
        assert compliance.organization.id == test_organization.id


@pytest.mark.unit
class TestSessionModelComplianceFlag:
    """Tests for Session model compliance flag."""

    def test_session_default_not_compliance_only(self, db, test_user):
        """Test that sessions are not compliance only by default."""
        session = Session(
            user_id=test_user.id,
            token="test-token-123",
            status=SessionStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            last_activity_at=datetime.now(timezone.utc),
        )
        session.save()

        assert session.is_compliance_only is False

    def test_session_compliance_only(self, db, test_user):
        """Test creating a compliance-only session."""
        session = Session(
            user_id=test_user.id,
            token="compliance-token-123",
            status=SessionStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            last_activity_at=datetime.now(timezone.utc),
            is_compliance_only=True,
        )
        session.save()

        assert session.is_compliance_only is True

    def test_session_to_dict_excludes_token(self, db, test_user):
        """Test that session to_dict excludes the token."""
        session = Session(
            user_id=test_user.id,
            token="test-token-456",
            status=SessionStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            last_activity_at=datetime.now(timezone.utc),
        )
        session.save()

        session_dict = session.to_dict()

        assert "id" in session_dict
        assert "user_id" in session_dict
        assert "is_compliance_only" in session_dict
        assert session_dict["is_compliance_only"] is False


@pytest.mark.unit
class TestUserStatusComplianceSuspended:
    """Tests for UserStatus.COMPLIANCE_SUSPENDED."""

    def test_compliance_suspended_status_exists(self):
        """Test that COMPLIANCE_SUSPENDED status exists."""
        assert UserStatus.COMPLIANCE_SUSPENDED.value == "compliance_suspended"

    def test_create_compliance_suspended_user(self, db):
        """Test creating a compliance suspended user."""
        user = User(
            email="suspended@example.com",
            full_name="Suspended User",
            status=UserStatus.COMPLIANCE_SUSPENDED,
        )
        user.save()

        assert user.status == UserStatus.COMPLIANCE_SUSPENDED

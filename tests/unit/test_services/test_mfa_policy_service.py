"""Unit tests for MfaPolicyService."""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from gatehouse_app.models import (
    User,
    Organization,
    OrganizationMember,
    OrganizationSecurityPolicy,
    UserSecurityPolicy,
    MfaPolicyCompliance,
    Session,
)
from gatehouse_app.services.mfa_policy_service import (
    MfaPolicyService,
    OrgPolicyDto,
    EffectiveUserPolicyDto,
    AggregateMfaStateDto,
    LoginPolicyResult,
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
class TestMfaPolicyService:
    """Tests for MfaPolicyService."""

    def test_get_org_policy_not_found(self, db, test_organization):
        """Test getting organization policy when none exists."""
        policy = MfaPolicyService.get_org_policy(test_organization.id)
        assert policy is None

    def test_get_org_policy_found(self, db, test_organization):
        """Test getting organization policy when it exists."""
        # Create policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
        )
        org_policy.save()

        policy = MfaPolicyService.get_org_policy(test_organization.id)

        assert policy is not None
        assert policy.organization_id == test_organization.id
        assert policy.mfa_policy_mode == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value
        assert policy.mfa_grace_period_days == 14
        assert policy.notify_days_before == 7
        assert policy.policy_version == 1

    def test_get_effective_user_policy_no_org_policy(self, db, test_user, test_organization):
        """Test effective user policy when no org policy exists."""
        policy = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        assert policy is not None
        assert policy.organization_id == test_organization.id
        assert policy.effective_mode == MfaPolicyMode.DISABLED.value
        assert policy.requires_totp is False
        assert policy.requires_webauthn is False
        assert policy.is_exempt is True

    def test_get_effective_user_policy_with_org_policy(self, db, test_user, test_organization):
        """Test effective user policy with org policy and no override."""
        # Create org policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
        )
        org_policy.save()

        policy = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        assert policy is not None
        assert policy.effective_mode == MfaPolicyMode.REQUIRE_TOTP.value
        assert policy.requires_totp is True
        assert policy.requires_webauthn is False
        assert policy.is_exempt is False

    def test_get_effective_user_policy_with_override_inherit(self, db, test_user, test_organization):
        """Test effective user policy with INHERIT override."""
        # Create org policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_WEBAUTHN,
            mfa_grace_period_days=7,
        )
        org_policy.save()

        # Create user override
        user_override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.INHERIT,
        )
        user_override.save()

        policy = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        assert policy.effective_mode == MfaPolicyMode.REQUIRE_WEBAUTHN.value
        assert policy.requires_webauthn is True

    def test_get_effective_user_policy_with_override_exempt(self, db, test_user, test_organization):
        """Test effective user policy with EXEMPT override."""
        # Create org policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
        )
        org_policy.save()

        # Create user override
        user_override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.EXEMPT,
        )
        user_override.save()

        policy = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        assert policy.effective_mode == MfaPolicyMode.DISABLED.value
        assert policy.is_exempt is True

    def test_get_effective_user_policy_with_override_required(self, db, test_user, test_organization):
        """Test effective user policy with REQUIRED override."""
        # Create org policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
        )
        org_policy.save()

        # Create user override
        user_override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.REQUIRED,
        )
        user_override.save()

        policy = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        assert policy.effective_mode == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value
        assert policy.requires_totp is True
        assert policy.requires_webauthn is True
        assert policy.is_exempt is False

    def test_evaluate_user_mfa_state_no_policy(self, db, test_user, test_organization):
        """Test evaluating user MFA state with no policy."""
        # Create membership
        membership = OrganizationMember(
            user_id=test_user.id,
            organization_id=test_organization.id,
            role=OrganizationRole.MEMBER,
        )
        membership.save()

        state = MfaPolicyService.evaluate_user_mfa_state(test_user)

        assert state is not None
        assert state.overall_status == MfaComplianceStatus.COMPLIANT.value
        assert len(state.missing_methods) == 0
        assert len(state.orgs) == 1

    def test_evaluate_user_mfa_state_with_policy(self, db, test_user, test_organization):
        """Test evaluating user MFA state with policy."""
        # Create membership
        membership = OrganizationMember(
            user_id=test_user.id,
            organization_id=test_organization.id,
            role=OrganizationRole.MEMBER,
        )
        membership.save()

        # Create org policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
        )
        org_policy.save()

        state = MfaPolicyService.evaluate_user_mfa_state(test_user)

        assert state is not None
        assert state.overall_status == MfaComplianceStatus.IN_GRACE.value
        assert "totp" in state.missing_methods
        assert len(state.orgs) == 1
        assert state.orgs[0].effective_mode == MfaPolicyMode.REQUIRE_TOTP.value

    def test_after_primary_auth_success_no_required_policy(self, db, test_user, test_organization):
        """Test after_primary_auth_success with no required policy."""
        # Create membership
        membership = OrganizationMember(
            user_id=test_user.id,
            organization_id=test_organization.id,
            role=OrganizationRole.MEMBER,
        )
        membership.save()

        result = MfaPolicyService.after_primary_auth_success(test_user)

        assert result.can_create_full_session is True
        assert result.create_compliance_only_session is False
        assert result.compliance_summary.overall_status == MfaComplianceStatus.COMPLIANT.value

    def test_after_primary_auth_success_in_grace(self, db, test_user, test_organization):
        """Test after_primary_auth_success when user is in grace period."""
        # Create membership
        membership = OrganizationMember(
            user_id=test_user.id,
            organization_id=test_organization.id,
            role=OrganizationRole.MEMBER,
        )
        membership.save()

        # Create org policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
        )
        org_policy.save()

        result = MfaPolicyService.after_primary_auth_success(test_user)

        assert result.can_create_full_session is True
        assert result.create_compliance_only_session is False
        assert result.compliance_summary.overall_status == MfaComplianceStatus.IN_GRACE.value

    def test_after_primary_auth_success_past_due(self, db, test_user, test_organization):
        """Test after_primary_auth_success when user is past due."""
        # Create membership
        membership = OrganizationMember(
            user_id=test_user.id,
            organization_id=test_organization.id,
            role=OrganizationRole.MEMBER,
        )
        membership.save()

        # Create org policy
        org_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
        )
        org_policy.save()

        # Create compliance record past due
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.PAST_DUE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=30),
            deadline_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        compliance.save()

        result = MfaPolicyService.after_primary_auth_success(test_user)

        assert result.can_create_full_session is False
        assert result.create_compliance_only_session is True

    def test_create_org_policy_new(self, db, test_organization):
        """Test creating a new organization policy."""
        policy = MfaPolicyService.create_org_policy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            updated_by_user_id=None,
        )

        assert policy is not None
        assert policy.organization_id == test_organization.id
        assert policy.mfa_policy_mode == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN
        assert policy.policy_version == 1

    def test_create_org_policy_update(self, db, test_organization):
        """Test updating an existing organization policy."""
        # Create initial policy
        initial_policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
        )
        initial_policy.save()

        # Update policy
        updated_policy = MfaPolicyService.create_org_policy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=7,
            updated_by_user_id=None,
        )

        assert updated_policy.mfa_policy_mode == MfaPolicyMode.REQUIRE_TOTP
        assert updated_policy.mfa_grace_period_days == 7
        assert updated_policy.policy_version == 2

    def test_set_user_override_new(self, db, test_user, test_organization):
        """Test setting a new user override."""
        override = MfaPolicyService.set_user_override(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.REQUIRED,
            force_totp=True,
            force_webauthn=False,
            updated_by_user_id=None,
        )

        assert override is not None
        assert override.user_id == test_user.id
        assert override.organization_id == test_organization.id
        assert override.mfa_override_mode == MfaRequirementOverride.REQUIRED
        assert override.force_totp is True

    def test_set_user_override_update(self, db, test_user, test_organization):
        """Test updating an existing user override."""
        # Create initial override
        initial_override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.INHERIT,
        )
        initial_override.save()

        # Update override
        updated_override = MfaPolicyService.set_user_override(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.EXEMPT,
            updated_by_user_id=None,
        )

        assert updated_override.mfa_override_mode == MfaRequirementOverride.EXEMPT

    def test_get_user_compliance(self, db, test_user, test_organization):
        """Test getting user compliance record."""
        # Create compliance record
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.COMPLIANT,
            policy_version=1,
        )
        compliance.save()

        result = MfaPolicyService.get_user_compliance(test_user.id, test_organization.id)

        assert result is not None
        assert result.status == MfaComplianceStatus.COMPLIANT

    def test_get_user_compliance_not_found(self, db, test_user, test_organization):
        """Test getting user compliance record when none exists."""
        result = MfaPolicyService.get_user_compliance(test_user.id, test_organization.id)
        assert result is None

    def test_get_org_compliance_list(self, db, test_user, test_organization):
        """Test getting organization compliance list."""
        # Create compliance record
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.IN_GRACE,
            policy_version=1,
            deadline_at=datetime.now(timezone.utc) + timedelta(days=14),
        )
        compliance.save()

        results = MfaPolicyService.get_org_compliance_list(test_organization.id)

        assert len(results) == 1
        assert results[0]["user_id"] == test_user.id
        assert results[0]["status"] == MfaComplianceStatus.IN_GRACE.value

    def test_get_org_compliance_list_with_status_filter(self, db, test_user, test_organization):
        """Test getting organization compliance list with status filter."""
        # Create compliance record
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.COMPLIANT,
            policy_version=1,
        )
        compliance.save()

        # Filter by different status
        results = MfaPolicyService.get_org_compliance_list(
            test_organization.id, status=MfaComplianceStatus.IN_GRACE
        )
        assert len(results) == 0

        # Filter by correct status
        results = MfaPolicyService.get_org_compliance_list(
            test_organization.id, status=MfaComplianceStatus.COMPLIANT
        )
        assert len(results) == 1


@pytest.mark.unit
class TestMfaPolicyServiceDto:
    """Tests for MfaPolicyService DTOs."""

    def test_org_policy_dto(self):
        """Test OrgPolicyDto creation."""
        dto = OrgPolicyDto(
            organization_id="org-123",
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP.value,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )

        assert dto.organization_id == "org-123"
        assert dto.mfa_policy_mode == "require_totp"
        assert dto.mfa_grace_period_days == 14

    def test_effective_user_policy_dto(self):
        """Test EffectiveUserPolicyDto creation."""
        dto = EffectiveUserPolicyDto(
            organization_id="org-123",
            effective_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value,
            requires_totp=True,
            requires_webauthn=True,
            grace_period_days=14,
            is_exempt=False,
        )

        assert dto.requires_totp is True
        assert dto.requires_webauthn is True
        assert dto.is_exempt is False

    def test_aggregate_mfa_state_dto(self):
        """Test AggregateMfaStateDto creation."""
        dto = AggregateMfaStateDto(
            overall_status=MfaComplianceStatus.IN_GRACE.value,
            missing_methods=["totp"],
            deadline_at="2025-02-01T00:00:00Z",
            orgs=[],
        )

        assert dto.overall_status == "in_grace"
        assert "totp" in dto.missing_methods
        assert dto.deadline_at == "2025-02-01T00:00:00Z"

    def test_login_policy_result(self):
        """Test LoginPolicyResult creation."""
        summary = AggregateMfaStateDto(
            overall_status=MfaComplianceStatus.IN_GRACE.value,
            missing_methods=["totp"],
            orgs=[],
        )
        result = LoginPolicyResult(
            can_create_full_session=True,
            create_compliance_only_session=False,
            compliance_summary=summary,
        )

        assert result.can_create_full_session is True
        assert result.create_compliance_only_session is False
        assert result.compliance_summary.overall_status == "in_grace"

"""Integration tests for MFA compliance enforcement."""
import pytest
import json
from datetime import datetime, timezone, timedelta
from gatehouse_app.models.user import User
from gatehouse_app.models.organization import Organization
from gatehouse_app.models.organization_member import OrganizationMember
from gatehouse_app.models.organization_security_policy import OrganizationSecurityPolicy
from gatehouse_app.models.mfa_policy_compliance import MfaPolicyCompliance
from gatehouse_app.models.user_security_policy import UserSecurityPolicy
from gatehouse_app.models.session import Session
from gatehouse_app.utils.constants import MfaPolicyMode, MfaComplianceStatus, UserStatus, MfaRequirementOverride
from gatehouse_app.services.mfa_policy_service import MfaPolicyService


@pytest.mark.integration
class TestMfaComplianceLogin:
    """Integration tests for MFA compliance during login."""

    def test_login_with_no_policy(self, client, db, test_user):
        """Test login with no MFA policy (should work normally)."""
        login_data = {
            "email": test_user.email,
            "password": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]
        assert "token" in data["data"]
        # No MFA compliance info should be present when no policy exists
        assert "mfa_compliance" not in data["data"]
        assert "requires_mfa_enrollment" not in data["data"]

    def test_login_with_optional_policy(self, client, db, test_user, test_organization):
        """Test login with optional MFA policy (should work normally)."""
        # Create an optional MFA policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        login_data = {
            "email": test_user.email,
            "password": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]
        assert "token" in data["data"]
        # MFA compliance should be present but status should be not_applicable
        assert "mfa_compliance" in data["data"]
        assert data["data"]["mfa_compliance"]["overall_status"] == "not_applicable"
        assert "requires_mfa_enrollment" not in data["data"]

    def test_login_with_required_policy_in_grace_period(self, client, db, test_user, test_organization):
        """Test login with required policy within grace period (should work with warning)."""
        # Create a required MFA policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        login_data = {
            "email": test_user.email,
            "password": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]
        assert "token" in data["data"]
        # MFA compliance should be present with in_grace status
        assert "mfa_compliance" in data["data"]
        assert data["data"]["mfa_compliance"]["overall_status"] == "in_grace"
        assert "requires_mfa_enrollment" not in data["data"]
        assert "totp" in data["data"]["mfa_compliance"]["missing_methods"]

    def test_login_with_required_policy_after_deadline(self, client, db, test_user, test_organization):
        """Test login with required policy after deadline (should get compliance-only session)."""
        # Create a required MFA policy with past deadline
        past_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        
        # Create compliance record past due
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.PAST_DUE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=15),
            deadline_at=past_deadline,
        )
        db.session.add(compliance)
        db.session.commit()

        login_data = {
            "email": test_user.email,
            "password": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]
        assert "token" in data["data"]
        # Should have compliance-only session
        assert data["data"]["requires_mfa_enrollment"] is True
        assert "mfa_compliance" in data["data"]
        assert data["data"]["mfa_compliance"]["overall_status"] in ["past_due", "suspended"]

    def test_login_with_suspended_user(self, client, db, test_user, test_organization):
        """Test login with compliance suspended user (should get compliance-only session)."""
        # Set user status to compliance suspended
        test_user.status = UserStatus.COMPLIANCE_SUSPENDED
        db.session.commit()

        login_data = {
            "email": test_user.email,
            "password": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "user" in data["data"]
        assert "token" in data["data"]
        # Should have compliance-only session
        assert data["data"]["requires_mfa_enrollment"] is True


@pytest.mark.integration
class TestMfaComplianceAccess:
    """Integration tests for MFA compliance access control."""

    def test_compliance_only_session_denied_full_access(self, client, db, test_user, test_organization):
        """Test that compliance-only session cannot access full access endpoints."""
        # Create a required MFA policy with past deadline
        past_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        
        # Create compliance record past due
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.PAST_DUE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=15),
            deadline_at=past_deadline,
        )
        db.session.add(compliance)
        
        # Create a compliance-only session
        session = Session(
            user_id=test_user.id,
            token="compliance_only_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_compliance_only=True,
        )
        db.session.add(session)
        db.session.commit()

        # Try to access a full-access endpoint (get_my_organizations)
        response = client.get(
            "/api/v1/users/me/organizations",
            headers={"Authorization": "Bearer compliance_only_token"},
        )

        assert response.status_code == 403
        data = response.get_json()
        assert data["success"] is False
        assert data["error_type"] == "MFA_COMPLIANCE_REQUIRED"

    def test_compliance_only_session_can_access_mfa_enrollment(self, client, db, test_user, test_organization):
        """Test that compliance-only session can access MFA enrollment endpoints."""
        # Create a required MFA policy with past deadline
        past_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        
        # Create compliance record past due
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.PAST_DUE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=15),
            deadline_at=past_deadline,
        )
        db.session.add(compliance)
        
        # Create a compliance-only session
        session = Session(
            user_id=test_user.id,
            token="compliance_only_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_compliance_only=True,
        )
        db.session.add(session)
        db.session.commit()

        # Try to access MFA enrollment endpoint (should work)
        response = client.get(
            "/api/v1/auth/totp/status",
            headers={"Authorization": "Bearer compliance_only_token"},
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

    def test_compliance_only_session_can_access_logout(self, client, db, test_user, test_organization):
        """Test that compliance-only session can access logout endpoint."""
        # Create a required MFA policy with past deadline
        past_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        
        # Create compliance record past due
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.PAST_DUE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=15),
            deadline_at=past_deadline,
        )
        db.session.add(compliance)
        
        # Create a compliance-only session
        session = Session(
            user_id=test_user.id,
            token="compliance_only_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_compliance_only=True,
        )
        db.session.add(session)
        db.session.commit()

        # Try to access logout endpoint (should work)
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer compliance_only_token"},
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True


@pytest.mark.integration
class TestMfaComplianceWebAuthn:
    """Integration tests for MFA compliance with WebAuthn login."""

    def test_webauthn_login_with_required_policy_in_grace_period(self, client, db, test_user, test_organization):
        """Test WebAuthn login with required policy within grace period."""
        # Create a required MFA policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # Note: Full WebAuthn login test would require WebAuthn setup
        # This test verifies the compliance response structure
        login_data = {
            "email": test_user.email,
            "password": "TestPassword123!",
        }

        response = client.post(
            "/api/v1/auth/login",
            data=json.dumps(login_data),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "mfa_compliance" in data["data"]
        assert data["data"]["mfa_compliance"]["overall_status"] == "in_grace"


@pytest.mark.integration
class TestMfaComplianceOIDC:
    """Integration tests for MFA compliance with OIDC authorization."""

    def test_oidc_authorize_with_compliance_required(self, client, db, test_user, test_organization, app):
        """Test OIDC authorize with compliance required (should show error)."""
        # Create a required MFA policy with past deadline
        past_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        
        # Create compliance record past due
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.PAST_DUE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=15),
            deadline_at=past_deadline,
        )
        db.session.add(compliance)
        db.session.commit()

        # Try OIDC authorize with credentials
        response = client.post(
            "/oidc/authorize",
            data={
                "client_id": "test_client",
                "redirect_uri": "http://localhost:8080/callback",
                "response_type": "code",
                "scope": "openid profile email",
                "state": "test_state",
                "email": test_user.email,
                "password": "TestPassword123!",
            },
        )

        # Should return login page with error
        assert response.status_code == 200
        assert b"Your account requires multi factor enrollment before using single sign on" in response.data


# =============================================================================
# Phase 4: Edge Case Tests
# =============================================================================


@pytest.mark.integration
class TestMfaComplianceMultiOrg:
    """Integration tests for multi-organization MFA compliance edge cases."""

    def test_user_with_multiple_orgs_different_policies(self, client, db, test_user):
        """Test user belonging to multiple orgs with different MFA policies."""
        # Create two organizations
        org1 = Organization(
            name="Org1",
            slug="org1-test-multi",
        )
        org2 = Organization(
            name="Org2",
            slug="org2-test-multi",
        )
        db.session.add_all([org1, org2])
        db.session.commit()

        # Add user to both orgs
        membership1 = OrganizationMember(
            user_id=test_user.id,
            organization_id=org1.id,
            role="member",
        )
        membership2 = OrganizationMember(
            user_id=test_user.id,
            organization_id=org2.id,
            role="member",
        )
        db.session.add_all([membership1, membership2])
        db.session.commit()

        # Create different policies for each org
        # Org1: OPTIONAL (no requirement)
        policy1 = OrganizationSecurityPolicy(
            organization_id=org1.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        # Org2: REQUIRE_TOTP (strictest)
        policy2 = OrganizationSecurityPolicy(
            organization_id=org2.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add_all([policy1, policy2])
        db.session.commit()

        # Evaluate user MFA state
        compliance_summary = MfaPolicyService.evaluate_user_mfa_state(test_user)

        # Overall status should reflect the strictest policy (REQUIRE_TOTP from org2)
        assert compliance_summary.overall_status == MfaComplianceStatus.IN_GRACE.value
        assert "totp" in compliance_summary.missing_methods

        # Verify per-org breakdown
        assert len(compliance_summary.orgs) == 2
        org1_status = next((o for o in compliance_summary.orgs if o.organization_id == org1.id), None)
        org2_status = next((o for o in compliance_summary.orgs if o.organization_id == org2.id), None)

        assert org1_status is not None
        assert org2_status is not None
        assert org1_status.status == MfaComplianceStatus.NOT_APPLICABLE.value
        assert org2_status.status == MfaComplianceStatus.IN_GRACE.value

    def test_user_with_multiple_orgs_all_suspended(self, client, db, test_user):
        """Test user with multiple orgs where all require MFA and are past due."""
        # Create two organizations
        org1 = Organization(
            name="Org1",
            slug="org1-test-suspended",
        )
        org2 = Organization(
            name="Org2",
            slug="org2-test-suspended",
        )
        db.session.add_all([org1, org2])
        db.session.commit()

        # Add user to both orgs
        membership1 = OrganizationMember(
            user_id=test_user.id,
            organization_id=org1.id,
            role="member",
        )
        membership2 = OrganizationMember(
            user_id=test_user.id,
            organization_id=org2.id,
            role="member",
        )
        db.session.add_all([membership1, membership2])
        db.session.commit()

        # Create required policies
        policy1 = OrganizationSecurityPolicy(
            organization_id=org1.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        policy2 = OrganizationSecurityPolicy(
            organization_id=org2.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add_all([policy1, policy2])
        db.session.commit()

        # Create past-due compliance records for both
        past_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        compliance1 = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=org1.id,
            status=MfaComplianceStatus.SUSPENDED,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=30),
            deadline_at=past_deadline,
            suspended_at=past_deadline,
        )
        compliance2 = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=org2.id,
            status=MfaComplianceStatus.SUSPENDED,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=30),
            deadline_at=past_deadline,
            suspended_at=past_deadline,
        )
        db.session.add_all([compliance1, compliance2])
        db.session.commit()

        # Evaluate user MFA state
        compliance_summary = MfaPolicyService.evaluate_user_mfa_state(test_user)

        # Overall status should be SUSPENDED
        assert compliance_summary.overall_status == MfaComplianceStatus.SUSPENDED.value

    def test_strictest_mode_selection(self):
        """Test that get_strictest_mode returns the most restrictive policy."""
        modes = [
            MfaPolicyMode.DISABLED.value,
            MfaPolicyMode.OPTIONAL.value,
            MfaPolicyMode.REQUIRE_TOTP.value,
        ]
        result = MfaPolicyService.get_strictest_mode(modes)
        assert result == MfaPolicyMode.REQUIRE_TOTP.value

        # Test with REQUIRE_TOTP_OR_WEBAUTHN (strictest)
        modes_strictest = [
            MfaPolicyMode.REQUIRE_TOTP.value,
            MfaPolicyMode.REQUIRE_WEBAUTHN.value,
            MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value,
        ]
        result = MfaPolicyService.get_strictest_mode(modes_strictest)
        assert result == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value


@pytest.mark.integration
class TestMfaComplianceUserOverrides:
    """Integration tests for user override edge cases."""

    def test_user_override_inherit_mode(self, client, db, test_user, test_organization):
        """Test INHERIT mode - org policy applies as is."""
        # Create a required policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # Create INHERIT override (default behavior)
        override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.INHERIT,
        )
        db.session.add(override)
        db.session.commit()

        # Get effective policy
        effective = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        # Should inherit org policy
        assert effective.effective_mode == MfaPolicyMode.REQUIRE_TOTP.value
        assert effective.requires_totp is True
        assert effective.is_exempt is False

    def test_user_override_required_mode(self, client, db, test_user, test_organization):
        """Test REQUIRED mode - user always required to have MFA."""
        # Create an optional policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # Create REQUIRED override
        override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.REQUIRED,
        )
        db.session.add(override)
        db.session.commit()

        # Get effective policy
        effective = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        # Should be upgraded to REQUIRE_TOTP_OR_WEBAUTHN
        assert effective.effective_mode == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value
        assert effective.requires_totp is True
        assert effective.requires_webauthn is True
        assert effective.is_exempt is False

    def test_user_override_exempt_mode(self, client, db, test_user, test_organization):
        """Test EXEMPT mode - org policy does not apply."""
        # Create a required policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # Create EXEMPT override
        override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.EXEMPT,
        )
        db.session.add(override)
        db.session.commit()

        # Get effective policy
        effective = MfaPolicyService.get_effective_user_policy(test_user.id, test_organization.id)

        # Should be exempt from policy
        assert effective.is_exempt is True
        assert effective.effective_mode == MfaPolicyMode.DISABLED.value
        assert effective.requires_totp is False
        assert effective.requires_webauthn is False

    def test_get_override_summary(self, client, db, test_user, test_organization):
        """Test getting override summary for a user."""
        # No override exists
        summary = MfaPolicyService.get_override_summary(test_user.id, test_organization.id)

        assert summary["has_override"] is False
        assert summary["mode"] == "inherit"

        # Create an override
        override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.EXEMPT,
        )
        db.session.add(override)
        db.session.commit()

        # Get summary again
        summary = MfaPolicyService.get_override_summary(test_user.id, test_organization.id)

        assert summary["has_override"] is True
        assert summary["mode"] == "exempt"
        assert summary["is_exempt"] is True


@pytest.mark.integration
class TestMfaCompliancePolicyChanges:
    """Integration tests for policy changes affecting existing users."""

    def test_policy_change_triggers_compliance_reevaluation(self, client, db, test_user, test_organization):
        """Test that policy change triggers compliance reevaluation."""
        # Create initial optional policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # Create compliance record (should be NOT_APPLICABLE)
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.NOT_APPLICABLE,
            policy_version=1,
        )
        db.session.add(compliance)
        db.session.commit()

        # Update policy to REQUIRE_TOTP
        MfaPolicyService.create_org_policy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
            notify_days_before=7,
            updated_by_user_id=test_user.id,
        )

        # Reevaluate all compliance
        updated_count = MfaPolicyService.reevaluate_all_org_compliance(test_organization.id)

        # Should have updated at least one record
        assert updated_count >= 1

        # Check compliance status was updated
        updated_compliance = MfaPolicyService.get_user_compliance(test_user.id, test_organization.id)
        assert updated_compliance.status == MfaComplianceStatus.IN_GRACE.value
        assert updated_compliance.deadline_at is not None

    def test_policy_relaxation_clears_requirements(self, client, db, test_user, test_organization):
        """Test that relaxing policy clears compliance requirements."""
        # Create required policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # Create IN_GRACE compliance record
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.IN_GRACE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc),
            deadline_at=datetime.now(timezone.utc) + timedelta(days=14),
        )
        db.session.add(compliance)
        db.session.commit()

        # Update policy to OPTIONAL
        MfaPolicyService.create_org_policy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.OPTIONAL,
            mfa_grace_period_days=14,
            notify_days_before=7,
            updated_by_user_id=test_user.id,
        )

        # Reevaluate compliance
        MfaPolicyService.reevaluate_all_org_compliance(test_organization.id)

        # Check compliance status was updated to NOT_APPLICABLE
        updated_compliance = MfaPolicyService.get_user_compliance(test_user.id, test_organization.id)
        assert updated_compliance.status == MfaComplianceStatus.NOT_APPLICABLE.value


@pytest.mark.integration
class TestMfaComplianceScheduledJob:
    """Integration tests for the MFA compliance scheduled job."""

    def test_transition_to_suspended(self, client, db, test_user, test_organization):
        """Test that past-due users are transitioned to suspended."""
        # Create required policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # Create past-due compliance record
        past_deadline = datetime.now(timezone.utc) - timedelta(hours=1)
        compliance = MfaPolicyCompliance(
            user_id=test_user.id,
            organization_id=test_organization.id,
            status=MfaComplianceStatus.PAST_DUE,
            policy_version=1,
            applied_at=datetime.now(timezone.utc) - timedelta(days=15),
            deadline_at=past_deadline,
        )
        db.session.add(compliance)
        db.session.commit()

        # Run the job
        now = datetime.now(timezone.utc)
        suspended_count = MfaPolicyService.transition_to_suspended_if_past_due(now)

        # Should have suspended the user
        assert suspended_count >= 1

        # Check compliance status
        updated_compliance = MfaPolicyService.get_user_compliance(test_user.id, test_organization.id)
        assert updated_compliance.status == MfaComplianceStatus.SUSPENDED.value
        assert updated_compliance.suspended_at is not None

        # Check user status
        db.refresh(test_user)
        assert test_user.status == UserStatus.COMPLIANCE_SUSPENDED

    def test_check_and_restore_user_status(self, client, db, test_user, test_organization):
        """Test that suspended users are restored when they become compliant."""
        # Create required policy
        policy = OrganizationSecurityPolicy(
            organization_id=test_organization.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add(policy)
        db.session.commit()

        # User is suspended
        test_user.status = UserStatus.COMPLIANCE_SUSPENDED
        db.session.commit()

        # Create EXEMPT override to clear requirement
        override = UserSecurityPolicy(
            user_id=test_user.id,
            organization_id=test_organization.id,
            mfa_override_mode=MfaRequirementOverride.EXEMPT,
        )
        db.session.add(override)
        db.session.commit()

        # Check and restore status
        restored = MfaPolicyService.check_and_restore_user_status(test_user.id)

        # Should have restored user
        assert restored is True
        db.refresh(test_user)
        assert test_user.status == UserStatus.ACTIVE


@pytest.mark.integration
class TestMfaComplianceMultiOrgAggregate:
    """Integration tests for multi-org aggregate state calculation."""

    def test_get_multi_org_aggregate_state(self, client, db, test_user):
        """Test aggregate state calculation for multi-org user."""
        # Create two organizations
        org1 = Organization(
            name="AggOrg1",
            slug="agg-org1-test",
        )
        org2 = Organization(
            name="AggOrg2",
            slug="agg-org2-test",
        )
        db.session.add_all([org1, org2])
        db.session.commit()

        # Add user to both
        membership1 = OrganizationMember(
            user_id=test_user.id,
            organization_id=org1.id,
            role="member",
        )
        membership2 = OrganizationMember(
            user_id=test_user.id,
            organization_id=org2.id,
            role="member",
        )
        db.session.add_all([membership1, membership2])
        db.session.commit()

        # Create policies
        policy1 = OrganizationSecurityPolicy(
            organization_id=org1.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_TOTP,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        policy2 = OrganizationSecurityPolicy(
            organization_id=org2.id,
            mfa_policy_mode=MfaPolicyMode.REQUIRE_WEBAUTHN,
            mfa_grace_period_days=14,
            notify_days_before=7,
            policy_version=1,
        )
        db.session.add_all([policy1, policy2])
        db.session.commit()

        # Get aggregate state
        aggregate = MfaPolicyService.get_multi_org_aggregate_state(test_user)

        # Verify structure
        assert "overall_status" in aggregate
        assert "strictest_mode" in aggregate
        assert "missing_methods" in aggregate
        assert "requiring_org_count" in aggregate
        assert "requiring_orgs" in aggregate
        assert "per_org_details" in aggregate

        # Strictest mode should be REQUIRE_TOTP_OR_WEBAUTHN
        assert aggregate["strictest_mode"] == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value

        # Both orgs should require MFA
        assert aggregate["requiring_org_count"] == 2
        assert len(aggregate["requiring_orgs"]) == 2
        assert len(aggregate["per_org_details"]) == 2
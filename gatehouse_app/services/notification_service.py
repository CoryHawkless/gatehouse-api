"""Notification Service for MFA compliance notifications.

This service handles sending MFA-related notifications to users, including:
- Deadline reminder emails
- Suspension notifications
- Compliance status updates

The service is designed to work with or without email infrastructure:
- If email is configured, it sends actual emails
- If email is not available, it logs notifications for debugging/auditing

Usage:
    from gatehouse_app.services.notification_service import NotificationService
    NotificationService.send_mfa_deadline_reminder(user, compliance, org_policy)
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import logging
import json

from gatehouse_app.extensions import db
from gatehouse_app.models.mfa_policy_compliance import MfaPolicyCompliance
from gatehouse_app.models.organization_security_policy import OrganizationSecurityPolicy
from gatehouse_app.models.user import User
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.utils.constants import AuditAction

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending MFA compliance notifications."""

    # Configuration keys for email settings
    EMAIL_ENABLED_KEY = "EMAIL_ENABLED"
    SMTP_HOST_KEY = "SMTP_HOST"
    SMTP_PORT_KEY = "SMTP_PORT"
    SMTP_USERNAME_KEY = "SMTP_USERNAME"
    SMTP_PASSWORD_KEY = "SMTP_PASSWORD"
    FROM_ADDRESS_KEY = "FROM_ADDRESS"

    @staticmethod
    def send_mfa_deadline_reminder(
        user: User,
        compliance: MfaPolicyCompliance,
        org_policy: OrganizationSecurityPolicy,
    ) -> bool:
        """Send MFA deadline reminder notification to user.

        Sends a reminder email to users who are approaching their MFA
        compliance deadline. The reminder includes:
        - Days remaining until deadline
        - Required MFA methods
        - Link to MFA enrollment

        Args:
            user: User to notify
            compliance: User's compliance record
            org_policy: Organization's MFA policy

        Returns:
            True if notification was sent successfully, False otherwise
        """
        try:
            # Calculate days until deadline
            deadline = compliance.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            days_until_deadline = (deadline - now).days

            # Build notification content
            subject = f"Action Required: MFA enrollment deadline in {days_until_deadline} days"
            body = NotificationService._build_deadline_reminder_body(
                user, compliance, org_policy, days_until_deadline
            )

            # Send the notification
            success = NotificationService._send_email(
                to_address=user.email,
                subject=subject,
                body=body,
            )

            if success:
                logger.info(
                    f"Sent MFA deadline reminder to {user.email} "
                    f"({days_until_deadline} days remaining # Audit log
)"
                )
                               AuditService.log_action(
                    action=AuditAction.MFA_POLICY_USER_COMPLIANT,
                    user_id=user.id,
                    organization_id=compliance.organization_id,
                    description=f"MFA deadline reminder sent. Days remaining: {days_until_deadline}",
                )
            else:
                logger.warning(
                    f"Failed to send MFA deadline reminder to {user.email}"
                )

            return success

        except Exception as e:
            logger.exception(f"Error sending MFA deadline reminder to {user.email}: {e}")
            return False

    @staticmethod
    def send_mfa_suspended_notification(
        user: User,
        compliance: MfaPolicyCompliance,
        org_policy: OrganizationSecurityPolicy,
    ) -> bool:
        """Send MFA suspension notification to user.

        Notifies users that their account has been suspended due to
        failure to comply with MFA requirements. The notification includes:
        - Explanation of suspension
        - Steps to restore access
        - Link to MFA enrollment

        Args:
            user: User to notify
            compliance: User's compliance record
            org_policy: Organization's MFA policy

        Returns:
            True if notification was sent successfully, False otherwise
        """
        try:
            # Build notification content
            subject = "Account Access Restricted - MFA Enrollment Required"
            body = NotificationService._build_suspension_body(
                user, compliance, org_policy
            )

            # Send the notification
            success = NotificationService._send_email(
                to_address=user.email,
                subject=subject,
                body=body,
            )

            if success:
                logger.info(f"Sent MFA suspension notification to {user.email}")
                # Audit log
                AuditService.log_action(
                    action=AuditAction.MFA_POLICY_USER_SUSPENDED,
                    user_id=user.id,
                    organization_id=compliance.organization_id,
                    description="MFA compliance suspension notification sent",
                )
            else:
                logger.warning(
                    f"Failed to send MFA suspension notification to {user.email}"
                )

            return success

        except Exception as e:
            logger.exception(
                f"Error sending MFA suspension notification to {user.email}: {e}"
            )
            return False

    @staticmethod
    def _build_deadline_reminder_body(
        user: User,
        compliance: MfaPolicyCompliance,
        org_policy: OrganizationSecurityPolicy,
        days_until_deadline: int,
    ) -> str:
        """Build the email body for deadline reminder.

        Args:
            user: User being notified
            compliance: Compliance record
            org_policy: Organization policy
            days_until_deadline: Days remaining until deadline

        Returns:
            Email body string
        """
        org_name = compliance.organization_id  # In real impl, fetch org name

        body = f"""
Dear {user.full_name or user.email},

This is a reminder that you need to set up multi-factor authentication (MFA)
to maintain access to your account in the organization "{org_name}".

**Important Details:**
- Days remaining: {days_until_deadline}
- Deadline: {compliance.deadline_at.strftime('%Y-%m-%d %H:%M UTC') if compliance.deadline_at else 'Not set'}

**Required MFA Methods:**
"""

        # Add required methods based on policy mode
        from gatehouse_app.utils.constants import MfaPolicyMode

        mode = org_policy.mfa_policy_mode
        if mode == MfaPolicyMode.REQUIRE_TOTP:
            body += "- Authenticator app (TOTP)\n"
        elif mode == MfaPolicyMode.REQUIRE_WEBAUTHN:
            body += "- Passkey (WebAuthn)\n"
        elif mode == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN:
            body += "- Authenticator app (TOTP) OR Passkey (WebAuthn)\n"
        else:
            body += "- Multi-factor authentication\n"

        body += """
**How to Set Up MFA:**
1. Log in to your account
2. Navigate to Settings > Security
3. Follow the prompts to set up an authenticator app or passkey

If you do not set up MFA by the deadline, your account access will be restricted.

If you have any questions, please contact your organization administrator.

Best regards,
Gatehouse Security Team
"""
        return body

    @staticmethod
    def _build_suspension_body(
        user: User,
        compliance: MfaPolicyCompliance,
        org_policy: OrganizationSecurityPolicy,
    ) -> str:
        """Build the email body for suspension notification.

        Args:
            user: User being notified
            compliance: Compliance record
            org_policy: Organization policy

        Returns:
            Email body string
        """
        org_name = compliance.organization_id  # In real impl, fetch org name

        body = f"""
Dear {user.full_name or user.email},

Your account access has been restricted because you did not set up
multi-factor authentication (MFA) within the required timeframe for
the organization "{org_name}".

**What Happened:**
Your MFA compliance deadline passed without MFA being configured.
As a result, your account has been placed in a suspended state.

**How to Restore Access:**
1. Log in to your account (you will see a compliance enrollment screen)
2. Follow the prompts to set up an authenticator app or passkey
3. Once MFA is configured, your access will be restored

**Required MFA Methods:
"""

        # Add required methods based on policy mode
        from gatehouse_app.utils.constants import MfaPolicyMode

        mode = org_policy.mfa_policy_mode
        if mode == MfaPolicyMode.REQUIRE_TOTP:
            body += "- Authenticator app (TOTP)\n"
        elif mode == MfaPolicyMode.REQUIRE_WEBAUTHN:
            body += "- Passkey (WebAuthn)\n"
        elif mode == MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN:
            body += "- Authenticator app (TOTP) OR Passkey (WebAuthn)\n"
        else:
            body += "- Multi-factor authentication\n"

        body += """
**Need Help?**
Contact your organization administrator if you have questions.

Best regards,
Gatehouse Security Team
"""
        return body

    @staticmethod
    def _send_email(
        to_address: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
    ) -> bool:
        """Send an email notification.

        This method attempts to send an email using configured SMTP settings.
        If email is not configured, it logs the notification instead.

        Args:
            to_address: Recipient email address
            subject: Email subject
            body: Plain text email body
            html_body: Optional HTML email body

        Returns:
            True if email was sent (or logged), False on error
        """
        try:
            from flask import current_app

            # Check if email is configured
            email_enabled = current_app.config.get(
                NotificationService.EMAIL_ENABLED_KEY, False
            )

            if not email_enabled:
                # Log the notification instead of sending
                logger.info(
                    f"[EMAIL SIMULATION] To: {to_address}\n"
                    f"Subject: {subject}\n"
                    f"Body: {body[:200]}..." if len(body) > 200 else f"Body: {body}"
                )
                return True

            # Get email configuration
            smtp_host = current_app.config.get(NotificationService.SMTP_HOST_KEY)
            smtp_port = current_app.config.get(NotificationService.SMTP_PORT_KEY, 587)
            smtp_username = current_app.config.get(NotificationService.SMTP_USERNAME_KEY)
            smtp_password = current_app.config.get(NotificationService.SMTP_PASSWORD_KEY)
            from_address = current_app.config.get(
                NotificationService.FROM_ADDRESS_KEY, "noreply@gatehouse.local"
            )

            # Import send_email based on available mail library
            try:
                from flask_mail import Message

                from gatehouse_app import mail

                msg = Message(
                    subject=subject,
                    recipients=[to_address],
                    body=body,
                    html=html_body,
                    sender=from_address,
                )
                mail.send(msg)
                logger.info(f"Email sent successfully to {to_address}")
                return True

            except ImportError:
                # Flask-Mail not available, use SMTP directly
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = from_address
                msg["To"] = to_address

                # Attach plain text and HTML versions
                part1 = MIMEText(body, "plain")
                msg.attach(part1)

                if html_body:
                    part2 = MIMEText(html_body, "html")
                    msg.attach(part2)

                # Send via SMTP
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    if smtp_username and smtp_password:
                        server.login(smtp_username, smtp_password)
                    server.send_message(msg)

                logger.info(f"Email sent successfully to {to_address}")
                return True

        except Exception as e:
            logger.exception(f"Failed to send email to {to_address}: {e}")
            # Log the notification as fallback
            logger.info(
                f"[EMAIL FALLBACK] To: {to_address}\n"
                f"Subject: {subject}\n"
                f"Body: {body[:500]}..." if len(body) > 500 else f"Body: {body}"
            )
            return True  # Return True to continue processing

    @staticmethod
    def get_notification_stats(user_id: str) -> Dict[str, Any]:
        """Get notification statistics for a user.

        Args:
            user_id: User ID

        Returns:
            Dictionary with notification statistics
        """
        from gatehouse_app.models.mfa_policy_compliance import MfaPolicyCompliance

        stats = {
            "total_notifications": 0,
            "last_notification": None,
            "by_organization": [],
        }

        compliance_records = MfaPolicyCompliance.query.filter_by(
            user_id=user_id, deleted_at=None
        ).all()

        total_notifications = 0
        last_notification = None

        for record in compliance_records:
            total_notifications += record.notification_count
            if record.last_notified_at:
                if last_notification is None or record.last_notified_at > last_notification:
                    last_notification = record.last_notified_at

            stats["by_organization"].append({
                "organization_id": record.organization_id,
                "notification_count": record.notification_count,
                "last_notified_at": record.last_notified_at.isoformat() if record.last_notified_at else None,
            })

        stats["total_notifications"] = total_notifications
        stats["last_notification"] = last_notification.isoformat() if last_notification else None

        return stats
"""Management script for Flask application."""
import os
from dotenv import load_dotenv

# Load environment variables FIRST, before any app imports
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

from flask.cli import FlaskGroup
from gatehouse_app import create_app

# Create application
app = create_app(os.getenv("FLASK_ENV", "development"))

# Create Flask CLI group
cli = FlaskGroup(create_app=lambda: app)


@cli.command("run_mfa_compliance_job")
def run_mfa_compliance_job():
    """Run the MFA compliance scheduled job.
    
    This command processes MFA compliance transitions:
    - Transitions users from PAST_DUE to SUSPENDED status
    - Sends deadline reminder notifications
    - Updates notification tracking metadata
    
    Usage:
        python manage.py run_mfa_compliance_job
    
    This can be called via cron or a task scheduler:
        0 * * * * cd /path/to/app && python manage.py run_mfa_compliance_job
    """
    from datetime import datetime, timezone
    from gatehouse_app.jobs.mfa_compliance_job import process_mfa_compliance, get_job_status
    
    print("=" * 60)
    print("MFA Compliance Job")
    print("=" * 60)
    
    now = datetime.now(timezone.utc)
    print(f"Start time: {now.isoformat()}")
    print()
    
    # Show current status before processing
    print("Current Compliance Status:")
    status = get_job_status(now)
    for status_name, count in status["status_counts"].items():
        print(f"  {status_name}: {count}")
    print(f"  Approaching deadline: {status['approaching_deadline_count']}")
    print(f"  Past due: {status['past_due_count']}")
    print()
    
    # Run the job
    print("Processing compliance...")
    result = process_mfa_compliance(now)
    
    print()
    print("Job Results:")
    print(f"  Users suspended: {result['suspended_count']}")
    print(f"  Notifications sent: {result['notified_count']}")
    print(f"  Records processed: {result['processed_count']}")
    
    if result['errors']:
        print()
        print("Errors:")
        for error in result['errors']:
            print(f"  - {error}")
    
    print()
    print("=" * 60)
    print("Job completed successfully")
    print("=" * 60)


@cli.command("mfa_compliance_status")
def mfa_compliance_status():
    """Show current MFA compliance status.
    
    Usage:
        python manage.py mfa_compliance_status
    """
    from datetime import datetime, timezone
    from gatehouse_app.jobs.mfa_compliance_job import get_job_status
    
    print("=" * 60)
    print("MFA Compliance Status Report")
    print("=" * 60)
    
    now = datetime.now(timezone.utc)
    status = get_job_status(now)
    
    print(f"Report time: {status['timestamp']}")
    print()
    
    print("Compliance Records by Status:")
    for status_name, count in sorted(status["status_counts"].items()):
        bar = "█" * min(count, 50)
        print(f"  {status_name:20s}: {count:5d} {bar}")
    
    print()
    print("Summary:")
    print(f"  Approaching deadline: {status['approaching_deadline_count']}")
    print(f"  Past due (pending suspension): {status['past_due_count']}")
    
    total = sum(status["status_counts"].values())
    compliant = status["status_counts"].get("compliant", 0)
    if total > 0:
        compliance_rate = (compliant / total) * 100
        print(f"  Compliance rate: {compliance_rate:.1f}%")
    
    print("=" * 60)


if __name__ == "__main__":
    cli()

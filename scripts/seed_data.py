"""Seed database with comprehensive test data.

This script creates:
- 3 organizations (Acme Corp, Tech Startup, Data Systems Inc)
- 2 admin users
- 8 regular users
- Proper organization memberships with different roles
"""
import sys

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.organization import Organization
from app.models.organization_member import OrganizationMember
from app.models.authentication_method import AuthenticationMethod
from app.services.auth_service import AuthService
from app.services.organization_service import OrganizationService
from app.utils.constants import OrganizationRole, UserStatus, AuthMethodType
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create application
app = create_app()


def user_exists(email):
    """Check if a user with the given email exists."""
    return User.query.filter_by(email=email.lower(), deleted_at=None).first() is not None


def organization_exists(slug):
    """Check if an organization with the given slug exists."""
    return Organization.query.filter_by(slug=slug, deleted_at=None).first() is not None


def create_or_get_user(email, password, full_name):
    """Create a user if they don't exist, or return existing user."""
    existing_user = User.query.filter_by(email=email.lower(), deleted_at=None).first()
    if existing_user:
        print(f"  → User {email} already exists, skipping")
        return existing_user
    
    try:
        user = AuthService.register_user(
            email=email,
            password=password,
            full_name=full_name,
        )
        print(f"  → Created user: {email}")
        return user
    except Exception as e:
        # If email already exists (soft deleted), try to find it
        existing = User.query.filter_by(email=email.lower()).first()
        if existing:
            print(f"  → User {email} exists (soft deleted), skipping")
            return existing
        raise e


def create_or_get_organization(name, slug, owner_user_id, description=None):
    """Create an organization if it doesn't exist, or return existing org."""
    existing_org = Organization.query.filter_by(slug=slug, deleted_at=None).first()
    if existing_org:
        print(f"  → Organization {name} already exists, skipping")
        return existing_org
    
    existing = Organization.query.filter_by(slug=slug).first()
    if existing:
        print(f"  → Organization {slug} exists (soft deleted), skipping")
        return existing
    
    try:
        org = OrganizationService.create_organization(
            name=name,
            slug=slug,
            owner_user_id=owner_user_id,
            description=description,
        )
        print(f"  → Created organization: {name}")
        return org
    except Exception as e:
        print(f"  → Error creating organization {name}: {e}")
        raise e


def add_org_member(org, user_id, role, inviter_id):
    """Add a user to an organization if not already a member."""
    existing = OrganizationMember.query.filter_by(
        user_id=user_id,
        organization_id=org.id,
        deleted_at=None,
    ).first()
    
    if existing:
        print(f"    → User {user_id} is already a member of {org.name}, skipping")
        return existing
    
    try:
        member = OrganizationService.add_member(
            org=org,
            user_id=user_id,
            role=role,
            inviter_id=inviter_id,
        )
        print(f"    → Added user to {org.name} as {role.value}")
        return member
    except Exception as e:
        # ConflictError means already a member
        if "already a member" in str(e).lower():
            print(f"    → User {user_id} is already a member of {org.name}, skipping")
            return
        raise e


def seed_data():
    """Seed the database with test data."""
    print("=" * 60)
    print("Authy2 Database Seed Script")
    print("=" * 60)
    
    with app.app_context():
        # Define test data
        # Organizations
        organizations = [
            {
                "name": "Acme Corporation",
                "slug": "acme-corp",
                "description": "Leading provider of innovative enterprise solutions",
            },
            {
                "name": "Tech Startup Inc",
                "slug": "tech-startup",
                "description": "Disrupting the industry with cutting-edge technology",
            },
            {
                "name": "Data Systems Inc",
                "slug": "data-systems",
                "description": "Enterprise data management and analytics",
            },
        ]
        
        # Admin users (global admins across organizations)
        admin_users = [
            {
                "email": "admin@acme-corp.com",
                "password": "AdminPass123!",
                "full_name": "Alice Administrator",
            },
            {
                "email": "superadmin@acme-corp.com",
                "password": "SuperAdmin123!",
                "full_name": "Sarah SuperAdmin",
            },
        ]
        
        # Regular users for Acme Corp
        acme_users = [
            {
                "email": "bob@acme-corp.com",
                "password": "UserPass123!",
                "full_name": "Bob Builder",
            },
            {
                "email": "carol@acme-corp.com",
                "password": "UserPass123!",
                "full_name": "Carol Developer",
            },
            {
                "email": "david@acme-corp.com",
                "password": "UserPass123!",
                "full_name": "David Designer",
            },
            {
                "email": "eve@acme-corp.com",
                "password": "UserPass123!",
                "full_name": "Eve Engineer",
            },
        ]
        
        # Regular users for Tech Startup
        tech_startup_users = [
            {
                "email": "frank@tech-startup.com",
                "password": "UserPass123!",
                "full_name": "Frank Founder",
            },
            {
                "email": "grace@tech-startup.com",
                "password": "UserPass123!",
                "full_name": "Grace Growth",
            },
            {
                "email": "henry@tech-startup.com",
                "password": "UserPass123!",
                "full_name": "Henry Hacker",
            },
        ]
        
        # Regular users for Data Systems
        data_systems_users = [
            {
                "email": "iris@data-systems.com",
                "password": "UserPass123!",
                "full_name": "Iris Analyst",
            },
            {
                "email": "jack@data-systems.com",
                "password": "UserPass123!",
                "full_name": "Jack Data",
            },
        ]
        
        # Cross-organization users (users in multiple orgs)
        cross_org_users = [
            {
                "email": "charlie@cross-org.com",
                "password": "UserPass123!",
                "full_name": "Charlie Consultant",
            },
        ]
        
        # =========================================================================
        # Step 1: Create Users First (needed for organization owners)
        # =========================================================================
        print("\n[Step 1] Creating Admin Users...")
        admin_objects = {}
        
        for admin_data in admin_users:
            user = create_or_get_user(
                email=admin_data["email"],
                password=admin_data["password"],
                full_name=admin_data["full_name"],
            )
            admin_objects[admin_data["email"]] = user
        
        print(f"\n  Created {len(admin_objects)} admin users")
        
        # =========================================================================
        # Step 2: Create Regular Users
        # =========================================================================
        print("\n[Step 2] Creating Regular Users...")
        all_users = {}
        
        # Acme Corp users
        print("\n  Acme Corporation Users:")
        for user_data in acme_users:
            user = create_or_get_user(
                email=user_data["email"],
                password=user_data["password"],
                full_name=user_data["full_name"],
            )
            all_users[user_data["email"]] = user
        
        # Tech Startup users
        print("\n  Tech Startup Users:")
        for user_data in tech_startup_users:
            user = create_or_get_user(
                email=user_data["email"],
                password=user_data["password"],
                full_name=user_data["full_name"],
            )
            all_users[user_data["email"]] = user
        
        # Data Systems users
        print("\n  Data Systems Users:")
        for user_data in data_systems_users:
            user = create_or_get_user(
                email=user_data["email"],
                password=user_data["password"],
                full_name=user_data["full_name"],
            )
            all_users[user_data["email"]] = user
        
        # Cross-organization user
        print("\n  Cross-Organization User:")
        for user_data in cross_org_users:
            user = create_or_get_user(
                email=user_data["email"],
                password=user_data["password"],
                full_name=user_data["full_name"],
            )
            all_users[user_data["email"]] = user
        
        print(f"\n  Created {len(all_users)} regular users")
        
        # =========================================================================
        # Step 3: Create Organizations (with valid owner_user_id)
        # =========================================================================
        print("\n[Step 3] Creating Organizations...")
        org_objects = {}
        
        # Map organizations to their owners
        org_owner_map = {
            "acme-corp": "admin@acme-corp.com",
            "tech-startup": "superadmin@acme-corp.com",
            "data-systems": "admin@acme-corp.com",
        }
        
        for org_data in organizations:
            owner_email = org_owner_map.get(org_data["slug"])
            owner_user = admin_objects.get(owner_email) if owner_email else None
            owner_user_id = owner_user.id if owner_user else None
            
            org = create_or_get_organization(
                name=org_data["name"],
                slug=org_data["slug"],
                owner_user_id=owner_user_id,
                description=org_data["description"],
            )
            org_objects[org_data["slug"]] = org
        
        print(f"\n  Created {len(org_objects)} organizations")
        
        # =========================================================================
        # Step 4: Add Users to Organizations
        # =========================================================================
        print("\n[Step 4] Adding Users to Organizations...")
        
        # Get organization and user references
        acme_org = org_objects.get("acme-corp")
        tech_org = org_objects.get("tech-startup")
        data_org = org_objects.get("data-systems")
        acme_admin = admin_objects.get("admin@acme-corp.com")
        sarah = admin_objects.get("superadmin@acme-corp.com")
        alice = admin_objects.get("admin@acme-corp.com")
        
        # Add Acme Corp users
        print("\n  Adding to Acme Corporation:")
        for user_email in ["bob@acme-corp.com", "carol@acme-corp.com"]:
            user = all_users.get(user_email)
            if user and acme_admin and acme_org:
                add_org_member(acme_org, user.id, OrganizationRole.MEMBER, acme_admin.id)
        
        # Make Carol an admin
        carol = all_users.get("carol@acme-corp.com")
        if carol and acme_admin and acme_org:
            try:
                OrganizationService.update_member_role(
                    acme_org, carol.id, OrganizationRole.ADMIN, acme_admin.id
                )
                print(f"    → Promoted Carol to ADMIN in Acme Corp")
            except Exception:
                pass  # May already be admin
        
        # Add Tech Startup users
        print("\n  Adding to Tech Startup:")
        for user_email in ["frank@tech-startup.com", "grace@tech-startup.com"]:
            user = all_users.get(user_email)
            if user and sarah and tech_org:
                add_org_member(tech_org, user.id, OrganizationRole.MEMBER, sarah.id)
        
        # Make Frank an admin
        frank = all_users.get("frank@tech-startup.com")
        if frank and sarah and tech_org:
            try:
                OrganizationService.update_member_role(
                    tech_org, frank.id, OrganizationRole.ADMIN, sarah.id
                )
                print(f"    → Promoted Frank to ADMIN in Tech Startup")
            except Exception:
                pass
        
        # Add Data Systems users
        print("\n  Adding to Data Systems:")
        if data_org:
            # Alice is owner of Data Systems too
            if alice:
                add_org_member(data_org, alice.id, OrganizationRole.OWNER, alice.id)
            
            for user_email in ["iris@data-systems.com", "jack@data-systems.com"]:
                user = all_users.get(user_email)
                if user and alice:
                    add_org_member(data_org, user.id, OrganizationRole.MEMBER, alice.id)
        
        # Add cross-organization user to multiple orgs
        print("\n  Adding Cross-Organization User:")
        charlie = all_users.get("charlie@cross-org.com")
        if charlie:
            # Add Charlie to Acme Corp as guest
            if acme_admin and acme_org:
                add_org_member(acme_org, charlie.id, OrganizationRole.GUEST, acme_admin.id)
            
            # Add Charlie to Tech Startup as member
            if sarah and tech_org:
                add_org_member(tech_org, charlie.id, OrganizationRole.MEMBER, sarah.id)
        
        # =========================================================================
        # Summary
        # =========================================================================
        print("\n" + "=" * 60)
        print("Seed Complete!")
        print("=" * 60)
        
        print("\n📊 Summary:")
        print(f"  Organizations: {len(org_objects)}")
        print(f"  Admin Users: {len(admin_objects)}")
        print(f"  Regular Users: {len(all_users)}")
        
        print("\n🔐 Test Credentials:")
        print("\n  Admin Accounts:")
        for email, password in [
            ("admin@acme-corp.com", "AdminPass123!"),
            ("superadmin@acme-corp.com", "SuperAdmin123!"),
        ]:
            print(f"    {email} / {password}")
        
        print("\n  Regular User Accounts (password: UserPass123!):")
        for email in list(all_users.keys())[:5]:
            print(f"    {email}")
        if len(all_users) > 5:
            print(f"    ... and {len(all_users) - 5} more")
        
        print("\n🏢 Organizations:")
        for slug, org in org_objects.items():
            member_count = org.get_member_count()
            owner = org.get_owner()
            owner_email = owner.email if owner else "None"
            print(f"  {org.name} (slug: {slug})")
            print(f"    Members: {member_count}, Owner: {owner_email}")
        
        print("\n" + "=" * 60)


if __name__ == "__main__":
    try:
        seed_data()
        print("\n✅ Database seeded successfully!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error seeding database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

"""Initialize database script."""
from app import create_app
from app.extensions import db
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create application
app = create_app()

with app.app_context():
    # Drop all tables
    print("Dropping all tables...")
    db.drop_all()

    # Create all tables
    print("Creating all tables...")
    db.create_all()

    print("Database initialized successfully!")

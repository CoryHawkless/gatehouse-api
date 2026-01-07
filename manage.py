"""Management script for Flask application."""
import os
from flask.cli import FlaskGroup
from app import create_app
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create application
app = create_app(os.getenv("FLASK_ENV", "development"))

# Create Flask CLI group
cli = FlaskGroup(create_app=lambda: app)

if __name__ == "__main__":
    cli()

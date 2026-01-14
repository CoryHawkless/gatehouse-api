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

if __name__ == "__main__":
    cli()

"""WSGI entry point for the application."""
from dotenv import load_dotenv, find_dotenv

# Load environment variables from .env file FIRST, before any imports
# This must be done before importing app to ensure config has access to env vars
load_dotenv(find_dotenv())

import os
from app import create_app

# Create application instance
app = create_app(os.getenv("FLASK_ENV", "development"))

if __name__ == "__main__":
    app.run()

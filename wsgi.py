"""WSGI entry point for the application."""
from dotenv import load_dotenv, find_dotenv

# Load environment variables from .env file FIRST, before any imports
# This must be done before importing app to ensure config has access to env vars
load_dotenv(find_dotenv())

import os
from gatehouse_app import create_app

# Create application instance
application = create_app(os.getenv("FLASK_ENV", "development"))

# For backwards compatibility
app = application

if __name__ == "__main__":
    app.run()

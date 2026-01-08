"""Flask-Migrate environment configuration."""
import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

# Import the Flask app and db
from app import create_app
from app.extensions import db

# Get the app
app = create_app(os.getenv("FLASK_ENV", "development"))

# Set the Flask application context
with app.app_context():
    from alembic import context
    
    # this is the Alembic Config object, which provides access
    # to the values within the .ini file in use.
    config = context.config

    # Set the SQLAlchemy URL from the app config
    config.set_main_option('sqlalchemy.url', app.config.get('SQLALCHEMY_DATABASE_URI'))

    # Set the target metadata
    target_metadata = db.metadata

    def run_migrations_offline():
        """Run migrations in 'offline' mode.

        This configures the context with just a URL
        and not an Engine, though an Engine is acceptable
        here too.  By skipping the Engine creation
        we don't even need a DBAPI to be available.
        """
        url = config.get_main_option("sqlalchemy.url")
        context.configure(
            url=url,
            target_metadata=target_metadata,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
        )

        with context.begin_transaction():
            context.run_migrations()


    def run_migrations_online():
        """Run migrations in 'online' mode.

        In this scenario we need to create an Engine
        and associate a connection with the context.
        """
        connection = db.engine.connect()
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        try:
            with context.begin_transaction():
                context.run_migrations()
        finally:
            connection.close()

    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()

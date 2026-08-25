"""
ADFIR Platform — Alembic Migration Environment
================================================
Configures the Alembic migration environment for SQLAlchemy 2.x.
Reads database URL from the application configuration so migrations
always use the same connection string as the running app.

Run migrations with:
    alembic upgrade head         # Apply all pending migrations.
    alembic revision --autogenerate -m "description"  # Generate new migration.
    alembic downgrade -1         # Roll back one migration.
"""

import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Ensure the project root is importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env so DATABASE_URL is available.
from dotenv import load_dotenv
load_dotenv()

from backend.config import get_config
from backend.extensions import db

# Import ALL models so Alembic can detect them for autogenerate.
import backend.models  # noqa: F401

# ---------------------------------------------------------------------------
# Alembic configuration object (from alembic.ini)
# ---------------------------------------------------------------------------
config = context.config

# Set up Python logging from the alembic.ini loggers section.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Provide the SQLAlchemy metadata for --autogenerate support.
target_metadata = db.metadata

# Override sqlalchemy.url from the application's config.
cfg = get_config()
config.set_main_option("sqlalchemy.url", cfg.SQLALCHEMY_DATABASE_URI)


# ---------------------------------------------------------------------------
# Migration execution modes
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode (no live DB connection).
    Generates SQL scripts that can be applied manually.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode (requires a live DB connection).
    Used for normal ``alembic upgrade`` commands.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

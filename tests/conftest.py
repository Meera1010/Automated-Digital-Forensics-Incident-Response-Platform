"""
ADFIR Platform — pytest Shared Fixtures
========================================
Provides shared fixtures used across all test modules.
The 'testing' environment config uses a separate test database so tests
never touch the development or production database.

TODO (Phase 1): Expand fixtures as each module is implemented.
"""

import pytest


@pytest.fixture(scope="session")
def app():
    """
    Create a Flask application configured for testing.
    Uses TestingConfig: separate test DB, short JWT expiry, no scheduler.
    """
    from backend.app import create_app
    application = create_app("testing")
    return application


@pytest.fixture(scope="session")
def client(app):
    """Flask test client for making HTTP requests in tests."""
    return app.test_client()


@pytest.fixture(scope="session", autouse=True)
def db_setup(app):
    """Drop and recreate schema once per test session."""
    from backend.extensions import db as _db
    import backend.models  # noqa: F401 – registers all models with metadata
    with app.app_context():
        _db.drop_all()
        _db.create_all()
        # Seed users for tests since create_app tried before tables existed
        from backend.app import _seed_initial_users
        _seed_initial_users(app)
        yield _db
        _db.drop_all()

@pytest.fixture(scope="function")
def db_session(app, db_setup):
    """
    Provide a database session. Cleans up by truncating tables instead of dropping the schema.
    """
    from sqlalchemy import text
    with app.app_context():
        yield db_setup.session
        db_setup.session.remove()
        
        # Clean up all tables in reverse dependency order
        for table in reversed(db_setup.metadata.sorted_tables):
            db_setup.session.execute(table.delete())
        db_setup.session.commit()

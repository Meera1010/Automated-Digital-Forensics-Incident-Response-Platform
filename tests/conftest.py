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


@pytest.fixture(scope="function")
def db_session(app):
    """
    Provide a database session that rolls back after each test function.
    This keeps tests isolated without needing to drop/recreate the schema.
    TODO (Phase 1): Wire up table creation and rollback.
    """
    from backend.extensions import db as _db
    with app.app_context():
        # TODO: Create all tables before the test session.
        # TODO: Roll back the transaction after each test.
        yield _db.session

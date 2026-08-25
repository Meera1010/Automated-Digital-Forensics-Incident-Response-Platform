"""
ADFIR Platform — Flask Application Factory
==========================================
``create_app()`` is the single entry point for constructing a configured
Flask application.  It wires together:

  * Configuration (per-environment)
  * SQLAlchemy database connection
  * JWT authentication
  * CORS headers
  * All API blueprints
  * Background scheduler
  * Error handlers
  * Storage directory bootstrap

Usage:
    from backend.app import create_app
    app = create_app("development")
"""

import os
import logging
from typing import Optional
from flask import Flask, jsonify

from backend.config import get_config
from backend.extensions import db, jwt, cors, scheduler

logger = logging.getLogger(__name__)


def create_app(env: Optional[str] = None) -> Flask:

    """
    Flask application factory.

    Args:
        env: Environment name — 'development', 'testing', or 'production'.
             If omitted, reads from FLASK_ENV environment variable.

    Returns:
        A fully configured Flask application instance.
    """
    app = Flask(
        __name__,
        # Serve the frontend static files from the top-level frontend/ dir.
        static_folder=os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "frontend"
        ),
        static_url_path="",
    )

    # ------------------------------------------------------------------
    # 1. Load configuration
    # ------------------------------------------------------------------
    config_class = get_config(env)
    app.config.from_object(config_class)

    # ------------------------------------------------------------------
    # 2. Configure logging
    # ------------------------------------------------------------------
    _configure_logging(app)

    # ------------------------------------------------------------------
    # 3. Initialise Flask extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(
        app,
        origins=app.config.get("CORS_ORIGINS", ["*"]),
        supports_credentials=True,
    )

    # ------------------------------------------------------------------
    # 4. Register API blueprints
    # ------------------------------------------------------------------
    _register_blueprints(app)

    # ------------------------------------------------------------------
    # 5. Register error handlers
    # ------------------------------------------------------------------
    _register_error_handlers(app)

    # ------------------------------------------------------------------
    # 6. Ensure required storage directories exist
    # ------------------------------------------------------------------
    _bootstrap_storage_dirs(app)

    # ------------------------------------------------------------------
    # 7. Seed initial user accounts if database is empty
    # ------------------------------------------------------------------
    with app.app_context():
        _seed_initial_users(app)

    # ------------------------------------------------------------------
    # 8. Start background scheduler (skip in testing to avoid interference)
    # ------------------------------------------------------------------
    if not app.config.get("TESTING", False) and app.config.get(
        "SCHEDULER_ENABLED", True
    ):
        _start_scheduler(app)

    # ------------------------------------------------------------------
    # 9. Frontend catch-all — serve index.html for any non-API route
    # ------------------------------------------------------------------
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        """Serve the single-page frontend for any non-API route."""
        index_path = os.path.join(app.static_folder, "index.html")
        if os.path.exists(index_path):
            return app.send_static_file("index.html")
        return jsonify({"message": "ADFIR Platform API is running."}), 200

    logger.info(
        "ADFIR application created | env=%s | debug=%s",
        env or os.environ.get("FLASK_ENV", "development"),
        app.config.get("DEBUG"),
    )
    return app



# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _configure_logging(app: Flask) -> None:
    """Set up root-logger level from config."""
    level_name = app.config.get("LOG_LEVEL", "INFO")
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Quieten noisy third-party loggers in production.
    if not app.config.get("DEBUG"):
        logging.getLogger("apscheduler").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def _register_blueprints(app: Flask) -> None:
    """Import and register all API blueprints under the API prefix."""
    prefix = app.config.get("API_PREFIX", "/api/v1")

    from backend.api.auth import auth_bp
    from backend.api.events import events_bp
    from backend.api.incidents import incidents_bp
    from backend.api.evidence import evidence_bp
    from backend.api.rules import rules_bp
    from backend.api.playbooks import playbooks_bp
    from backend.api.reports import reports_bp
    from backend.api.audit import audit_bp
    from backend.api.dashboard import dashboard_bp

    app.register_blueprint(auth_bp, url_prefix=f"{prefix}/auth")
    app.register_blueprint(events_bp, url_prefix=f"{prefix}/events")
    app.register_blueprint(incidents_bp, url_prefix=f"{prefix}/incidents")
    app.register_blueprint(evidence_bp, url_prefix=f"{prefix}/evidence")
    app.register_blueprint(rules_bp, url_prefix=f"{prefix}/rules")
    app.register_blueprint(playbooks_bp, url_prefix=f"{prefix}/playbooks")
    app.register_blueprint(reports_bp, url_prefix=f"{prefix}/reports")
    app.register_blueprint(audit_bp, url_prefix=f"{prefix}/audit")
    app.register_blueprint(dashboard_bp, url_prefix=f"{prefix}/dashboard")

    logger.debug("Registered %d API blueprints under %s", 9, prefix)


def _register_error_handlers(app: Flask) -> None:
    """Attach centralised JSON error responses to common HTTP errors."""
    from backend.utils.error_handlers import register_error_handlers
    register_error_handlers(app)


def _bootstrap_storage_dirs(app: Flask) -> None:
    """Create evidence, report, and lab data directories if they don't exist."""
    paths = [
        app.config.get("EVIDENCE_STORAGE_PATH", "data/evidence"),
        app.config.get("REPORTS_STORAGE_PATH", "data/reports"),
        app.config.get("LAB_DATA_PATH", "data/lab"),
    ]
    for path in paths:
        os.makedirs(path, exist_ok=True)
    logger.debug("Storage directories verified/created: %s", paths)


def _start_scheduler(app: Flask) -> None:
    """Register background jobs and start the APScheduler instance."""
    from backend.scheduler.jobs import register_jobs
    with app.app_context():
        register_jobs(scheduler, app)
    if not scheduler.running:
        scheduler.start()
    logger.info("Background scheduler started.")


def _seed_initial_users(app: Flask) -> None:
    """Seed initial analyst and supervisor user accounts if the users table is empty."""
    try:
        from backend.models.user import User, UserRole
        if User.query.first() is None:
            admin = User(username="admin", role=UserRole.ADMIN)
            admin.set_password("admin123!")

            analyst = User(username="analyst", role=UserRole.ANALYST)
            analyst.set_password("analyst123!")

            supervisor = User(username="supervisor", role=UserRole.SUPERVISOR)
            supervisor.set_password("supervisor123!")

            db.session.add(admin)
            db.session.add(analyst)
            db.session.add(supervisor)
            db.session.commit()
            logger.info("Seeded default users: 'admin', 'analyst', and 'supervisor'.")
    except Exception as exc:
        logger.debug("Skipping user seed (DB tables not yet created): %s", exc)


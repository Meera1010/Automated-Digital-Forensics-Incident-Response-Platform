"""
ADFIR Platform — Background Scheduler Jobs
============================================
Defines and registers all APScheduler background jobs.
Each job is a simple function that runs within a Flask application context.

Jobs registered here:
  1. detection_poll_job   — Process unprocessed RawEvents through detection.
  2. rule_reload_job      — Reload rule YAML files into DB if changed.
  3. stale_incident_job   — Flag incidents stuck in a state too long.
  4. db_health_job        — Quick DB connectivity ping for monitoring.

TODO (Phase 2+): Implement each job function body.
"""

import logging
from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)


def register_jobs(scheduler: BackgroundScheduler, app: Flask) -> None:
    """
    Register all background jobs with the APScheduler instance.
    All jobs run within a Flask application context.

    Args:
        scheduler: The BackgroundScheduler instance from extensions.py.
        app: The Flask application instance (for app context).
    """

    def detection_poll_job():
        """
        Fetch all unprocessed RawEvent rows and run them through the
        detection engine.  Fires every DETECTION_POLL_INTERVAL_SECONDS.
        """
        with app.app_context():
            # TODO: Import and call detection.engine.run_detection_cycle().
            logger.debug("Detection poll job fired.")

    def rule_reload_job():
        """
        Check YAML rule files for updates and upsert changed rules into DB.
        Fires every 60 seconds.
        """
        with app.app_context():
            # TODO: Import and call detection.rule_loader.reload_if_changed().
            logger.debug("Rule reload job fired.")

    def stale_incident_job():
        """
        Find incidents that have been in the same state for > 30 minutes
        and log a warning to the audit trail.  Fires every 5 minutes.
        """
        with app.app_context():
            # TODO: Query incidents by status + updated_at threshold.
            # TODO: Write audit log warning for stale incidents.
            logger.debug("Stale incident check job fired.")

    def db_health_job():
        """
        Execute a trivial DB query to confirm the connection pool is healthy.
        Fires every 60 seconds.
        """
        with app.app_context():
            try:
                from backend.extensions import db
                db.session.execute(db.text("SELECT 1"))
                logger.debug("DB health check: OK")
            except Exception as exc:
                logger.error("DB health check failed: %s", exc)

    # Register jobs with their schedules.
    poll_interval = app.config.get("DETECTION_POLL_INTERVAL_SECONDS", 5)

    scheduler.add_job(
        detection_poll_job,
        trigger="interval",
        seconds=poll_interval,
        id="detection_poll",
        replace_existing=True,
    )
    scheduler.add_job(
        rule_reload_job,
        trigger="interval",
        seconds=60,
        id="rule_reload",
        replace_existing=True,
    )
    scheduler.add_job(
        stale_incident_job,
        trigger="interval",
        seconds=300,
        id="stale_incident_check",
        replace_existing=True,
    )
    scheduler.add_job(
        db_health_job,
        trigger="interval",
        seconds=60,
        id="db_health",
        replace_existing=True,
    )

    logger.info(
        "Registered %d background jobs (detection poll every %ds).",
        4, poll_interval,
    )

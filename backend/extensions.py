"""
ADFIR Platform — Flask Extension Instances
==========================================
All Flask extensions are instantiated here WITHOUT an application object
(using the application-factory pattern).  They are bound to the real app
inside ``create_app()`` via their ``.init_app(app)`` method.

Import from this module whenever you need to use db, jwt, cors, etc.
"""

from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler

# ---------------------------------------------------------------------------
# SQLAlchemy — ORM & database connection pool
# License: MIT
# ---------------------------------------------------------------------------
db = SQLAlchemy()

# ---------------------------------------------------------------------------
# JWTManager — stateless JWT authentication
# License: MIT
# ---------------------------------------------------------------------------
jwt = JWTManager()

# ---------------------------------------------------------------------------
# CORS — cross-origin resource sharing for the frontend
# License: MIT
# ---------------------------------------------------------------------------
cors = CORS()

# ---------------------------------------------------------------------------
# BackgroundScheduler — APScheduler in-process job runner
# Used for: detection poll cycle, stale incident checks, rule reloads.
# License: MIT
# ---------------------------------------------------------------------------
scheduler = BackgroundScheduler(
    job_defaults={
        "coalesce": True,       # Run missed jobs only once when catching up.
        "max_instances": 1,     # Never run the same job concurrently.
    }
)

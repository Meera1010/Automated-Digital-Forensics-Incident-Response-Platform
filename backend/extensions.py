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
# JWTManager — stateless JWT authentication + revocation list
# License: MIT
# ---------------------------------------------------------------------------
jwt = JWTManager()

# In-memory token blocklist for revoked JWT tokens (JTI)
token_blocklist = set()


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    """Return True if the token's JTI is in the revoked blocklist."""
    jti = jwt_payload.get("jti")
    return jti in token_blocklist


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

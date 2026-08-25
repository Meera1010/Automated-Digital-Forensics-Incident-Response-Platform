"""
ADFIR Platform — Development Server Entry Point
================================================
Run the Flask development server with:

    python run.py

Or with a specific environment:

    FLASK_ENV=production python run.py

Do NOT use this script in production.
In production, use a proper WSGI server such as:

    gunicorn "backend.app:create_app()" --workers 4 --bind 0.0.0.0:8000
"""

import os
import sys
import logging

# Ensure the project root is on the Python path so `backend` is importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv

# Load environment variables from .env before creating the Flask app.
# This must happen before any module-level config reads.
load_dotenv()

from backend.app import create_app

# Determine environment from FLASK_ENV (defaults to 'development').
env = os.environ.get("FLASK_ENV", "development")
app = create_app(env)

if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = env == "development"

    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    print(
        f"\n"
        f"  ╔══════════════════════════════════════════════════╗\n"
        f"  ║   ADFIR — Automated Digital Forensics &          ║\n"
        f"  ║            Incident Response Platform            ║\n"
        f"  ╚══════════════════════════════════════════════════╝\n"
        f"\n"
        f"  Environment : {env.upper()}\n"
        f"  Listening   : http://{host}:{port}\n"
        f"  Debug Mode  : {debug}\n"
        f"  Log Level   : {log_level}\n"
    )

    app.run(host=host, port=port, debug=debug)

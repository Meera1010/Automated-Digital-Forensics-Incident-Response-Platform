"""
ADFIR Platform — Events API Blueprint
=======================================
Endpoints:
  POST /api/v1/events/ingest   — Sensor endpoint: receive a synthetic event.
  GET  /api/v1/events          — List recent raw events (paginated).
  GET  /api/v1/events/<id>     — Get a single raw event by ID.

TODO (Phase 2):
  - Implement ingest with Marshmallow validation.
  - Call ingestion.normalizer.normalize_event().
  - Call ingestion.deduplicator.is_duplicate().
  - Persist to raw_events table.
  - Return 202 Accepted (detection is async).
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

events_bp = Blueprint("events", __name__)


@events_bp.post("/ingest")
def ingest_event():
    """
    Receive a single synthetic security event from a sensor or data generator.
    Validates, normalises, deduplicates, and queues for detection.
    Returns 202 Accepted — detection happens asynchronously.
    """
    # TODO: Validate request.json against RawEventIngestSchema (Marshmallow).
    # TODO: Normalise via ingestion.normalizer.
    # TODO: Check deduplication window.
    # TODO: Compute SHA-256 checksum of payload.
    # TODO: Persist RawEvent to DB.
    # TODO: Return 202 with event ID.
    return jsonify({"message": "Not yet implemented"}), 501


@events_bp.get("/")
@jwt_required()
def list_events():
    """
    Return a paginated list of recent raw events.
    Query params: page, per_page, event_type, source_ip, processed
    """
    # TODO: Build SQLAlchemy query with filters.
    # TODO: Paginate and return results.
    return jsonify({"events": [], "total": 0, "page": 1}), 200


@events_bp.get("/<uuid:event_id>")
@jwt_required()
def get_event(event_id):
    """Return a single raw event by its UUID."""
    # TODO: Fetch RawEvent by ID, return 404 if not found.
    return jsonify({"message": "Not yet implemented"}), 501

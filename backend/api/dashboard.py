"""
ADFIR Platform — Dashboard API Blueprint
==========================================
Endpoints:
  GET /api/v1/dashboard/summary  — Counts by status/severity, recent activity.
  GET /api/v1/dashboard/metrics  — Time-series event and incident counts.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/summary")
@jwt_required()
def get_summary():
    """
    Return at-a-glance counts and recent activity for the dashboard header.

    Response includes:
      - incidents_by_status: { NEW: n, INVESTIGATING: n, ... }
      - incidents_by_severity: { P1: n, P2: n, P3: n, P4: n }
      - total_events_today: int
      - total_incidents_open: int
      - recent_incidents: [ Incident.to_dict(), ... ] (last 5)
    """
    # TODO: Run aggregation queries against Incident and RawEvent tables.
    return jsonify({
        "incidents_by_status": {},
        "incidents_by_severity": {},
        "total_events_today": 0,
        "total_incidents_open": 0,
        "recent_incidents": [],
    }), 200


@dashboard_bp.get("/metrics")
@jwt_required()
def get_metrics():
    """
    Return time-series data for the live chart panels.
    Query params: period (1h|24h|7d), default 24h.

    Response includes:
      - events_over_time: [ { timestamp, count } ]
      - incidents_over_time: [ { timestamp, count } ]
      - detections_by_rule: [ { rule_id, rule_name, hit_count } ]
    """
    # TODO: Build time-bucket aggregation queries.
    period = request.args.get("period", "24h")
    return jsonify({
        "period": period,
        "events_over_time": [],
        "incidents_over_time": [],
        "detections_by_rule": [],
    }), 200

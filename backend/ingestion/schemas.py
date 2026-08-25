"""
ADFIR Platform — Ingestion Marshmallow Schemas
================================================
Input validation schemas for the event ingestion API endpoint.

TODO (Phase 2):
  - Define RawEventIngestSchema with all expected fields.
  - Add field-level validators for IPs, timestamps, event_type enum.
"""

from marshmallow import Schema, fields, validate

class RawEventIngestSchema(Schema):
    """Validates the body of POST /api/v1/events/ingest."""
    # TODO: Define required and optional fields.
    # TODO: Add validators for source_ip (valid IP), event_type (known values).
    pass


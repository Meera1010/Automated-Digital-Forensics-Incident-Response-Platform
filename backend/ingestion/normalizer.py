"""
ADFIR Platform — Event Normaliser
====================================
Transforms raw inbound JSON payloads into a canonical RawEvent schema.

TODO (Phase 2):
  - Define canonical field mapping per event_type.
  - Strip unknown fields.
  - Coerce types (timestamps, IPs).
  - Return a dict matching the RawEvent model columns.
"""

def normalize_event(raw_payload: dict) -> dict:
    """
    Normalise an inbound event payload into the canonical RawEvent schema.

    Args:
        raw_payload: Raw JSON dict from the ingest endpoint.

    Returns:
        A normalised dict ready for RawEvent model construction.

    Raises:
        ValueError: If required fields are missing or malformed.
    """
    # TODO: Implement normalisation logic per event_type.
    raise NotImplementedError("normalize_event not yet implemented.")


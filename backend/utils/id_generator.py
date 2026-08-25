"""
ADFIR Platform — Incident Number Generator
============================================
Generates human-readable, sequential incident identifiers in the format:
  INC-YYYY-NNNNN  (e.g. INC-2025-00001)

The counter is derived from the total number of existing incidents plus one,
so there are no gaps and no separate sequence table is required.  If two
incidents are opened within the same database transaction, the application
layer must retry on unique constraint violation.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Fixed prefix for all incident numbers.
INCIDENT_PREFIX = "INC"


def generate_incident_number(existing_count: int) -> str:
    """
    Generate the next incident number based on how many incidents already exist.

    Args:
        existing_count: Total number of Incident rows currently in the database.

    Returns:
        A string like 'INC-2025-00042'.

    Example:
        >>> generate_incident_number(41)
        'INC-2025-00042'
    """
    year = datetime.now(timezone.utc).year
    sequence = existing_count + 1
    return f"{INCIDENT_PREFIX}-{year}-{sequence:05d}"

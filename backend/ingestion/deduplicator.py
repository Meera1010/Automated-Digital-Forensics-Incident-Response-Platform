"""
ADFIR Platform — Event Deduplicator
======================================
Prevents the same event from being stored and evaluated multiple times
within a 5-second sliding window.

TODO (Phase 2):
  - Maintain a sliding window of recent event checksums in memory.
  - Return True if an event with the same checksum was seen recently.
"""

from collections import deque
from datetime import datetime, timezone, timedelta

# In-memory window: deque of (checksum, received_at) tuples.
_recent: deque = deque()
WINDOW_SECONDS: int = 5


def is_duplicate(checksum: str) -> bool:
    """
    Return True if an event with this SHA-256 checksum was received
    within the last WINDOW_SECONDS seconds.

    Args:
        checksum: SHA-256 hex digest of the normalised event payload.

    Returns:
        True if this is a duplicate, False otherwise.
    """
    # TODO: Implement sliding window deduplication.
    raise NotImplementedError("is_duplicate not yet implemented.")


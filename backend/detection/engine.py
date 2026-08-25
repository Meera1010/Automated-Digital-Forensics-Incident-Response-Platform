"""
ADFIR Platform — Detection Engine
====================================
Main evaluation loop.  For each unprocessed RawEvent, runs it through
all enabled detection rules and emits DetectionHit records.

TODO (Phase 2):
  - Load enabled rules from DB.
  - Route each event to applicable evaluators by event_type.
  - Handle DetectionHit creation and correlation hand-off.
"""

import logging
logger = logging.getLogger(__name__)

def run_detection_cycle() -> int:
    """
    Process all RawEvent rows where processed=False.
    Returns the number of events processed.
    TODO: Implement.
    """
    raise NotImplementedError("run_detection_cycle not yet implemented.")


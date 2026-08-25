"""
ADFIR Platform — Incident Correlator
========================================
Determines whether a DetectionHit should open a new incident or be
correlated with an existing open incident.

Correlation criteria:
  - Same source_ip AND same attack_category AND incident opened within
    CORRELATION_WINDOW_SECONDS seconds.

TODO (Phase 3): Implement find_correlatable_incident() and correlate().
"""

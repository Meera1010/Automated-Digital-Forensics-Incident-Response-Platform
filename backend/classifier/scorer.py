"""
ADFIR Platform — Severity Scorer
=====================================
Computes weighted severity scores from an InvestigationSummary.

Weights:
  asset_criticality  × 0.30
  attack_confidence  × 0.25
  rule_severity      × 0.20
  event_volume       × 0.15
  time_risk          × 0.10

TODO (Phase 3): Implement score(summary) -> SeverityAssessment
"""

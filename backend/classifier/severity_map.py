"""
ADFIR Platform — Severity Tier Mapping
========================================
Maps composite scores to P1–P4 severity tiers.

Thresholds:
  P1 (Critical): score >= 8.0
  P2 (High):     score >= 6.0
  P3 (Medium):   score >= 3.5
  P4 (Low):      score < 3.5
"""

SEVERITY_THRESHOLDS = [
    (8.0, "P1"),
    (6.0, "P2"),
    (3.5, "P3"),
    (0.0, "P4"),
]

def score_to_severity(score: float) -> str:
    """Map a composite score to a severity tier string."""
    for threshold, tier in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return tier
    return "P4"


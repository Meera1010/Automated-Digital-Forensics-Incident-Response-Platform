"""
ADFIR Platform — Rule State Cache
====================================
In-memory state storage for stateful detection rules.

- Threshold rules: sliding deque of (timestamp, group_key) per rule.
- Sequence rules: partial match state per (rule_id, source_ip) with TTL.
- Cache is intentionally not persisted across restarts.

TODO (Phase 2): Implement cache classes.
"""

from collections import defaultdict, deque

class ThresholdCache:
    """Maintains a sliding window of event timestamps per (rule_id, group_key)."""
    # TODO: Implement.
    pass

class SequenceCache:
    """Tracks partial sequence matches with TTL expiry."""
    # TODO: Implement.
    pass


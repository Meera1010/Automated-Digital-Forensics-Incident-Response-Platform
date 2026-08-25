"""
Allowlist exclusion evaluator.
Fires for any matching event whose source_ip is NOT in the configured allowlist.
TODO (Phase 2): Implement evaluate(rule, event) -> DetectionHit | None
"""

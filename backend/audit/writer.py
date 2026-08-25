"""
ADFIR Platform — Audit Writer
================================
Single interface for writing audit log entries from any module.
Maintains the chained SHA-256 checksum on every write.

Usage:
    from backend.audit.writer import write_audit
    write_audit(
        module="orchestrator.state_machine",
        action="incident.state_transition",
        target_type="incident",
        target_id=incident.id,
        detail={"from": "NEW", "to": "INVESTIGATING"},
    )

TODO (Phase 1): Implement write_audit() with chained checksum computation.
"""

import logging
logger = logging.getLogger(__name__)

SENTINEL_CHECKSUM = "0" * 64  # SHA-256 of empty string for the first row.

def write_audit(
    module: str,
    action: str,
    target_type: str = None,
    target_id = None,
    detail: dict = None,
    actor_type: str = "system",
    actor_id: str = "system",
) -> None:
    """
    Append an entry to the audit log with chained integrity checksum.

    Args:
        module: Name of the module writing the entry (e.g. "orchestrator").
        action: Short verb describing the action (e.g. "incident.created").
        target_type: Entity type affected (e.g. "incident").
        target_id: UUID of the affected entity.
        detail: Additional structured context dict.
        actor_type: "system" or "user".
        actor_id: Module name or user UUID.

    TODO: Implement using AuditLog model + chained checksum.
    """
    logger.debug(
        "AUDIT [%s] %s.%s target=%s/%s",
        actor_id, module, action, target_type, target_id
    )
    # TODO: Implement chained checksum write to AuditLog table.


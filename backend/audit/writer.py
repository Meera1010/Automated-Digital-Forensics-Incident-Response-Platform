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

import hashlib
import json
import logging
from typing import Optional, Union
from uuid import UUID

from backend.extensions import db
from backend.models.audit_log import AuditLog
from backend.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

SENTINEL_CHECKSUM = "0" * 64  # SHA-256 of empty string for the first row.


def compute_row_checksum(
    prev_checksum: str,
    logged_at_iso: str,
    actor_type: str,
    actor_id: str,
    module: str,
    action: str,
    target_type: Optional[str],
    target_id_str: Optional[str],
    detail_str: str,
) -> str:
    """Compute the SHA-256 digest for a single audit log entry."""
    canonical = (
        f"{prev_checksum}|{logged_at_iso}|{actor_type}|{actor_id}|"
        f"{module}|{action}|{target_type or ''}|{target_id_str or ''}|{detail_str}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_audit(
    module: str,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[Union[UUID, str]] = None,
    detail: Optional[dict] = None,
    actor_type: str = "system",
    actor_id: str = "system",
) -> AuditLog:

    """
    Append an entry to the audit log with chained integrity checksum.

    Args:
        module: Name of the module writing the entry (e.g. "orchestrator").
        action: Short verb describing the action (e.g. "incident.created").
        target_type: Entity type affected (e.g. "incident").
        target_id: UUID or ID string of the affected entity.
        detail: Additional structured context dict.
        actor_type: "system" or "user".
        actor_id: Module name or user UUID string.

    Returns:
        The created AuditLog instance.
    """
    now = utc_now()
    detail = detail or {}
    detail_str = json.dumps(detail, sort_keys=True)
    target_id_str = str(target_id) if target_id else None

    # Fetch the checksum of the last row inserted into the audit log
    last_row = (
        db.session.query(AuditLog.row_checksum)
        .order_by(AuditLog.id.desc())
        .first()
    )

    prev_checksum = last_row.row_checksum if last_row else SENTINEL_CHECKSUM
    row_checksum = compute_row_checksum(
        prev_checksum=prev_checksum,
        logged_at_iso=now.isoformat(),
        actor_type=actor_type,
        actor_id=actor_id,
        module=module,
        action=action,
        target_type=target_type,
        target_id_str=target_id_str,
        detail_str=detail_str,
    )

    entry = AuditLog(
        logged_at=now,
        actor_type=actor_type,
        actor_id=actor_id,
        module=module,
        action=action,
        target_type=target_type,
        target_id=target_id_str if target_id_str else None,
        detail_json=detail,
        prev_checksum=prev_checksum,
        row_checksum=row_checksum,
    )

    db.session.add(entry)
    db.session.commit()

    logger.debug(
        "AUDIT [#%s] [%s] %s.%s target=%s/%s checksum=%s...",
        entry.id, actor_id, module, action, target_type, target_id_str, row_checksum[:8]
    )

    return entry



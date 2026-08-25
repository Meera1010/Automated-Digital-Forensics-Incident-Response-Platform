"""
Unit tests for the Audit Log module:
  - Writing audit log entries with chained SHA-256 checksums
  - Verifying chain integrity across multiple entries
"""

import pytest
from backend.audit.writer import write_audit, SENTINEL_CHECKSUM
from backend.models.audit_log import AuditLog


def test_write_audit_entry(app):
    """Test writing a single audit entry creates a row with chained checksum."""
    with app.app_context():
        entry = write_audit(
            module="test_module",
            action="test.action",
            target_type="test_entity",
            detail={"key": "value"},
            actor_id="test_user",
        )

        assert entry.id is not None
        assert entry.module == "test_module"
        assert entry.action == "test.action"
        assert len(entry.row_checksum) == 64


def test_audit_chain_sequential_checksums(app):
    """Test that consecutive audit entries properly chain their prev_checksum values."""
    with app.app_context():
        entry1 = write_audit(
            module="test_module",
            action="action_1",
            actor_id="user_1",
        )
        entry2 = write_audit(
            module="test_module",
            action="action_2",
            actor_id="user_2",
        )

        assert entry2.prev_checksum == entry1.row_checksum


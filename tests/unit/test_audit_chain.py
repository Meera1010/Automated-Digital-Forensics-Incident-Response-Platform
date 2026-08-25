"""
Unit tests for the Audit Log module:
  - Writing audit log entries with chained SHA-256 checksums
  - Verifying chain integrity across multiple entries
"""

import pytest
from backend.audit.writer import write_audit, SENTINEL_CHECKSUM
from backend.models.audit_log import AuditLog


def test_write_audit_entry(app, db_session):
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


def test_audit_chain_sequential_checksums(app, db_session):
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

def test_audit_immutability(app, db_session):
    """Test that audit log entries cannot be modified or deleted."""
    from backend.extensions import db
    from backend.audit.writer import write_audit
    with app.app_context():
        entry = write_audit(
            module="test_module",
            action="test.action",
            actor_id="test_user"
        )
        
        # Test modification
        entry.action = "modified.action"
        try:
            db.session.commit()
            assert False, "Should have raised an exception on update"
        except Exception as e:
            db.session.rollback()
            assert "cannot be updated" in str(e)
            
        # Test deletion
        db.session.delete(entry)
        try:
            db.session.commit()
            assert False, "Should have raised an exception on delete"
        except Exception as e:
            db.session.rollback()
            assert "cannot be deleted" in str(e)

"""
ADFIR Platform — RawEvent Model
=================================
Stores every normalised security event received by the ingestion layer.
Each row represents one atomic event (auth failure, port scan probe, etc.)
from a synthetic sensor or the data generator tool.

The SHA-256 checksum column ensures the stored payload was not tampered
with after ingestion.
"""

from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Text,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from backend.extensions import db
from backend.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class RawEvent(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    """
    A single, normalised security event from a synthetic sensor.
    """

    __tablename__ = "raw_events"

    # When the event was received by the ingestion endpoint (server-side UTC).
    received_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Sensor or generator tag that produced this event (e.g. 'SYN-NET-01').
    source_tag = Column(String(64), nullable=False, index=True)

    # Canonical event category (e.g. 'auth_failure', 'port_scan', 'dns_query').
    event_type = Column(String(64), nullable=False, index=True)

    # Source and destination synthetic IP addresses.
    source_ip = Column(String(45), nullable=True, index=True)
    dest_ip = Column(String(45), nullable=True)

    # Synthetic username involved in the event (may be null).
    username = Column(String(128), nullable=True)

    # FK-style reference to synthetic_assets.id (soft reference — no DB FK
    # to avoid cascading complexity on lab state changes).
    asset_id = Column(String(64), nullable=True, index=True)

    # Full normalised event payload as JSONB for flexible querying.
    payload_json = Column(JSONB, nullable=False, default=dict)

    # SHA-256 hex digest of the serialised payload_json.
    # Computed by the ingestion normaliser before INSERT.
    checksum = Column(String(64), nullable=False)

    # Set to True once the detection engine has evaluated this event.
    processed = Column(Boolean, nullable=False, default=False, index=True)

    # Relationships
    detection_hits = relationship(
        "DetectionHit", back_populates="raw_event", lazy="dynamic"
    )

    # Compound index for the most common detection query:
    # "unprocessed events of a given type from a given source".
    __table_args__ = (
        Index("ix_raw_events_unprocessed_type", "processed", "event_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<RawEvent {self.id!s:.8} type={self.event_type!r} "
            f"src={self.source_ip!r}>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "received_at": self.received_at.isoformat(),
            "source_tag": self.source_tag,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "username": self.username,
            "asset_id": self.asset_id,
            "payload_json": self.payload_json,
            "checksum": self.checksum,
            "processed": self.processed,
        }

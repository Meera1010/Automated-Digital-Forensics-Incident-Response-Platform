"""
ADFIR Platform — SyntheticAsset Model
=======================================
Represents a simulated network asset (workstation, server, device) in the
controlled lab environment.  Response actions operate on these records
rather than on real infrastructure.

Criticality scale: 1 (low) → 5 (mission-critical).
Status transitions: active ↔ quarantined, active → offline.
"""

import enum
from sqlalchemy import Column, String, SmallInteger, Enum as SaEnum
from sqlalchemy.dialects.postgresql import JSON

from backend.extensions import db
from backend.models.base import TimestampMixin


class AssetType(enum.Enum):
    WORKSTATION = "workstation"
    SERVER = "server"
    NETWORK_DEVICE = "network_device"
    DATABASE_SERVER = "database_server"
    WEB_SERVER = "web_server"


class AssetStatus(enum.Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    OFFLINE = "offline"


class SyntheticAsset(TimestampMixin, db.Model):
    """
    A synthetic (simulated) asset in the lab network.
    The primary key is a human-readable string like 'ASSET-WS-001'.
    """

    __tablename__ = "synthetic_assets"

    # Human-readable identifier, e.g. "ASSET-WS-001".
    id = Column(String(64), primary_key=True, nullable=False)

    # Friendly display name.
    name = Column(String(128), nullable=False)

    # Category of asset.
    asset_type = Column(
        SaEnum(AssetType, name="asset_type_enum"),
        nullable=False,
        default=AssetType.WORKSTATION,
    )

    # Business criticality: 1 = low risk, 5 = mission-critical.
    criticality = Column(SmallInteger, nullable=False, default=1)

    # Synthetic (non-routable) IP address for the lab.
    ip_address = Column(String(45), nullable=False, index=True)

    # Organisational context.
    department = Column(String(64), nullable=True)

    # Flexible key/value metadata (OS version, installed services, etc.).
    tags = Column(JSON, nullable=True, default=dict)

    # Current operational status — updated by response actions.
    status = Column(
        SaEnum(AssetStatus, name="asset_status_enum"),
        nullable=False,
        default=AssetStatus.ACTIVE,
    )

    def __repr__(self) -> str:
        return f"<SyntheticAsset {self.id!r} {self.asset_type.value}>"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "asset_type": self.asset_type.value,
            "criticality": self.criticality,
            "ip_address": self.ip_address,
            "department": self.department,
            "tags": self.tags or {},
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

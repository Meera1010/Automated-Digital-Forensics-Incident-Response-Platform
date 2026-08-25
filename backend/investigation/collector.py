"""
ADFIR Platform — Evidence Collector
=======================================
Collects all raw events, related asset info, and context for an incident.
Passes each artifact to the Evidence Vault for storage.

This module implements the Evidence Collection Module as requested.
"""

import json
from abc import ABC, abstractmethod
from typing import List, Optional
import uuid

from backend.vault import vault_manager
from backend.models.evidence_artifact import EvidenceArtifact
from tools.data_generator.generator import generate_event
from datetime import datetime, timezone


class BaseEvidenceSource(ABC):
    """Abstract base class for evidence collection sources."""
    
    @abstractmethod
    def collect(self, incident_id: str) -> List[EvidenceArtifact]:
        """Collect evidence and store it via the vault manager."""
        pass


class SyntheticEventSource(BaseEvidenceSource):
    """
    Evidence source that generates synthetic cybersecurity events
    and stores them as a JSON evidence artifact.
    """
    
    def __init__(self, event_count: int = 10, suspicious_freq: float = 0.1):
        self.event_count = event_count
        self.suspicious_freq = suspicious_freq

    def collect(self, incident_id: str) -> List[EvidenceArtifact]:
        import random
        events = []
        now = datetime.now(timezone.utc)
        
        event_types = [
            "auth_success",
            "auth_failure",
            "process_start",
            "file_create",
            "file_delete",
            "network_connection",
            "security_alert",
        ]
        
        for _ in range(self.event_count):
            is_suspicious = random.random() < self.suspicious_freq
            ev_type = random.choice(event_types)
            event = generate_event(is_suspicious, ev_type, now)
            events.append(event)
            
        # Serialize to bytes
        artifact_bytes = json.dumps(events, indent=2).encode('utf-8')
        
        # Store in vault
        metadata = {
            "event_count": self.event_count,
            "suspicious_frequency": self.suspicious_freq,
            "is_synthetic": True,
            "generated_at": now.isoformat()
        }
        
        artifact = vault_manager.store(
            artifact_bytes=artifact_bytes,
            artifact_type="synthetic_events_dump",
            incident_id=incident_id,
            filename="synthetic_events.json",
            source="SyntheticEventSource",
            metadata=metadata
        )
        
        return [artifact]


class EvidenceCollector:
    """Orchestrator for evidence collection from multiple sources."""
    
    def __init__(self, sources: Optional[List[BaseEvidenceSource]] = None):
        self.sources = sources or []
        
    def add_source(self, source: BaseEvidenceSource):
        self.sources.append(source)
        
    def collect_all(self, incident_id: str) -> List[EvidenceArtifact]:
        """Iterate over all sources and collect evidence."""
        collected_artifacts = []
        for source in self.sources:
            artifacts = source.collect(incident_id)
            collected_artifacts.extend(artifacts)
        return collected_artifacts

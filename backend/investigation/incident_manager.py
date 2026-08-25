"""
ADFIR Platform — Incident Manager
===================================
Automates the creation and progression of incidents from detection alerts.
"""

from datetime import datetime, timezone
import uuid

from backend.extensions import db
from backend.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.models.investigation_record import InvestigationRecord
from backend.models.detection_hit import DetectionHit
from backend.models.raw_event import RawEvent
from backend.models.evidence_artifact import EvidenceArtifact
from backend.investigation.automated_investigator import AutomatedInvestigator


class IncidentManager:
    """
    Orchestrates the lifecycle of Incidents.
    """

    def __init__(self):
        pass

    def create_incident_from_hit(self, hit: DetectionHit) -> Incident:
        """
        Creates a new incident from a detection hit.
        
        1. Create an incident automatically.
        2. Generate a unique Incident ID.
        3. Assign severity.
        4. Assign incident category.
        5. Link related evidence.
        6. Link triggered rules.
        7. Record timestamps.
        8. Set incident status.
        9. Create an investigation record.
        """
        now = datetime.now(timezone.utc)
        
        # 2. Generate a unique Incident ID
        date_str = now.strftime("%Y%m%d")
        unique_suffix = str(uuid.uuid4())[:8].upper()
        incident_number = f"INC-{date_str}-{unique_suffix}"
        
        # 3. Assign severity
        rule_severity = hit.match_detail_json.get("severity", 5)
        severity = self._map_severity(rule_severity)
        
        # 4. Assign incident category
        rule_id_str = hit.match_detail_json.get("rule_id_str", "UNKNOWN")
        category = self._map_category(rule_id_str)
        
        # 1. Create an incident automatically
        incident = Incident(
            incident_number=incident_number,
            title=f"Automated Detection: {rule_id_str}",
            status=IncidentStatus.NEW.value,
            severity=severity,
            attack_category=category,
            opened_at=now,
            summary_text=f"Incident generated automatically from rule {rule_id_str}."
        )
        
        db.session.add(incident)
        db.session.flush() # flush to get incident.id
        
        # 6. Link triggered rules
        hit.correlated_incident_id = incident.id
        db.session.add(hit)
        
        # 5. Link related evidence
        # Find if the raw event was saved as evidence
        evidence = db.session.query(EvidenceArtifact).filter_by(
            sha256_hash=hit.raw_event.checksum
        ).first()
        
        if evidence:
            evidence.incident_id = incident.id
            db.session.add(evidence)
            
        # 9. Create an investigation record
        investigation = InvestigationRecord(
            incident_id=incident.id,
            findings=f"Investigation automatically started for {incident_number}.",
            status="NEW"
        )
        db.session.add(investigation)
        
        db.session.flush() # ensure investigation has an id
        
        from backend.audit.writer import write_audit
        write_audit(
            module="incident_manager",
            action="incident.created",
            target_type="Incident",
            target_id=incident.id,
            detail={"incident_number": incident.incident_number, "rule_id_str": rule_id_str},
            actor_id="system_incident_manager"
        )
        
        db.session.commit()
        
        # 10. Run Automated Investigation
        investigator = AutomatedInvestigator()
        investigator.investigate(incident)
        
        return incident

    def _map_severity(self, rule_severity: int) -> str:
        if rule_severity >= 9:
            return IncidentSeverity.P1.value
        elif rule_severity >= 7:
            return IncidentSeverity.P2.value
        elif rule_severity >= 4:
            return IncidentSeverity.P3.value
        else:
            return IncidentSeverity.P4.value

    def _map_category(self, rule_id_str: str) -> str:
        if rule_id_str.startswith("AUTH"):
            return "Credential Access"
        elif rule_id_str.startswith("PROC"):
            return "Execution"
        elif rule_id_str.startswith("NET"):
            return "Command and Control"
        elif rule_id_str.startswith("INT"):
            return "Defense Evasion"
        elif rule_id_str.startswith("FREQ"):
            return "Impact"
        elif rule_id_str.startswith("FILE"):
            return "Discovery"
        return "Unknown"

    def update_incident_status(self, incident: Incident, status: str):
        """Update incident status and timestamps."""
        incident.status = status
        
        if status == IncidentStatus.INVESTIGATING.value:
            incident.classified_at = datetime.now(timezone.utc)
        elif status == IncidentStatus.CONTAINED.value:
            incident.contained_at = datetime.now(timezone.utc)
        elif status in [IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value]:
            incident.closed_at = datetime.now(timezone.utc)
        
        db.session.add(incident)
        db.session.commit()

        if status == IncidentStatus.RESOLVED.value:
            try:
                from backend.reporting.generator import generate_report
                generate_report(incident_id=incident.id, format_type="html")
                generate_report(incident_id=incident.id, format_type="json")
                generate_report(incident_id=incident.id, format_type="pdf")
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to auto-generate reports for {incident.id}: {e}")


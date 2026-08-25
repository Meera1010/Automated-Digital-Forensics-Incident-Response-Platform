"""
ADFIR Platform — Automated Investigator
=========================================
Performs automated investigation tasks upon incident creation.
1. Finds related events and evidence.
2. Verifies evidence hashes.
3. Builds an incident timeline.
4. Identifies triggered detection rules and indicators.
5. Calculates severity.
6. Generates a deterministic investigation summary.
"""

from typing import List, Dict, Any, Set
from datetime import datetime, timezone
import json

from backend.extensions import db
from backend.models.incident import Incident, IncidentSeverity
from backend.models.raw_event import RawEvent
from backend.models.detection_hit import DetectionHit
from backend.models.evidence_artifact import EvidenceArtifact
from backend.models.investigation_record import InvestigationRecord
from backend.vault.vault_manager import verify_evidence
from backend.utils.error_handlers import EvidenceTamperedException, ResourceNotFoundError


class AutomatedInvestigator:
    """
    Runs automated triage and investigation on newly created Incidents.
    """

    def investigate(self, incident: Incident) -> None:
        """
        Execute the deterministic investigation logic for the incident.
        Updates the incident severity and creates/updates an InvestigationRecord.
        """
        # 1. Find related events (via DetectionHits)
        hits: List[DetectionHit] = incident.detection_hits.all()
        
        events: List[RawEvent] = []
        rule_ids: Set[str] = set()
        max_rule_severity = 0
        
        for hit in hits:
            # 6. Identify triggered detection rules
            rule_id_str = hit.match_detail_json.get("rule_id_str")
            if rule_id_str:
                rule_ids.add(rule_id_str)
                
            # 7. Calculate incident severity
            rule_sev = hit.match_detail_json.get("severity", 0)
            if rule_sev > max_rule_severity:
                max_rule_severity = rule_sev
                
            if hit.raw_event:
                events.append(hit.raw_event)
                
        # Upgrade severity if max rule severity is high enough
        computed_severity = self._map_severity(max_rule_severity)
        # Assuming P1 is highest, P4 is lowest
        severity_rank = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
        current_sev_rank = severity_rank.get(incident.severity, 0)
        computed_sev_rank = severity_rank.get(computed_severity, 0)
        
        if computed_sev_rank > current_sev_rank:
            incident.severity = computed_severity
            
        # 4. Sort events chronologically
        events.sort(key=lambda e: e.received_at)
        
        # 8. Identify relevant indicators
        indicators = {
            "source_ips": set(),
            "dest_ips": set(),
            "usernames": set()
        }
        
        timeline_entries = []
        for e in events:
            if e.source_ip:
                indicators["source_ips"].add(e.source_ip)
            if e.dest_ip:
                indicators["dest_ips"].add(e.dest_ip)
            if e.username:
                indicators["usernames"].add(e.username)
                
            # 5. Build an incident timeline
            timestamp_str = e.received_at.isoformat()
            timeline_entries.append(f"[{timestamp_str}] {e.source_tag} - {e.event_type} - Src: {e.source_ip or 'N/A'}")

        # 2. Find related evidence & 3. Verify evidence hashes
        evidence_list: List[EvidenceArtifact] = incident.evidence_artifacts.all()
        verification_results = []
        
        for evidence in evidence_list:
            try:
                is_valid = verify_evidence(str(evidence.id))
                status = "VALID" if is_valid else "INVALID (Tampered)"
            except EvidenceTamperedException:
                status = "INVALID (Tampered)"
            except Exception as ex:
                status = f"ERROR ({str(ex)})"
            
            verification_results.append(f"Artifact {evidence.original_filename}: {status}")

        # 9. Generate an investigation summary
        summary_lines = [
            f"Automated Investigation Summary for {incident.incident_number}",
            "===========================================================",
            f"Triggered Rules: {', '.join(sorted(rule_ids)) if rule_ids else 'None'}",
            f"Computed Severity: {computed_severity}",
            "",
            "Indicators of Compromise:",
            f"- Source IPs: {', '.join(sorted(indicators['source_ips'])) if indicators['source_ips'] else 'None'}",
            f"- Dest IPs: {', '.join(sorted(indicators['dest_ips'])) if indicators['dest_ips'] else 'None'}",
            f"- Usernames: {', '.join(sorted(indicators['usernames'])) if indicators['usernames'] else 'None'}",
            "",
            "Evidence Integrity:",
        ]
        
        if verification_results:
            summary_lines.extend(f"- {res}" for res in verification_results)
        else:
            summary_lines.append("- No evidence artifacts linked.")
            
        summary_lines.append("")
        summary_lines.append("Chronological Timeline:")
        if timeline_entries:
            summary_lines.extend(f"- {entry}" for entry in timeline_entries)
        else:
            summary_lines.append("- No raw events found.")
            
        final_summary = "\n".join(summary_lines)
        
        # Save findings to InvestigationRecord
        # Get or create InvestigationRecord
        record = incident.investigation_records[0] if incident.investigation_records else None
        
        if not record:
            record = InvestigationRecord(
                incident_id=incident.id,
                findings=final_summary,
                status="COMPLETED"
            )
            db.session.add(record)
        else:
            # Append or overwrite depending on current logic, let's just append
            if record.findings:
                record.findings += "\n\n" + final_summary
            else:
                record.findings = final_summary
            record.status = "COMPLETED"
            
        db.session.add(incident)
        db.session.flush() # ensure record has id
        
        from backend.audit.writer import write_audit
        write_audit(
            module="automated_investigator",
            action="investigation.automated_action",
            target_type="InvestigationRecord",
            target_id=record.id,
            detail={"incident_number": incident.incident_number, "status": record.status},
            actor_id="system_investigator"
        )
        
        db.session.commit()
        
    def _map_severity(self, rule_severity: int) -> str:
        if rule_severity >= 9:
            return IncidentSeverity.P1.value
        elif rule_severity >= 7:
            return IncidentSeverity.P2.value
        elif rule_severity >= 4:
            return IncidentSeverity.P3.value
        else:
            return IncidentSeverity.P4.value

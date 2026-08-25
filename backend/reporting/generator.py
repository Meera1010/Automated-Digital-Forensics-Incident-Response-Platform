"""
ADFIR Platform — Report Generator
=====================================
Orchestrates report creation for a given incident and format.
Stores the result as an EvidenceArtifact and a Report DB record.
"""
import os
import hashlib
from datetime import datetime, timezone
from backend.extensions import db
from backend.models.incident import Incident
from backend.models.investigation_record import InvestigationRecord
from backend.models.evidence_artifact import EvidenceArtifact
from backend.models.response_action import ResponseAction
from backend.models.audit_log import AuditLog
from backend.models.report import Report, ReportFormat
from backend.reporting.html_renderer import render_html
from backend.reporting.json_renderer import render_json
from backend.reporting.pdf_renderer import render_pdf
from backend.audit.writer import write_audit
from backend.vault import vault_manager

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "storage", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

def _build_report_context(incident_id: str) -> dict:
    incident = db.session.query(Incident).get(incident_id)
    
    if not incident:
        raise ValueError(f"Incident {incident_id} not found.")

    investigation = db.session.query(InvestigationRecord).filter_by(incident_id=incident_id).first()
    evidence = db.session.query(EvidenceArtifact).filter_by(incident_id=incident_id).all()
    responses = db.session.query(ResponseAction).filter_by(incident_id=incident_id).all()
    audit_logs = db.session.query(AuditLog).filter_by(target_id=incident.id).all()
    
    # 1. Incident ID, 2. Category, 3. Severity, 13. Final Status (all in incident)
    # 4. Detection reason, 7. Timeline, 9. Indicators (in investigation)
    # 5. Evidence Info, 6. SHA-256 (in evidence)
    # 8. Triggered rules (in detection hits)
    # 10. Automated Response, 11. Response Result (in responses)
    # 12. Audit info (in audit_logs)

    hits_list = [
        {
            "rule_id": str(hit.rule_id),
            "rule_name": hit.rule.name if hit.rule else "Unknown",
            "severity": hit.rule.severity if hit.rule else "UNKNOWN",
            "timestamp": hit.timestamp.isoformat()
        } for hit in incident.detection_hits.all()
    ]

    context = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": incident.to_dict(),
        "investigation": investigation.to_dict() if investigation else {
            "detection_reason": "No investigation record found.",
            "timeline": [],
            "indicators": [],
            "summary": ""
        },
        "detection_hits": hits_list,
        "evidence": [e.to_dict() for e in evidence],
        "responses": [r.to_dict() for r in responses],
        "audit_logs": [a.to_dict() for a in audit_logs],
    }
    return context

def generate_report(incident_id: str, format_type: str = "html") -> Report:
    """
    Generates a forensic report for the given incident and format.
    """
    context = _build_report_context(incident_id)
    incident_num = context["incident"]["incident_number"]
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    
    file_content = None
    file_ext = format_type.lower()
    
    if file_ext == "html":
        file_content = render_html(context).encode("utf-8")
    elif file_ext == "json":
        file_content = render_json(context).encode("utf-8")
    elif file_ext == "pdf":
        html_content = render_html(context)
        file_content = render_pdf(html_content)
        if not file_content:
            # Fallback to HTML if PDF generation fails
            file_content = html_content.encode("utf-8")
            file_ext = "html"
    else:
        raise ValueError(f"Unsupported report format: {format_type}")

    file_hash = hashlib.sha256(file_content).hexdigest()
    file_name = f"report_{incident_num}_{timestamp_str}.{file_ext}"
    file_path = os.path.join(REPORTS_DIR, file_name)

    # Write report to disk
    with open(file_path, "wb") as f:
        f.write(file_content)

    # Update context with report hash for consistency if needed, but hash is generated after.
    # To embed hash IN the report, we'd need to calculate it over the payload without the hash, 
    # but the current template just puts the hash at the bottom. We'll skip embedding the final hash IN the HTML 
    # because it creates a circular dependency, or we just rely on DB/Vault hash. 
    # Actually, let's just use the file hash in the DB.

    # 1. Create Report record
    report_record = Report(
        incident_id=incident_id,
        generated_at=datetime.now(timezone.utc),
        format=file_ext,
        title=f"Forensic Report — {incident_num}",
        sha256_hash=file_hash,
        storage_path=file_name,
        generated_by="system"
    )
    db.session.add(report_record)

    # 2. Add as Evidence Artifact (Chain of Custody) using vault
    evidence_record = vault_manager.store(
        artifact_bytes=file_content,
        artifact_type=f"forensic_report_{file_ext}",
        incident_id=str(incident_id),
        filename=file_name,
        source="adfir_reporting_module",
        metadata={"generated_by": "system"}
    )
    
    db.session.flush() # Populate report_record.id

    db.session.commit()

    # 3. Audit log the generation
    write_audit(
        module="reporting.generator",
        action="report.generated",
        target_type="report",
        target_id=report_record.id,
        detail={"incident_number": incident_num, "format": file_ext, "result": "SUCCESS"}
    )

    return report_record

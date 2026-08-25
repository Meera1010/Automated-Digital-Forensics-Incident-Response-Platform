"""
ADFIR Platform — Investigation Summary Builder
================================================
Produces an InvestigationSummary struct handed to the Severity Classifier.

Fields: incident_id, event_count, unique_source_ips, asset_criticality,
        rule_severity_weights, earliest_event_at, latest_event_at.

TODO (Phase 3): Implement build_summary(incident) -> dict
"""

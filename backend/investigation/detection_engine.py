import json
import logging
from datetime import datetime, timezone
from typing import List

from backend.extensions import db
from backend.models.raw_event import RawEvent
from backend.models.detection_rule import DetectionRule, RuleType
from backend.models.detection_hit import DetectionHit
from backend.investigation.detection_rules import (
    RepeatedFailedLoginRule,
    SuspiciousProcessExecutionRule,
    UnexpectedNetworkActivityRule,
    EvidenceIntegrityViolationRule,
    AbnormalEventFrequencyRule,
    SuspiciousFileActivityRule
)

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self):
        self.rules = [
            RepeatedFailedLoginRule(),
            SuspiciousProcessExecutionRule(),
            UnexpectedNetworkActivityRule(),
            EvidenceIntegrityViolationRule(),
            AbnormalEventFrequencyRule(),
            SuspiciousFileActivityRule()
        ]
        self.rule_db_map = {}

    def sync_rules(self):
        """
        Ensures that the Python-defined rules exist in the DetectionRule table
        so that DetectionHit records can establish valid foreign keys.
        """
        for rule in self.rules:
            db_rule = db.session.query(DetectionRule).filter_by(rule_id=rule.rule_id).first()
            if not db_rule:
                db_rule = DetectionRule(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    rule_type=RuleType.PATTERN_MATCH,
                    severity_weight=rule.severity,
                    conditions_yaml="custom_python_logic: true\n" + f"description: {rule.conditions}",
                    enabled=True
                )
                db.session.add(db_rule)
                db.session.flush()
            else:
                # Update existing rule just in case logic/severity changed
                db_rule.name = rule.name
                db_rule.description = rule.description
                db_rule.severity_weight = rule.severity
                db.session.flush()
                
            self.rule_db_map[rule.rule_id] = db_rule.id
            
        db.session.commit()
        logger.info(f"Synced {len(self.rules)} rules to database.")

    def evaluate_events(self, events: List[RawEvent]):
        """
        Evaluates a list of events against all loaded rules.
        Creates DetectionHit records for triggered rules.
        """
        if not self.rule_db_map:
            self.sync_rules()

        hits_created = 0
        for event in events:
            for rule in self.rules:
                try:
                    triggered, reason = rule.evaluate(event)
                    if triggered:
                        hit = DetectionHit(
                            rule_id=self.rule_db_map[rule.rule_id],
                            raw_event_id=event.id,
                            fired_at=datetime.now(timezone.utc),
                            match_detail_json={
                                "reason": reason,
                                "severity": rule.severity,
                                "recommended_response": rule.recommended_response,
                                "rule_id_str": rule.rule_id
                            }
                        )
                        db.session.add(hit)
                        hits_created += 1
                        logger.warning(f"DetectionHit triggered: {rule.rule_id} on event {event.id}")
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule.rule_id} on event {event.id}: {str(e)}")
            
            event.processed = True
            
        db.session.commit()
        return hits_created

    def run_unprocessed(self):
        """
        Convenience method to find all unprocessed events and evaluate them.
        """
        events = db.session.query(RawEvent).filter_by(processed=False).all()
        if not events:
            return 0
        return self.evaluate_events(events)


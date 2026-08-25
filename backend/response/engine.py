"""
ADFIR Platform — Response Engine
=====================================
Loads and executes a ResponsePlaybook for a classified incident.
Runs actions sequentially; records each result in response_actions table.
"""

import yaml
import time
import logging
from typing import List

from backend.extensions import db
from backend.models.incident import Incident
from backend.models.response_playbook import ResponsePlaybook
from backend.models.response_action import ResponseAction, ActionStatus
from backend.audit.writer import write_audit
from backend.response.actions.registry import get_action_handler

# Ensure handlers are registered
import backend.response.actions.handlers 

logger = logging.getLogger(__name__)


def execute_response_for_incident(incident: Incident) -> List[ResponseAction]:
    """
    Selects the appropriate ResponsePlaybook for the incident and executes
    its configured actions sequentially.

    Returns a list of created ResponseAction records.
    """
    
    if incident.severity is None or incident.attack_category is None:
        logger.warning(f"Incident {incident.id} is missing severity or attack_category. Cannot run playbook.")
        return []

    playbook = ResponsePlaybook.query.filter_by(
        attack_category=incident.attack_category,
        severity_tier=incident.severity,
        enabled=True
    ).first()

    if not playbook:
        logger.info(f"No active playbook found for category {incident.attack_category} and severity {incident.severity}")
        return []

    # Assign playbook to incident
    incident.assigned_playbook_id = playbook.id
    
    actions_to_execute = []
    try:
        actions_to_execute = yaml.safe_load(playbook.actions_yaml)
    except Exception as e:
        logger.error(f"Failed to parse playbook {playbook.id} actions_yaml: {e}")
        return []

    if not isinstance(actions_to_execute, list):
        logger.error(f"Playbook {playbook.id} actions_yaml must be a list.")
        return []

    executed_actions = []

    for action_def in actions_to_execute:
        action_name = action_def.get("action")
        params = action_def.get("params", {})
        
        if not action_name:
            continue

        handler = get_action_handler(action_name)
        
        start_time = time.time()
        
        if not handler:
            status = ActionStatus.FAILED
            detail = f"Handler for action '{action_name}' not found in registry."
        else:
            try:
                status_str, detail = handler(incident, params)
                status = ActionStatus(status_str)
            except Exception as e:
                logger.error(f"Error executing action {action_name}: {e}")
                status = ActionStatus.FAILED
                detail = str(e)
                
        end_time = time.time()
        duration_ms = int((end_time - start_time) * 1000)

        # Create ResponseAction record
        response_action = ResponseAction(
            incident_id=incident.id,
            playbook_id=playbook.id,
            action_name=action_name,
            action_params_json=params,
            status=status.value,
            result_detail=detail,
            duration_ms=duration_ms
        )
        db.session.add(response_action)
        executed_actions.append(response_action)
        
        # Write Audit Log
        write_audit(
            module="response.engine",
            action="playbook.action_executed",
            target_type="incident",
            target_id=incident.id,
            detail={
                "playbook_id": str(playbook.id),
                "action": action_name,
                "status": status.value,
                "detail": detail
            }
        )
        
        # Stop on failure for safety? Typically yes, but we'll continue 
        # unless it's a critical error for now. 

    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"Database error committing response actions: {e}")
        db.session.rollback()

    return executed_actions

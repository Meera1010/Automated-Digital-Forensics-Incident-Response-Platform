"""
ADFIR Platform — Incident State Machine
=========================================
Defines valid state transitions and enforces them.

Valid transitions:
  NEW → INVESTIGATING → CLASSIFIED → RESPONDING → CONTAINED → CLOSED

Every transition is recorded in the audit log before committing.

TODO (Phase 3): Implement transition() and get_valid_transitions().
"""

from backend.models.incident import IncidentStatus

VALID_TRANSITIONS = {
    IncidentStatus.NEW.value:           [IncidentStatus.INVESTIGATING.value],
    IncidentStatus.INVESTIGATING.value: [IncidentStatus.CLASSIFIED.value],
    IncidentStatus.CLASSIFIED.value:    [IncidentStatus.RESPONDING.value],
    IncidentStatus.RESPONDING.value:    [IncidentStatus.CONTAINED.value],
    IncidentStatus.CONTAINED.value:     [IncidentStatus.CLOSED.value],
    IncidentStatus.CLOSED.value:        [],
}

def transition(incident, new_status: str) -> None:
    """
    Move an incident to a new status, enforcing valid transition rules.
    Raises ValueError if the transition is not permitted.
    TODO: Implement.
    """
    raise NotImplementedError("transition() not yet implemented.")


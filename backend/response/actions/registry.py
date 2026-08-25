"""
ADFIR Platform — Response Actions Registry
============================================
Provides a registry to map action names (from YAML playbooks) to Python functions.
"""

from typing import Callable, Dict, Any, Tuple
from backend.models.incident import Incident

# Type signature for a handler: (incident, params) -> (status_string, detail_string)
ActionHandler = Callable[[Incident, Dict[str, Any]], Tuple[str, str]]

ACTION_HANDLERS: Dict[str, ActionHandler] = {}

def register_action(name: str):
    """
    Decorator to register a function as a response action handler.
    """
    def decorator(func: ActionHandler):
        ACTION_HANDLERS[name] = func
        return func
    return decorator

def get_action_handler(name: str) -> ActionHandler:
    """
    Returns the handler for the given action name, or None if not found.
    """
    return ACTION_HANDLERS.get(name)

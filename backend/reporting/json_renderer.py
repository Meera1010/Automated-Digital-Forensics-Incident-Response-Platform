"""
ADFIR Platform — JSON Report Renderer
=========================================
Renders a machine-readable incident report as a structured JSON document.
"""
import json

def render_json(context: dict) -> str:
    """
    Serializes the forensic report context into a formatted JSON string.
    """
    return json.dumps(context, indent=2, default=str)

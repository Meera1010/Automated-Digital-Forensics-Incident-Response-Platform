"""
ADFIR Platform — Rule Loader
================================
Loads detection rule YAML files from backend/detection/rules/ and
upserts them into the detection_rules database table.

TODO (Phase 2):
  - Walk rules/ directory for *.yaml files.
  - Parse each file with PyYAML.
  - Upsert into DB: insert if rule_id not found, update if changed.
  - Increment version on update.
"""

import logging
logger = logging.getLogger(__name__)

RULES_DIR = "backend/detection/rules"

def load_rules_from_disk() -> int:
    """
    Load all YAML rule files and upsert into DB.
    Returns the number of rules loaded.
    TODO: Implement.
    """
    raise NotImplementedError("load_rules_from_disk not yet implemented.")

def reload_if_changed() -> int:
    """
    Check YAML files for modifications since last load and reload changed ones.
    Returns the number of rules reloaded.
    TODO: Implement.
    """
    raise NotImplementedError("reload_if_changed not yet implemented.")


"""
ADFIR Platform — Playbook Loader
=====================================
Loads response playbook YAML files from backend/response/playbooks/
and upserts them into the response_playbooks table.
"""

import os
import yaml
import logging
from backend.extensions import db
from backend.models.response_playbook import ResponsePlaybook

logger = logging.getLogger(__name__)

PLAYBOOKS_DIR = "backend/response/playbooks"


def load_playbooks_from_disk(directory: str = PLAYBOOKS_DIR) -> int:
    """
    Scans the directory for .yaml files, parses them, and upserts
    the playbooks into the ResponsePlaybook table.

    Returns the number of playbooks loaded.
    """
    if not os.path.isdir(directory):
        logger.warning(f"Playbooks directory {directory} does not exist.")
        return 0

    loaded_count = 0
    for filename in os.listdir(directory):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue

        filepath = os.path.join(directory, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                
            if not isinstance(data, dict):
                logger.error(f"Invalid playbook format in {filename}: Must be a dictionary.")
                continue
                
            name = data.get("name")
            attack_category = data.get("attack_category")
            severity_tier = data.get("severity_tier")
            actions = data.get("actions", [])
            enabled = data.get("enabled", True)
            
            if not all([name, attack_category, severity_tier]):
                logger.error(f"Missing required fields in {filename}. "
                             f"Required: name, attack_category, severity_tier.")
                continue

            actions_yaml = yaml.dump(actions)

            # Upsert by name, attack_category, severity_tier
            playbook = ResponsePlaybook.query.filter_by(
                attack_category=attack_category,
                severity_tier=severity_tier
            ).first()

            if playbook:
                playbook.name = name
                playbook.actions_yaml = actions_yaml
                playbook.enabled = enabled
            else:
                playbook = ResponsePlaybook(
                    name=name,
                    attack_category=attack_category,
                    severity_tier=severity_tier,
                    actions_yaml=actions_yaml,
                    enabled=enabled
                )
                db.session.add(playbook)
                
            loaded_count += 1
            
        except Exception as e:
            logger.error(f"Error loading playbook from {filename}: {e}")
            
    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"Database error while committing playbooks: {e}")
        db.session.rollback()
        
    return loaded_count

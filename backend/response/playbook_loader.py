"""
ADFIR Platform — Playbook Loader
=====================================
Loads response playbook YAML files from backend/response/playbooks/
and upserts them into the response_playbooks table.

TODO (Phase 4): Implement load_playbooks_from_disk() and reload_if_changed().
"""

PLAYBOOKS_DIR = "backend/response/playbooks"


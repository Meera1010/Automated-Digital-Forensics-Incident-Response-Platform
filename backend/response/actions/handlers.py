"""
ADFIR Platform — Response Action Handlers
===========================================
Implements the safe simulated actions for the Automated Incident Response Module.
Actions target SyntheticAssets or perform logging/auditing, without touching
real infrastructure.
"""

from typing import Dict, Any, Tuple
from backend.models.incident import Incident, IncidentStatus
from backend.models.synthetic_asset import SyntheticAsset, AssetStatus
from backend.response.actions.registry import register_action


@register_action("isolate_endpoint")
def isolate_endpoint(incident: Incident, params: Dict[str, Any]) -> Tuple[str, str]:
    """
    Simulates marking a test endpoint as isolated.
    Requires 'ip_address' or 'asset_id' in params.
    """
    ip = params.get("ip_address")
    asset_id = params.get("asset_id")
    
    if not ip and not asset_id:
        return "failed", "Missing 'ip_address' or 'asset_id' parameter."

    query = SyntheticAsset.query
    if ip:
        query = query.filter_by(ip_address=ip)
    if asset_id:
        query = query.filter_by(id=asset_id)
        
    asset = query.first()
    
    if not asset:
        return "failed", f"SyntheticAsset not found for isolation (ip={ip}, id={asset_id})."
        
    asset.status = AssetStatus.QUARANTINED
    return "success", f"Endpoint {asset.id} ({asset.ip_address}) isolated."


@register_action("quarantine_file")
def quarantine_file(incident: Incident, params: Dict[str, Any]) -> Tuple[str, str]:
    """
    Simulates quarantining a synthetic test file.
    Requires 'file_path' and 'hash' in params.
    """
    file_path = params.get("file_path", "unknown_path")
    file_hash = params.get("hash", "unknown_hash")
    
    return "success", f"Test file {file_path} (hash: {file_hash}) quarantined successfully."


@register_action("disable_account")
def disable_account(incident: Incident, params: Dict[str, Any]) -> Tuple[str, str]:
    """
    Simulates disabling a test account.
    Requires 'username' in params.
    """
    username = params.get("username", "unknown_user")
    
    return "success", f"Simulated account {username} disabled."


@register_action("block_ip")
def block_ip(incident: Incident, params: Dict[str, Any]) -> Tuple[str, str]:
    """
    Simulates adding a test IP to a blocklist.
    Requires 'ip_address' in params.
    """
    ip = params.get("ip_address")
    
    if not ip:
        return "failed", "Missing 'ip_address' parameter for blocking."
        
    return "success", f"Test IP {ip} added to simulated blocklist."


@register_action("contain_incident")
def contain_incident(incident: Incident, params: Dict[str, Any]) -> Tuple[str, str]:
    """
    Marks the incident as contained.
    """
    incident.status = IncidentStatus.CONTAINED.value
    return "success", f"Incident {incident.id} marked as CONTAINED."

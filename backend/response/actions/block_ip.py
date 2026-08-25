"""
Action: block_synthetic_ip
Adds the source IP to the synthetic_blocked_ips table.
The ingestion layer checks this list and flags future events from blocked IPs.
TODO (Phase 4): Implement execute(incident, params) -> dict
"""

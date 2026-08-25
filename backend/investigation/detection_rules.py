import re
from datetime import timedelta
from typing import Optional, Tuple
from backend.models.raw_event import RawEvent
from backend.extensions import db

class BaseRule:
    rule_id: str = "BASE"
    name: str = "Base Rule"
    description: str = "Base description"
    conditions: str = "Base conditions"
    severity: int = 5  # 1 to 10
    recommended_response: str = "Investigate."

    def evaluate(self, event: RawEvent) -> Tuple[bool, Optional[str]]:
        """
        Evaluates the event. 
        Returns (True, reason) if triggered, else (False, None).
        """
        raise NotImplementedError


class RepeatedFailedLoginRule(BaseRule):
    rule_id = "AUTH-001"
    name = "Repeated Failed Login Attempts"
    description = "Detects multiple authentication failures from a single IP address."
    conditions = "More than 5 auth_failure events from the same source IP in the last 5 minutes."
    severity = 7
    recommended_response = "Block the source IP and verify if any successful login occurred afterwards."

    def evaluate(self, event: RawEvent) -> Tuple[bool, Optional[str]]:
        if event.event_type != "auth_failure":
            return False, None
        
        if not event.source_ip:
            return False, None

        time_window = event.received_at - timedelta(minutes=5)
        
        count = db.session.query(RawEvent).filter(
            RawEvent.event_type == "auth_failure",
            RawEvent.source_ip == event.source_ip,
            RawEvent.received_at >= time_window,
            RawEvent.received_at <= event.received_at
        ).count()
        
        # Count includes the current event if it's already in the DB.
        # So we trigger if count >= 5.
        if count >= 5:
            return True, f"Observed {count} failed logins from {event.source_ip} in 5 minutes."
            
        return False, None


class SuspiciousProcessExecutionRule(BaseRule):
    rule_id = "PROC-001"
    name = "Suspicious Process Execution"
    description = "Detects execution of processes commonly used by attackers."
    conditions = "Process name matches mimikatz, or powershell with encoded command flags."
    severity = 9
    recommended_response = "Isolate the host and investigate the process tree."

    def evaluate(self, event: RawEvent) -> Tuple[bool, Optional[str]]:
        if event.event_type != "process_execution":
            return False, None
            
        process_name = str(event.payload_json.get("process_name", "")).lower()
        command_line = str(event.payload_json.get("command_line", "")).lower()
        
        if "mimikatz" in process_name or "mimikatz" in command_line:
            return True, "Mimikatz execution detected."
            
        if "powershell" in process_name and ("-enc" in command_line or "-encodedcommand" in command_line):
            return True, "Encoded PowerShell command executed."
            
        return False, None


class UnexpectedNetworkActivityRule(BaseRule):
    rule_id = "NET-001"
    name = "Unexpected Network Activity"
    description = "Detects outbound connections to unexpected or suspicious ports."
    conditions = "Destination port is a common reverse shell port (e.g., 4444)."
    severity = 8
    recommended_response = "Check for active reverse shells or C2 beacons on the host."

    def evaluate(self, event: RawEvent) -> Tuple[bool, Optional[str]]:
        if event.event_type != "network_connection":
            return False, None
            
        dest_port = event.payload_json.get("dest_port")
        if dest_port in [4444, 4445, 31337]:
            return True, f"Connection to suspicious port {dest_port} detected."
            
        return False, None


class EvidenceIntegrityViolationRule(BaseRule):
    rule_id = "INT-001"
    name = "Evidence Integrity Violation"
    description = "Detects when evidence hashing or integrity verification fails."
    conditions = "Event type indicates an integrity failure."
    severity = 10
    recommended_response = "Immediately restrict access to evidence vault and audit recent changes."

    def evaluate(self, event: RawEvent) -> Tuple[bool, Optional[str]]:
        if event.event_type == "integrity_failure":
            return True, "Evidence integrity check failed."
        return False, None


class AbnormalEventFrequencyRule(BaseRule):
    rule_id = "FREQ-001"
    name = "Abnormal Event Frequency"
    description = "Detects bursts of events from a single source, indicating a possible DoS or brute force tool."
    conditions = "More than 100 events from the same source IP in the last 1 minute."
    severity = 6
    recommended_response = "Investigate the source IP for automated scripting or scanning."

    def evaluate(self, event: RawEvent) -> Tuple[bool, Optional[str]]:
        if not event.source_ip:
            return False, None
            
        time_window = event.received_at - timedelta(minutes=1)
        
        count = db.session.query(RawEvent).filter(
            RawEvent.source_ip == event.source_ip,
            RawEvent.received_at >= time_window,
            RawEvent.received_at <= event.received_at
        ).count()
        
        if count > 100:
            return True, f"High event frequency: {count} events in 1 minute from {event.source_ip}."
            
        return False, None


class SuspiciousFileActivityRule(BaseRule):
    rule_id = "FILE-001"
    name = "Suspicious File Activity"
    description = "Detects access or modification of sensitive system files."
    conditions = "File path matches /etc/shadow or SAM registry hive."
    severity = 8
    recommended_response = "Verify if the file access was authorized or part of credential dumping."

    def evaluate(self, event: RawEvent) -> Tuple[bool, Optional[str]]:
        if event.event_type != "file_activity":
            return False, None
            
        file_path = str(event.payload_json.get("file_path", "")).lower()
        
        sensitive_files = ["/etc/shadow", "/etc/passwd", "system32\\config\\sam", "system32/config/sam"]
        
        for sf in sensitive_files:
            if sf in file_path:
                return True, f"Sensitive file activity detected: {file_path}"
                
        return False, None


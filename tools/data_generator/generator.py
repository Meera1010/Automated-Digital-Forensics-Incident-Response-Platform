"""
Synthetic Forensic Data Generator
=================================
Generates fictional cybersecurity events for testing the ADFIR platform.
"""

import argparse
import json
import random
import sys
import uuid
import urllib.request
from datetime import datetime, timezone, timedelta
from faker import Faker

fake = Faker()

EVENT_TYPES = [
    "auth_success",
    "auth_failure",
    "process_start",
    "file_create",
    "file_delete",
    "network_connection",
    "security_alert",
]

SUSPICIOUS_IPS = ["185.15.59.224", "45.133.1.20", "193.201.224.218", "91.241.19.84", "45.227.253.250"]
SUSPICIOUS_PORTS = [4444, 1337, 6666, 31337, 445]
SUSPICIOUS_USERS = ["root", "admin", "test", "postgres", "sql_svc"]
SUSPICIOUS_PROCESSES = ["/tmp/xmrig", "C:\\Windows\\Temp\\update.exe", "powershell.exe -enc", "vssadmin.exe delete shadows"]
SUSPICIOUS_FILES = ["C:\\Windows\\Temp\\sys.dll", "/etc/shadow.bak", "C:\\Users\\Public\\mimikatz.exe"]

NORMAL_PROCESSES = ["C:\\Windows\\System32\\svchost.exe", "/usr/bin/bash", "C:\\Program Files\\Chrome\\chrome.exe", "/usr/sbin/sshd"]
NORMAL_FILES = ["C:\\Users\\Bob\\Documents\\report.docx", "/var/log/syslog", "C:\\Program Files\\App\\config.json"]


def generate_event(is_suspicious: bool, event_type: str, current_time: datetime) -> dict:
    """Generate a single realistic synthetic event."""
    # Ensure no real personal info / passwords are used by relying on Faker's synthetic generation.
    source_ip = random.choice(SUSPICIOUS_IPS) if is_suspicious else fake.ipv4()
    dest_ip = "10.0." + str(random.randint(1, 255)) + "." + str(random.randint(1, 255))
    username = random.choice(SUSPICIOUS_USERS) if is_suspicious else f"{fake.first_name().lower()}.{fake.last_name().lower()}"
    asset_id = f"SYN-HOST-{random.randint(100, 999)}"
    
    payload = {
        "is_synthetic": True,
        "environment": "lab",
        "description": f"Synthetic {event_type} event"
    }

    if event_type in ("auth_success", "auth_failure"):
        payload["src_ip"] = source_ip
        payload["auth_method"] = random.choice(["publickey", "password", "session_token"])
        payload["port"] = random.choice([22, 3389, 443])
        
    elif event_type == "process_start":
        payload["process_name"] = random.choice(SUSPICIOUS_PROCESSES) if is_suspicious else random.choice(NORMAL_PROCESSES)
        payload["pid"] = random.randint(1000, 30000)
        payload["parent_pid"] = random.randint(100, 999)
        if is_suspicious:
            payload["command_line"] = payload["process_name"] + " " + fake.word()

    elif event_type in ("file_create", "file_delete"):
        payload["file_path"] = random.choice(SUSPICIOUS_FILES) if is_suspicious else random.choice(NORMAL_FILES)
        payload["file_hash"] = fake.sha256()

    elif event_type == "network_connection":
        payload["src_ip"] = dest_ip
        payload["dst_ip"] = source_ip
        payload["dst_port"] = random.choice(SUSPICIOUS_PORTS) if is_suspicious else random.choice([80, 443, 53, 123])
        payload["protocol"] = random.choice(["TCP", "UDP"])
        payload["bytes_sent"] = random.randint(100, 50000)

    elif event_type == "security_alert":
        payload["alert_name"] = "Suspicious Activity Detected" if is_suspicious else "Routine Scan Completed"
        payload["severity"] = "High" if is_suspicious else "Low"

    return {
        "id": str(uuid.uuid4()),
        "received_at": current_time.isoformat(),
        "source_tag": f"SYN-GEN-{random.randint(10, 99)}",
        "event_type": event_type,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "username": username,
        "asset_id": asset_id,
        "payload_json": payload
    }


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic forensic data for ADFIR.")
    parser.add_argument("-n", "--count", type=int, default=100, help="Number of events to generate")
    parser.add_argument("--time-range", type=float, default=24.0, help="Time range in hours for the generated events")
    parser.add_argument("--event-types", type=str, default="all", help="Comma-separated list of event types (or 'all')")
    parser.add_argument("--suspicious-freq", type=float, default=0.1, help="Frequency of suspicious events (0.0 to 1.0)")
    parser.add_argument("--output", type=str, default="", help="File path to write JSON events. Defaults to stdout.")
    parser.add_argument("--api-url", type=str, default="", help="URL to POST events (e.g. http://localhost:5000/api/v1/events/ingest)")
    
    args = parser.parse_args()

    types_to_generate = EVENT_TYPES if args.event_types == "all" else args.event_types.split(",")
    valid_types = [t for t in types_to_generate if t in EVENT_TYPES]
    
    if not valid_types:
        print("Error: No valid event types specified.", file=sys.stderr)
        sys.exit(1)

    events = []
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=args.time_range)
    total_seconds = int((end_time - start_time).total_seconds())

    print(f"Generating {args.count} synthetic events...", file=sys.stderr)
    for _ in range(args.count):
        is_suspicious = random.random() < args.suspicious_freq
        ev_type = random.choice(valid_types)
        
        # Distribute randomly over the time range
        offset = random.randint(0, total_seconds) if total_seconds > 0 else 0
        ev_time = start_time + timedelta(seconds=offset)
        
        event = generate_event(is_suspicious, ev_type, ev_time)
        events.append(event)
        
    # Sort events chronologically
    events.sort(key=lambda x: x["received_at"])

    # Output handling
    if args.api_url:
        print(f"Sending events to {args.api_url}...", file=sys.stderr)
        headers = {"Content-Type": "application/json"}
        # We may need an auth token if the endpoint enforces it.
        # But the ingest endpoint might just accept a list of events.
        success = 0
        for ev in events:
            try:
                req = urllib.request.Request(args.api_url, data=json.dumps(ev).encode('utf-8'), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status in (200, 201, 202):
                        success += 1
                    else:
                        print(f"Failed to post event: {resp.status} {resp.reason}", file=sys.stderr)
            except Exception as e:
                print(f"Error posting event: {e}", file=sys.stderr)
        print(f"Successfully sent {success}/{len(events)} events.", file=sys.stderr)
        
    elif args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
        print(f"Saved {len(events)} events to {args.output}", file=sys.stderr)
        
    else:
        # Output to stdout
        print(json.dumps(events, indent=2))

if __name__ == "__main__":
    main()

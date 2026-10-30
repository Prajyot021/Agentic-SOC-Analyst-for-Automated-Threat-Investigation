"""
Add synthetic high-severity SOC test alerts to data/alerts.json.

This script is designed for repeatable testing:
- Resolves data/alerts.json relative to this script, not the shell's current directory.
- Validates the existing JSON structure before modifying it.
- Avoids adding duplicate event_id values.
- Writes through a temporary file and atomically replaces the target.
- Creates a timestamped backup before changing an existing file.

These records are synthetic test data, not verified live security incidents.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent / "data" / "alerts.json"

NEW_ALERTS = [
    {
        "event_id": "attack_ransomware_001",
        "timestamp": "2024-08-05T20:00:00Z",
        "severity": "critical",
        "alert_type": "process",
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "actor_user": "victim_user",
        "hostname": "target-win10",
        "process_name": "vssadmin.exe",
        "process_commandline": "vssadmin delete shadows /all /quiet",
        "process_lineage": ["explorer.exe", "cmd.exe", "vssadmin.exe"],
        "mitre_technique_id": "T1490",
        "raw_log": "Synthetic test event: shadow-copy deletion command",
        "summary": "Synthetic ransomware-style test alert: shadow copies deleted, potentially inhibiting system recovery."
    },
    {
        "event_id": "attack_bruteforce_002",
        "timestamp": "2024-08-05T20:05:00Z",
        "severity": "high",
        "alert_type": "auth",
        "source_ip": "185.220.101.50",
        "destination_ip": "192.168.1.10",
        "destination_port": 3389,
        "actor_user": "administrator",
        "hostname": "target-win10",
        "process_name": None,
        "process_commandline": None,
        "process_lineage": None,
        "mitre_technique_id": "T1110.001",
        "raw_log": "Synthetic test event: repeated failed RDP authentication attempts",
        "summary": "Synthetic brute-force test alert: repeated failed RDP authentication attempts within five minutes."
    },
    {
        "event_id": "attack_c2_beacon_003",
        "timestamp": "2024-08-05T20:10:00Z",
        "severity": "critical",
        "alert_type": "network",
        "source_ip": "192.168.1.87",
        # TEST-NET-2 address reserved for documentation; not a real C2 indicator.
        "destination_ip": "198.51.100.99",
        "destination_port": 443,
        "actor_user": None,
        "hostname": "target-win10",
        "process_name": "svchost.exe",
        "process_commandline": None,
        "process_lineage": ["services.exe", "svchost.exe"],
        "mitre_technique_id": "T1071.001",
        "raw_log": "Synthetic test event: periodic outbound connection to a documentation-only IP",
        "summary": "Synthetic command-and-control-style test alert: periodic outbound connections to a documentation-only IP address."
    },
    {
        "event_id": "attack_credential_dump_004",
        "timestamp": "2024-08-05T20:15:00Z",
        "severity": "critical",
        "alert_type": "process",
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "actor_user": "admin",
        "hostname": "target-win10",
        "process_name": "mimikatz.exe",
        "process_commandline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "process_lineage": ["explorer.exe", "cmd.exe", "mimikatz.exe"],
        "mitre_technique_id": "T1003.001",
        "raw_log": "Synthetic test event: credential-dumping tool execution indicator",
        "summary": "Synthetic credential-dumping test alert: a known credential-dumping tool name and command pattern were observed."
    },
    {
        "event_id": "attack_malicious_powershell_005",
        "timestamp": "2024-08-05T20:20:00Z",
        "severity": "high",
        "alert_type": "process",
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "actor_user": "user123",
        "hostname": "target-win10",
        "process_name": "powershell.exe",
        "process_commandline": "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "process_lineage": ["explorer.exe", "powershell.exe"],
        "mitre_technique_id": "T1059.001",
        "raw_log": "Synthetic test event: hidden PowerShell process with a Base64-encoded command argument",
        "summary": "Synthetic PowerShell test alert: hidden-window execution with an encoded command argument; the encoded fragment is not assumed to be a complete executable command."
    }
]


def load_alerts(path: Path) -> list:
    """Load and validate the existing JSON alert list."""
    if not path.is_file():
        raise FileNotFoundError(
            f"Alerts file not found: {path}\n"
            "Run this script from your project copy or update DATA_FILE."
        )

    try:
        with path.open("r", encoding="utf-8") as handle:
            alerts = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path} at line {exc.lineno}, column {exc.colno}.") from exc

    if not isinstance(alerts, list):
        raise ValueError(f"Expected a JSON list of alerts in {path}, got {type(alerts).__name__}.")

    for index, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            raise ValueError(f"Alert at index {index} is not a JSON object.")

    return alerts


def validate_new_alerts(alerts: list) -> None:
    """Check minimum fields and duplicate IDs in the synthetic records."""
    required_fields = {"event_id", "timestamp", "severity", "alert_type", "hostname"}
    seen = set()

    for index, alert in enumerate(alerts):
        missing = required_fields - alert.keys()
        if missing:
            raise ValueError(f"New alert {index} is missing required fields: {sorted(missing)}")

        event_id = alert["event_id"]
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError(f"New alert {index} has an invalid event_id.")
        if event_id in seen:
            raise ValueError(f"Duplicate event_id in NEW_ALERTS: {event_id}")
        seen.add(event_id)


def atomic_write_json(path: Path, data: list) -> None:
    """Write JSON to a temporary file and atomically replace the target."""
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_path, path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def main() -> None:
    validate_new_alerts(NEW_ALERTS)
    alerts = load_alerts(DATA_FILE)

    existing_ids = {
        alert.get("event_id")
        for alert in alerts
        if isinstance(alert.get("event_id"), str)
    }
    alerts_to_add = [
        alert for alert in NEW_ALERTS
        if alert["event_id"] not in existing_ids
    ]

    if not alerts_to_add:
        print("No changes made: all synthetic test alerts already exist.")
        print(f"Total alerts: {len(alerts)}")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = DATA_FILE.with_name(f"{DATA_FILE.stem}.backup-{timestamp}{DATA_FILE.suffix}")

    # Preserve the original bytes before any modification.
    backup_path.write_bytes(DATA_FILE.read_bytes())

    updated_alerts = alerts_to_add + alerts
    atomic_write_json(DATA_FILE, updated_alerts)

    print(f"Added {len(alerts_to_add)} synthetic test alert(s).")
    print(f"Skipped {len(NEW_ALERTS) - len(alerts_to_add)} alert(s) already present.")
    print(f"Total alerts: {len(updated_alerts)}")
    print(f"Updated file: {DATA_FILE}")
    print(f"Backup created: {backup_path}")
    print("\nAdded alerts:")
    for alert in alerts_to_add:
        print(
            f"- {alert['event_id']} | "
            f"{alert['alert_type']} | {alert['severity']} | "
            f"MITRE {alert['mitre_technique_id']}"
        )
    print("\nThese are synthetic test records, not verified live incidents.")


if __name__ == "__main__":
    main()

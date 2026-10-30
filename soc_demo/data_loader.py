"""
Utility functions for loading alert data.
Now uses REAL Wazuh alerts converted to Mini-OCSF format.
"""

import json
from typing import List
from pathlib import Path
from .models import Alert

_ALERTS_CACHE = {"mtime": None, "alerts": None}


def load_alerts() -> List[Alert]:
    """
    Load alerts from data/alerts.json (converted from Wazuh).

    Cached by the file's mtime -- correlation_node (in agents.py) calls
    this once per alert being processed, so a "Process all visible alerts"
    run of N alerts would otherwise re-read and re-validate the entire
    file N times. The cache invalidates itself automatically the moment
    alerts.json actually changes (e.g. after add_high_severity_alerts.py
    runs), so there's no staleness risk -- just call load_alerts()
    normally and let it decide whether a re-read is needed.

    Returns:
        List of Alert objects
        
    Raises:
        FileNotFoundError: If alerts.json doesn't exist
        ValueError: If JSON is malformed or doesn't match Alert schema
    """
    project_root = Path(__file__).parent.parent
    alerts_file = project_root / "data" / "alerts.json"

    if not alerts_file.exists():
        _ALERTS_CACHE["mtime"] = None
        _ALERTS_CACHE["alerts"] = None
        raise FileNotFoundError(
            f"Alerts file not found: {alerts_file}\n"
            f"Run: python soc_demo/wazuh_converter.py"
        )

    current_mtime = alerts_file.stat().st_mtime
    if _ALERTS_CACHE["alerts"] is not None and _ALERTS_CACHE["mtime"] == current_mtime:
        return _ALERTS_CACHE["alerts"]

    with open(alerts_file, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    alerts = []
    for i, alert_dict in enumerate(raw_data):
        try:
            alert = Alert(**alert_dict)
            alerts.append(alert)
        except Exception as e:
            raise ValueError(
                f"Alert #{i+1} (event_id: {alert_dict.get('event_id', 'unknown')}) "
                f"failed validation: {e}"
            )

    _ALERTS_CACHE["mtime"] = current_mtime
    _ALERTS_CACHE["alerts"] = alerts
    return alerts


def load_sample_alerts() -> List[Alert]:
    """
    Load original sample alerts (kept for reference/testing).
    
    Returns:
        List of Alert objects
    """
    project_root = Path(__file__).parent.parent
    alerts_file = project_root / "data" / "sample_alerts.json"
    
    if not alerts_file.exists():
        raise FileNotFoundError(f"Sample alerts not found: {alerts_file}")
    
    with open(alerts_file, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)
    
    alerts = []
    for i, alert_dict in enumerate(raw_data):
        try:
            alert = Alert(**alert_dict)
            alerts.append(alert)
        except Exception as e:
            raise ValueError(
                f"Alert #{i+1} failed validation: {e}"
            )
    
    return alerts


def get_alert_by_id(event_id: str) -> Alert:
    """
    Get a specific alert by its event_id.
    
    Args:
        event_id: The event_id to search for
        
    Returns:
        Alert object
        
    Raises:
        ValueError: If no alert with that ID is found
    """
    alerts = load_alerts()
    
    for alert in alerts:
        if alert.event_id == event_id:
            return alert
    
    raise ValueError(f"No alert found with event_id: {event_id}")
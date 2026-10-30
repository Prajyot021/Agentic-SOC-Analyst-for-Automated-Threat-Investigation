"""
Input validation for alerts and LLM-derived fields (Issue #12).

Nothing here raises for "soft" problems -- it returns a list of warning
strings so callers can decide whether to proceed, degrade, or escalate.
Hard-invalid data (e.g. severity outside the known enum) is normalized to a
safe default rather than crashing the pipeline, but every normalization is
recorded so it shows up in the audit trail.
"""

import ipaddress
import re
from typing import List, Optional, Tuple

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_mitre_technique_id(value: Optional[str]) -> bool:
    if not value:
        return False
    return bool(_MITRE_RE.match(value.strip()))


def normalize_severity(value: Optional[str]) -> Tuple[str, List[str]]:
    warnings = []
    key = (value or "").strip().lower()
    if key not in VALID_SEVERITIES:
        warnings.append(f"severity '{value}' not in {sorted(VALID_SEVERITIES)}; defaulting to 'low'")
        key = "low"
    return key, warnings


def validate_alert(alert) -> List[str]:
    """
    Sanity-check the fields the pipeline actually depends on. Returns a list
    of human-readable warnings (empty list = clean). Does not mutate the
    alert -- callers decide how to react.
    """
    warnings = []

    if not getattr(alert, "event_id", None):
        warnings.append("alert.event_id is missing")
    if not getattr(alert, "hostname", None):
        warnings.append("alert.hostname is missing")
    if not getattr(alert, "alert_type", None):
        warnings.append("alert.alert_type is missing")

    _, sev_warnings = normalize_severity(getattr(alert, "severity", None))
    warnings.extend(sev_warnings)

    mitre_id = getattr(alert, "mitre_technique_id", None)
    if mitre_id and not validate_mitre_technique_id(mitre_id):
        warnings.append(f"mitre_technique_id '{mitre_id}' does not match T#### / T####.### format")

    source_ip = getattr(alert, "source_ip", None)
    if source_ip and not validate_ip(source_ip):
        warnings.append(f"source_ip '{source_ip}' is not a valid IP address")

    dest_ip = getattr(alert, "destination_ip", None)
    if dest_ip and not validate_ip(dest_ip):
        warnings.append(f"destination_ip '{dest_ip}' is not a valid IP address")

    return warnings

"""
Convert Wazuh alerts to Mini-OCSF format.

Wazuh uses a different schema than our standardized Mini-OCSF.
This module bridges the gap.
"""

import argparse
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from soc_demo.models import Alert

logger = logging.getLogger(__name__)


class WazuhConverter:
    """Converts Wazuh alert format to Mini-OCSF Alert objects."""

    # (max_level_inclusive, severity), checked in order. Above the last -> critical.
    SEVERITY_THRESHOLDS = (
        (3, "low"),       # 0-3   Informational
        (7, "medium"),    # 4-7   Notification
        (11, "high"),     # 8-11  Important
    )                     # 12+   critical

    # Direct rule ID -> alert type. VERIFY these against your Wazuh ruleset;
    # group-based fallback below handles most alerts anyway.
    RULE_TYPE_MAP = {
        '530': 'auth',
        '533': 'auth',
        '60103': 'auth',
        '18104': 'process',
        '61603': 'process',
        '87411': 'network',
        '92014': 'process',
        '100002': 'process',
    }

    # Group keywords (substring match, lowercase), checked in this order.
    GROUP_KEYWORDS = (
        ('auth', ('authentication', 'logon', 'login', 'ssh')),
        ('network', ('firewall', 'network', 'connection', 'sysmon_event3')),
        ('file', ('syscheck', 'filesystem', 'file_')),
        ('process', ('powershell', 'process', 'execution', 'sysmon')),
    )

    # Values Wazuh/Windows use as "no value"
    EMPTY_VALUES = {'', '-', 'null', 'none', 'n/a'}

    def __init__(self):
        """Initialize converter."""
        pass

    # ------------------------------------------------------------------ helpers

    @classmethod
    def _clean(cls, value: Any) -> Optional[str]:
        """Normalize a field to a stripped string, or None if empty/placeholder."""
        if value is None:
            return None
        text = str(value).strip()
        return None if text.lower() in cls.EMPTY_VALUES else text

    @classmethod
    def _first(cls, source: Dict[str, Any], *keys: str) -> Optional[str]:
        """Return the first non-empty cleaned value among the given keys."""
        for key in keys:
            cleaned = cls._clean(source.get(key))
            if cleaned is not None:
                return cleaned
        return None

    @staticmethod
    def _eventdata(alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Safely return data.win.eventdata (or an empty dict)."""
        win = alert_data.get('win')
        if isinstance(win, dict):
            eventdata = win.get('eventdata')
            if isinstance(eventdata, dict):
                return eventdata
        return {}

    @staticmethod
    def _normalize_timestamp(raw: Optional[str]) -> str:
        """
        Convert Wazuh timestamps (e.g. 2024-05-12T10:15:30.123+0000) to
        UTC ISO 8601 with a trailing 'Z'. Falls back to the current time if
        missing, or to the raw string if it cannot be parsed.
        """
        if not raw:
            return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z'):
            try:
                parsed = datetime.strptime(raw, fmt)
                return parsed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
            except ValueError:
                continue
        return raw

    def _generate_event_id(self, wazuh_alert: Dict[str, Any]) -> str:
        """Build a unique, deterministic event ID."""
        agent_id = (wazuh_alert.get('agent') or {}).get('id', 'unknown')
        rule_id = (wazuh_alert.get('rule') or {}).get('id', '0000')

        # Prefer Wazuh's own unique alert ID (e.g. "1715508930.123456")
        native_id = wazuh_alert.get('id')
        if native_id:
            return f"wazuh_{agent_id}_{rule_id}_{native_id}"

        # Fallback: hash the whole alert so same-second events still differ
        digest = hashlib.sha1(
            json.dumps(wazuh_alert, sort_keys=True, default=str).encode('utf-8')
        ).hexdigest()[:12]
        return f"wazuh_{agent_id}_{rule_id}_{digest}"

    # ----------------------------------------------------------------- mapping

    def _map_severity(self, rule_level: Any) -> str:
        """Map Wazuh rule level (0-15) to low/medium/high/critical."""
        try:
            level = int(rule_level)
        except (TypeError, ValueError):
            return "medium"

        for max_level, severity in self.SEVERITY_THRESHOLDS:
            if level <= max_level:
                return severity
        return "critical"

    def _map_alert_type(self, rule_id: str, rule_groups: List[str]) -> str:
        """Determine alert type from rule ID, then from rule groups."""
        rule_id = str(rule_id)
        if rule_id in self.RULE_TYPE_MAP:
            return self.RULE_TYPE_MAP[rule_id]

        groups_lower = [str(g).lower() for g in (rule_groups or [])]

        for alert_type, keywords in self.GROUP_KEYWORDS:
            if any(kw in group for group in groups_lower for kw in keywords):
                return alert_type
        return 'other'

    # -------------------------------------------------------------- extraction

    def _extract_network_info(self, alert_data: Dict[str, Any]) -> Dict[str, Optional[str]]:
        """Extract source_ip, destination_ip, destination_port."""
        result = {
            'source_ip': None,
            'destination_ip': None,
            'destination_port': None,
        }

        # Windows event data (4625 logon, Sysmon event 3, WFP 5156)
        eventdata = self._eventdata(alert_data)
        if eventdata:
            result['source_ip'] = self._first(
                eventdata, 'ipAddress', 'sourceIp', 'sourceAddress'
            )
            result['destination_ip'] = self._first(
                eventdata, 'destinationIp', 'destinationAddress', 'destAddress'
            )
            result['destination_port'] = self._first(
                eventdata, 'destinationPort', 'destPort'
            )

        # Linux syslog / decoder data (overrides only when present)
        src = self._clean(alert_data.get('srcip'))
        dst = self._clean(alert_data.get('dstip'))
        dport = self._clean(alert_data.get('dstport'))
        if src:
            result['source_ip'] = src
        if dst:
            result['destination_ip'] = dst
        if dport:
            result['destination_port'] = dport

        return result

    def _extract_process_info(self, alert_data: Dict[str, Any]):
        """Extract process_name, process_commandline, process_lineage."""
        result = {
            'process_name': None,
            'process_commandline': None,
            'process_lineage': None,
        }

        eventdata = self._eventdata(alert_data)
        if eventdata:
            result['process_name'] = self._first(
                eventdata, 'image', 'processPath', 'newProcessName'
            )
            result['process_commandline'] = self._first(
                eventdata, 'commandLine', 'scriptBlockText'
            )

            parent = self._first(eventdata, 'parentImage', 'parentProcessName')
            if parent and result['process_name']:
                result['process_lineage'] = [parent, result['process_name']]

        return result

    def _extract_user(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Extract username from Windows or Linux/SSH data."""
        eventdata = self._eventdata(alert_data)
        if eventdata:
            user = self._first(eventdata, 'targetUserName', 'user', 'subjectUserName')
            if user:
                return user

        return self._first(alert_data, 'dstuser', 'srcuser')

    @staticmethod
    def _extract_mitre_id(rule: Dict[str, Any]) -> Optional[str]:
        """Return the first MITRE technique ID, handling list or string forms."""
        mitre = rule.get('mitre')
        if not isinstance(mitre, dict):
            return None
        ids = mitre.get('id')
        if isinstance(ids, str):
            return ids or None
        if isinstance(ids, list) and ids:
            return str(ids[0])
        return None

    # -------------------------------------------------------------- conversion

    def convert_alert(self, wazuh_alert: Dict[str, Any]) -> Optional[Alert]:
        """
        Convert a single Wazuh alert to a Mini-OCSF Alert.

        Returns:
            Alert object, or None if conversion fails
        """
        try:
            if not isinstance(wazuh_alert, dict):
                raise TypeError(f"Expected dict, got {type(wazuh_alert).__name__}")

            rule = wazuh_alert.get('rule') or {}
            agent = wazuh_alert.get('agent') or {}
            data = wazuh_alert.get('data') or {}

            event_id = self._generate_event_id(wazuh_alert)
            severity = self._map_severity(rule.get('level', 0))
            alert_type = self._map_alert_type(rule.get('id', ''), rule.get('groups', []))

            network_info = self._extract_network_info(data)
            process_info = self._extract_process_info(data)
            actor_user = self._extract_user(data)
            mitre_technique_id = self._extract_mitre_id(rule)

            return Alert(
                event_id=event_id,
                timestamp=self._normalize_timestamp(wazuh_alert.get('timestamp')),
                severity=severity,
                alert_type=alert_type,
                source_ip=network_info['source_ip'],
                destination_ip=network_info['destination_ip'],
                destination_port=network_info['destination_port'],
                actor_user=actor_user,
                hostname=agent.get('name', 'unknown'),
                process_name=process_info['process_name'],
                process_commandline=process_info['process_commandline'],
                process_lineage=process_info['process_lineage'],
                mitre_technique_id=mitre_technique_id,
                raw_log=wazuh_alert.get('full_log') or json.dumps(wazuh_alert),
                summary=rule.get('description', 'No description'),
            )

        except Exception as e:
            logger.error(f"Failed to convert alert: {e}")
            try:
                logger.debug(f"Alert data: {json.dumps(wazuh_alert, indent=2, default=str)}")
            except Exception:
                pass
            return None

    @staticmethod
    def _to_dict(alert: Alert) -> Dict[str, Any]:
        """Serialize an Alert (Pydantic v2, with v1 fallback)."""
        if hasattr(alert, 'model_dump'):
            return alert.model_dump(mode='json')
        return json.loads(alert.json())

    def convert_file(
        self,
        input_path: str,
        output_path: str,
        limit: Optional[int] = None
    ) -> int:
        """
        Convert a file of Wazuh alerts (NDJSON) to a Mini-OCSF JSON array.

        Args:
            input_path: Path to Wazuh alerts.json
            output_path: Path to write Mini-OCSF alerts.json
            limit: Maximum number of alerts to convert (None = all)

        Returns:
            Number of alerts written
        """
        logger.info(f"Converting Wazuh alerts from {input_path}")

        wazuh_alerts = []
        with open(input_path, 'r', encoding='utf-8-sig') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    wazuh_alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning(f"Skipping line {line_num}: Invalid JSON")
                    continue

                if limit is not None and len(wazuh_alerts) >= limit:
                    break

        logger.info(f"Loaded {len(wazuh_alerts)} raw Wazuh alerts")

        converted_alerts = []
        failed = 0
        seen_ids = set()
        duplicates = 0

        for wazuh_alert in wazuh_alerts:
            alert = self.convert_alert(wazuh_alert)
            if alert is None:
                failed += 1
                continue
            if alert.event_id in seen_ids:
                duplicates += 1
                continue
            seen_ids.add(alert.event_id)
            converted_alerts.append(alert)

        logger.info(f"Converted {len(converted_alerts)} alerts ({failed} failed)")
        if duplicates:
            logger.warning(f"Dropped {duplicates} alerts with duplicate event_id")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, 'w', encoding='utf-8') as f:
            json.dump([self._to_dict(a) for a in converted_alerts], f, indent=2)

        logger.info(f"Wrote Mini-OCSF alerts to {output}")
        return len(converted_alerts)


def main():
    """Convert Wazuh alerts to Mini-OCSF format."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(description="Wazuh -> Mini-OCSF alert converter")
    parser.add_argument(
        "--input",
        default=r"D:\SOC-PROJECT\wazuh-lab\exports\wazuh_raw_alerts.json",
        help="Path to raw Wazuh alerts (NDJSON)",
    )
    parser.add_argument("--output", default="data/alerts.json", help="Output JSON path")
    parser.add_argument("--limit", type=int, default=None, help="Max alerts to convert")
    args = parser.parse_args()

    wazuh_export = Path(args.input)

    if not wazuh_export.exists():
        print(f"❌ Wazuh export not found: {wazuh_export}")
        print("\nRun this first:")
        print('docker exec single-node-wazuh.manager-1 tail -n 1000 '
              '/var/ossec/logs/alerts/alerts.json > '
              'D:\\SOC-PROJECT\\wazuh-lab\\exports\\wazuh_raw_alerts.json')
        return

    print("=" * 70)
    print("Wazuh → Mini-OCSF Alert Converter")
    print("=" * 70)

    converter = WazuhConverter()
    count = converter.convert_file(str(wazuh_export), args.output, limit=args.limit)

    print(f"\n✅ Converted {count} alerts")
    print(f"📁 Output: {args.output}")
    print("\nNext: Update data_loader.py to use alerts.json instead of sample_alerts.json")


if __name__ == "__main__":
    main()
"""Check alert distribution."""
import json
from collections import Counter

with open('data/alerts.json', 'r') as f:
    alerts = json.load(f)

print(f"Total alerts: {len(alerts)}")
print("\nSeverity distribution:")
severities = Counter(a['severity'] for a in alerts)
for sev, count in severities.most_common():
    print(f"  {sev}: {count}")

print("\nAlert type distribution:")
types = Counter(a['alert_type'] for a in alerts)
for typ, count in types.most_common():
    print(f"  {typ}: {count}")

print("\nMITRE coverage:")
mitre_count = sum(1 for a in alerts if a.get('mitre_technique_id'))
print(f"  Alerts with MITRE tags: {mitre_count}/{len(alerts)}")

print("\nSample alert summaries:")
for i, alert in enumerate(alerts[:5], 1):
    print(f"\n{i}. [{alert['severity']}] {alert['alert_type']}")
    print(f"   {alert['summary'][:80]}")
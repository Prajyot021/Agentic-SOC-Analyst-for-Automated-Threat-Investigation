"""
Test loading REAL Wazuh alerts (converted to Mini-OCSF).
"""

from soc_demo.data_loader import load_alerts, load_sample_alerts


def main():
    print("=" * 70)
    print("Testing REAL Alert Data Loading")
    print("=" * 70)
    
    # Test 1: Load real alerts
    print("\n[Test 1] Loading real Wazuh alerts...")
    try:
        alerts = load_alerts()
        print(f"✅ Successfully loaded {len(alerts)} real alerts")
    except Exception as e:
        print(f"❌ Failed to load alerts: {e}")
        return
    
    # Test 2: Display sample alerts
    print("\n[Test 2] Sample real alerts:")
    print("-" * 70)
    for i, alert in enumerate(alerts[:5], 1):
        print(f"\n{i}. {alert.event_id}")
        print(f"   Type: {alert.alert_type} | Severity: {alert.severity}")
        print(f"   Host: {alert.hostname}")
        print(f"   User: {alert.actor_user or 'N/A'}")
        print(f"   MITRE: {alert.mitre_technique_id or 'N/A'}")
        print(f"   Summary: {alert.summary[:80]}...")
    
    # Test 3: Show alert type distribution
    print("\n[Test 3] Alert type distribution:")
    print("-" * 70)
    type_counts = {}
    for alert in alerts:
        type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1
    
    for alert_type, count in sorted(type_counts.items()):
        print(f"  {alert_type}: {count}")
    
    # Test 4: Show severity distribution
    print("\n[Test 4] Severity distribution:")
    print("-" * 70)
    severity_counts = {}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
    
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")
    
    # Test 5: Show MITRE coverage
    print("\n[Test 5] MITRE ATT&CK coverage:")
    print("-" * 70)
    mitre_techniques = set()
    for alert in alerts:
        if alert.mitre_technique_id:
            mitre_techniques.add(alert.mitre_technique_id)
    
    print(f"  Unique MITRE techniques: {len(mitre_techniques)}")
    print(f"  Techniques: {', '.join(sorted(mitre_techniques))}")
    
    print("\n" + "=" * 70)
    print("✅ Real alert data is ready!")
    print("=" * 70)


if __name__ == "__main__":
    main()
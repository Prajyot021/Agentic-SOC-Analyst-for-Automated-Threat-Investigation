"""
Test with a mock high-severity attack alert.
"""

from soc_demo.models import Alert
from soc_demo.graph import run_alert_through_pipeline
from datetime import datetime


def create_mock_attack_alert():
    """Create a realistic attack alert for testing."""
    return Alert(
        event_id="mock_attack_001",
        timestamp=datetime.utcnow().isoformat() + 'Z',
        severity="high",
        alert_type="process",
        source_ip=None,
        destination_ip=None,
        destination_port=None,
        actor_user="labuser",
        hostname="target-win10",
        process_name="powershell.exe",
        process_commandline="powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...",
        process_lineage=["explorer.exe", "cmd.exe", "powershell.exe"],
        mitre_technique_id="T1059.001",
        raw_log="Sysmon Event ID 1: PowerShell with encoded command",
        summary="PowerShell executed with base64-encoded command, potential malware execution"
    )


def main():
    print("="*70)
    print("Testing with Mock Attack Alert")
    print("="*70)
    
    alert = create_mock_attack_alert()
    
    print(f"\nMock Alert: {alert.event_id}")
    print(f"Type: {alert.alert_type} | Severity: {alert.severity}")
    print(f"MITRE: {alert.mitre_technique_id}")
    print(f"Summary: {alert.summary}")
    print()
    
    # Run through pipeline
    final_state = run_alert_through_pipeline(alert)
    
        # Print results
    confidence = final_state.get('confidence_score')
    print(f"\n{'Final Results':^70}")
    print("-"*70)
    print(f"Disposition: {final_state.get('disposition') or 'N/A'}")
    print(f"Confidence: {confidence:.2f}" if confidence is not None else "Confidence: N/A (auto-closed, decision node not run)")
    print(f"Proposed Action: {final_state.get('proposed_action') or 'None'}")
    print(f"Guardrail Decision: {final_state.get('guardrail_decision') or 'N/A'}")
    
    print(f"\n{'Audit Trail':^70}")
    print("-"*70)
    for entry in final_state.get('audit_trail', []):
        print(f"  {entry}")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
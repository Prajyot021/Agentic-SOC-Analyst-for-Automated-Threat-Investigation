"""
Test the complete agent pipeline with real alerts.
"""

from soc_demo.data_loader import load_alerts
from soc_demo.graph import run_alert_through_pipeline


def main():
    print("="*70)
    print("Testing Agent Pipeline")
    print("="*70)
    
    # Load real alerts
    alerts = load_alerts()
    
    print(f"\nLoaded {len(alerts)} alerts")
    print("\nProcessing first 3 alerts...\n")
    
    # Process first 3 alerts
    for i, alert in enumerate(alerts[:3], 1):
        print("\n" + "="*70)
        print(f"Alert {i}/{3}: {alert.event_id}")
        print("="*70)
        print(f"Type: {alert.alert_type} | Severity: {alert.severity}")
        print(f"Summary: {alert.summary[:80]}...")
        print()
        
        try:
            # Run through pipeline
            final_state = run_alert_through_pipeline(alert)
            
            # Print results
            confidence = final_state.get('confidence_score')
            print(f"\n{'Final Results':^70}")
            print("-"*70)
            print(f"Disposition: {final_state.get('disposition', 'None')}")
            print(f"Confidence: {confidence:.2f}" if confidence is not None else "Confidence: N/A (auto-closed, decision node not run)")
            print(f"Proposed Action: {final_state.get('proposed_action', 'None')}")
            print(f"Guardrail Decision: {final_state.get('guardrail_decision', 'Not evaluated')}")

            print(f"\n{'Audit Trail':^70}")
            print("-"*70)
            for entry in final_state.get('audit_trail', []):
                print(f"  {entry}")
            
        except Exception as e:
            print(f"\n❌ Error processing alert: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*70)
    print("Pipeline test complete!")
    print("="*70)


if __name__ == "__main__":
    main()
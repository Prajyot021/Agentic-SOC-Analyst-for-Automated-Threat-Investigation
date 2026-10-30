"""
Deterministic guardrail engine.
Non-LLM policy enforcement for action authorization.
"""

from typing import Dict, Any, Literal
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Action tier definitions
ACTION_TIERS = {
    # Tier 1: Read-only, always safe
    'query_logs': 1,
    'enrich_asset': 1,
    'open_ticket_info': 1,
    
    # Tier 2: Reversible, conditional approval
    'block_ip': 2,
    'disable_user': 2,
    'quarantine_file': 2,
    
    # Tier 3: Destructive, always needs human
    'isolate_host': 3,
    'delete_file': 3,
    'wipe_system': 3,
}


class GuardrailEngine:
    AUTO_APPROVE_CONFIDENCE_THRESHOLD = 0.85
    HIGH_CRITICALITY_ASSETS = ["high", "critical"]
    
    def __init__(self):
        """Initialize guardrail engine."""
        pass
    
    def classify_action_tier(self, action_name: str) -> int:
        return ACTION_TIERS.get(action_name, 3) 
    
    def evaluate(
        self,
        action_name: str,
        confidence_score: float,
        asset_criticality: str,
        proposed_by: str = "agent"
    ) -> Dict[str, Any]:
        tier = self.classify_action_tier(action_name)

        asset_criticality = asset_criticality.lower() if asset_criticality else "unknown"
        
        decision = {
            'action': action_name,
            'tier': tier,
            'decision': 'deny',  
            'reason': '',
        }

        if tier == 1:
            decision['decision'] = 'auto_approve'
            decision['reason'] = 'Tier 1 action (read-only) - always safe'
            logger.info(f" AUTO-APPROVED: {action_name} (Tier 1)")
            return decision

        if tier == 3:
            decision['decision'] = 'require_human_approval'
            decision['reason'] = 'Tier 3 action (destructive) - requires human approval'
            logger.warning(f" HUMAN APPROVAL REQUIRED: {action_name} (Tier 3)")
            return decision

        if tier == 2:

            if confidence_score < self.AUTO_APPROVE_CONFIDENCE_THRESHOLD:
                decision['decision'] = 'require_human_approval'
                decision['reason'] = f'Confidence too low ({confidence_score:.2f} < {self.AUTO_APPROVE_CONFIDENCE_THRESHOLD})'
                logger.warning(f" HUMAN APPROVAL REQUIRED: {action_name} - Low confidence")
                return decision

            if asset_criticality in self.HIGH_CRITICALITY_ASSETS:
                decision['decision'] = 'require_human_approval'
                decision['reason'] = f'High-criticality asset ({asset_criticality}) - requires human approval'
                logger.warning(f" HUMAN APPROVAL REQUIRED: {action_name} - Critical asset")
                return decision

            decision['decision'] = 'auto_approve'
            decision['reason'] = f'Tier 2 action approved: confidence={confidence_score:.2f}, criticality={asset_criticality}'
            logger.info(f" AUTO-APPROVED: {action_name} (Tier 2)")
            return decision

        decision['reason'] = f'Unknown action tier: {tier}'
        logger.error(f" DENIED: {action_name} - Unknown tier")
        return decision


def main():
    """Test guardrail engine."""
    engine = GuardrailEngine()
    
    print("="*70)
    print("Guardrail Engine Test")
    print("="*70)
    
    # Test cases
    test_cases = [
        # (action, confidence, criticality, expected_decision)
        ('query_logs', 0.5, 'high', 'auto_approve'),  # Tier 1 always approved
        ('block_ip', 0.9, 'low', 'auto_approve'),  # Tier 2, high confidence, low criticality
        ('block_ip', 0.7, 'low', 'require_human_approval'),  # Tier 2, low confidence
        ('block_ip', 0.9, 'high', 'require_human_approval'),  # Tier 2, high criticality
        ('isolate_host', 0.99, 'low', 'require_human_approval'),  # Tier 3 always needs approval
    ]
    
    for i, (action, conf, crit, expected) in enumerate(test_cases, 1):
        print(f"\nTest {i}: {action}")
        print(f"  Confidence: {conf}, Criticality: {crit}")
        
        result = engine.evaluate(action, conf, crit)
        
        print(f"  Decision: {result['decision']}")
        print(f"  Reason: {result['reason']}")
        
        if result['decision'] == expected:
            print(f"  ✅ PASS")
        else:
            print(f"  ❌ FAIL (expected {expected})")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
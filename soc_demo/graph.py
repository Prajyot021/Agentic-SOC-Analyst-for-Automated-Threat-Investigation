"""
LangGraph workflow definition.
Connects all agents into a state machine.
"""

from typing import Literal
from langgraph.graph import StateGraph, END
from soc_demo.models import AgentState
from soc_demo.agents import (
    router_node,
    triage_node,
    enrichment_node,
    correlation_node,
    decision_node,
    mitigation_node,
    reporting_node,
)
from soc_demo.guardrail import GuardrailEngine
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize guardrail engine
guardrail_engine = GuardrailEngine()

# Note: node_visits on AgentState and a track_node_visit()/MAX_NODE_VISITS
# pair used to exist here as unused loop-safety scaffolding -- no edge in
# this graph ever loops back to enrichment, so nothing called them. Removed
# rather than left as dead code implying a retry path that doesn't exist.
# If you want a real ambiguous-confidence retry loop later, this is where
# it'd go: an edge from decision back to enrichment, gated on node_visits.


def should_auto_close(state: AgentState) -> Literal["close", "continue"]:
    """
    Routing decision after triage.
    
    Auto-close if:
    - Assessment is likely_benign (matched a known benign pattern) AND
    - Severity is low
    """
    if (
        state.initial_severity_assessment == "likely_benign"
        and state.alert.severity == "low"
    ):
        logger.info(f"Auto-closing {state.alert.event_id} as false positive")
        return "close"
    
    return "continue"


def route_after_decision(state: AgentState) -> Literal["escalate", "mitigate"]:
    """
    Routing decision after decision node.

    Routes purely off state.disposition, which decision_node computes
    deterministically via scoring.determine_disposition(). Previously this
    function re-derived the same escalate/mitigate split from raw
    confidence_score using its own hardcoded thresholds (0.4 / 0.6) --
    independent of, and inconsistent with, the thresholds actually used to
    set disposition (0.35 / 0.65 in scoring.py). That meant a case could
    have disposition="escalate" but still get routed into the mitigation
    node because its raw score cleared 0.6, silently no-op through
    mitigation/guardrail before landing on reporting anyway. Routing off
    disposition makes this the single source of truth -- tune thresholds
    in one place (scoring.py) and routing follows automatically.
    """
    return "mitigate" if state.disposition == "action_recommended" else "escalate"


def guardrail_node(state: AgentState) -> AgentState:
    """
    Guardrail evaluation (not an agent, pure logic).
    """
    if not state.proposed_action:
        state.guardrail_decision = "no_action_proposed"
        state.audit_trail.append("[Guardrail] No action to evaluate")
        return state
    
    # Evaluate action
    result = guardrail_engine.evaluate(
        action_name=state.proposed_action,
        confidence_score=state.confidence_score or 0.0,
        asset_criticality=state.asset_criticality or "unknown"
    )
    
    state.guardrail_decision = result['decision']
    state.audit_trail.append(
        f"[Guardrail] {result['decision']} - {result['reason']}"
    )
    
    return state


# Build the graph
def build_graph() -> StateGraph:
    """
    Build the complete agent workflow graph.
    """
    workflow = StateGraph(AgentState)
    
    # Add all nodes
    workflow.add_node("router", router_node)
    workflow.add_node("triage", triage_node)
    workflow.add_node("enrichment", enrichment_node)
    workflow.add_node("correlation", correlation_node)
    workflow.add_node("decision", decision_node)
    workflow.add_node("mitigation", mitigation_node)
    workflow.add_node("guardrail", guardrail_node)
    workflow.add_node("reporting", reporting_node)
    
    # Define the flow
    workflow.set_entry_point("router")
    
    # Router → Triage
    workflow.add_edge("router", "triage")
    
    # Triage → either auto-close or continue
    workflow.add_conditional_edges(
        "triage",
        should_auto_close,
        {
            "close": "reporting",
            "continue": "enrichment",
        }
    )
    
    # Enrichment → Correlation
    workflow.add_edge("enrichment", "correlation")
    
    # Correlation → Decision
    workflow.add_edge("correlation", "decision")
    
    # Decision → either escalate or mitigate
    workflow.add_conditional_edges(
        "decision",
        route_after_decision,
        {
            "escalate": "reporting",
            "mitigate": "mitigation",
        }
    )
    
    # Mitigation → Guardrail
    workflow.add_edge("mitigation", "guardrail")
    
    # Guardrail → Reporting
    workflow.add_edge("guardrail", "reporting")
    
    # Reporting → END
    workflow.add_edge("reporting", END)
    
    return workflow.compile()


# Create the compiled graph
graph = build_graph()


def run_alert_through_pipeline(alert):
    """
    Helper function to run a single alert through the pipeline.
    
    Args:
        alert: Alert object
        
    Returns:
        Final AgentState
    """
    # Initialize state
    initial_state = AgentState(
        alert=alert,
        audit_trail=[],
    )
    
    # Run through graph
    logger.info(f"Processing alert: {alert.event_id}")
    final_state = graph.invoke(initial_state)
    
    return final_state
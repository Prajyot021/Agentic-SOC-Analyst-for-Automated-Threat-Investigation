"""
Data models for the SOC demo.
Defines the structure of alerts and other data objects.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class Alert(BaseModel):
    """
    Mini-OCSF alert schema.
    
    This is our standardized alert format that all agents work with.
    Based on OCSF but simplified to only the fields we need.
    """
    
    # Core identification
    event_id: str = Field(
        description="Unique identifier for this alert"
    )
    
    timestamp: str = Field(
        description="When the alert was generated (ISO 8601 format)"
    )
    
    # Classification
    severity: str = Field(
        description="Alert severity: low, medium, high, critical"
    )
    
    alert_type: str = Field(
        description="Category of alert: auth, network, process, file, etc."
    )
    
    # Network context (optional - not all alerts have network data)
    source_ip: Optional[str] = Field(
        default=None,
        description="Source IP address if applicable"
    )
    
    destination_ip: Optional[str] = Field(
        default=None,
        description="Destination IP address if applicable"
    )
    
    destination_port: Optional[int] = Field(
        default=None,
        description="Destination port if applicable"
    )
    
    # Identity context (optional)
    actor_user: Optional[str] = Field(
        default=None,
        description="Username associated with the activity"
    )
    
    # Asset context
    hostname: str = Field(
        description="Hostname where the alert originated"
    )
    
    # Process context (optional)
    process_name: Optional[str] = Field(
        default=None,
        description="Process name if applicable"
    )
    
    process_commandline: Optional[str] = Field(
        default=None,
        description="Full process command line if applicable"
    )
    
    process_lineage: Optional[List[str]] = Field(
        default=None,
        description="Parent process chain if available"
    )
    
    # Threat intelligence
    mitre_technique_id: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique ID (e.g., T1110)"
    )
    
    # Raw data
    raw_log: str = Field(
        description="Original raw log message"
    )
    
    # Human-readable summary
    summary: str = Field(
        description="Brief human-readable description of the alert"
    )
    
    class Config:
        """Pydantic configuration"""
        # Allow using this model with JSON
        json_schema_extra = {
            "example": {
                "event_id": "evt_001",
                "timestamp": "2024-01-15T10:30:00Z",
                "severity": "high",
                "alert_type": "auth",
                "source_ip": "192.168.1.100",
                "actor_user": "admin",
                "hostname": "WKS-001",
                "raw_log": "Failed login attempt",
                "summary": "Multiple failed login attempts detected"
            }
        }


class AgentState(BaseModel):
    """
    The state object that flows through the agent graph.
    
    Each agent reads from this state, adds its findings, and passes it forward.
    """
    
    # Input
    alert: Alert = Field(
        description="The original alert being processed"
    )
    
    # Router output
    routed_type: Optional[str] = Field(
        default=None,
        description="Alert type determined by Router agent"
    )
    
    validation_warnings: List[str] = Field(
        default_factory=list,
        description="Input-validation warnings raised on the incoming alert (Router agent)"
    )
    
    # Triage output
    initial_severity_assessment: Optional[str] = Field(
        default=None,
        description="Triage agent's severity assessment"
    )
    
    triage_reasoning: Optional[str] = Field(
        default=None,
        description="Why triage classified it this way"
    )
    
    # Enrichment output
    asset_criticality: Optional[str] = Field(
        default=None,
        description="Criticality level of the affected asset: low, medium, high"
    )
    
    asset_owner: Optional[str] = Field(
        default=None,
        description="Department/team that owns this asset"
    )
    
    is_known_benign: Optional[bool] = Field(
        default=False,
        description="Whether this matches a known benign pattern"
    )
    
    # Correlation output
    related_alerts: Optional[List[str]] = Field(
        default=None,
        description="Event IDs of related alerts"
    )
    
    correlation_pattern: Optional[str] = Field(
        default=None,
        description="Description of any pattern found"
    )
    
    correlated_alert_count: int = Field(
        default=0,
        description="Number of related alerts found by the Correlation agent"
    )
    
    # Decision output
    confidence_score: Optional[float] = Field(
        default=None,
        description="Confidence this is a real incident (0.0 to 1.0), deterministically computed"
    )
    
    score_breakdown: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Per-component breakdown of confidence_score (see scoring.ScoreBreakdown), for auditability"
    )
    
    disposition: Optional[str] = Field(
        default=None,
        description="Final decision: false_positive, escalate, action_recommended"
    )
    
    mitre_mapping: Optional[List[str]] = Field(
        default=None,
        description="MITRE ATT&CK techniques identified"
    )
    
    decision_reasoning: Optional[str] = Field(
        default=None,
        description="Explanation of the decision"
    )
    
    degraded_context: bool = Field(
        default=False,
        description="True if MITRE RAG context could not be retrieved and the decision was made without it"
    )
    
    llm_confidence_modifier: float = Field(
        default=0.0,
        description="Bounded (+/-0.10) qualitative adjustment from the LLM, folded into confidence_score"
    )
    
    llm_modifier_reasoning: Optional[str] = Field(
        default=None,
        description="LLM's stated reason for its confidence modifier"
    )
    
    # Mitigation output
    proposed_action: Optional[str] = Field(
        default=None,
        description="Action name from catalog: isolate_host, block_ip, etc."
    )
    
    action_parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Parameters for the proposed action"
    )
    
    action_tier: Optional[int] = Field(
        default=None,
        description="Action risk tier: 1 (safe), 2 (reversible), 3 (destructive)"
    )
    
    # Guardrail output
    guardrail_decision: Optional[str] = Field(
        default=None,
        description="auto_approve, require_human_approval, or deny"
    )
    
    human_decision: Optional[str] = Field(
        default=None,
        description="approved, rejected, or modified (if human reviewed)"
    )
    
    # Audit trail
    audit_trail: List[str] = Field(
        default_factory=list,
        description="Log of each agent's actions"
    )
    
    class Config:
        """Pydantic configuration"""
        arbitrary_types_allowed = True
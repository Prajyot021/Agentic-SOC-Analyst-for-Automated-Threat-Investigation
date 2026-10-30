"""
Deterministic confidence scoring for SOC alert triage.

Design rationale (for dissertation write-up):
The prior implementation asked an LLM to emit a confidence_score directly.
That is non-reproducible (same alert -> different scores across runs),
uncalibrated (the model has no grounded notion of what 0.75 means), and
undefensible in an evaluation chapter ("why 0.75?" has no answer).

This module replaces that with a fully deterministic, weighted rubric over
observable evidence (asset criticality, alert severity, correlation hits,
MITRE technique presence, known-benign match). Every run on the same input
produces the same score, and every score has a traceable breakdown you can
put in an appendix table. An LLM-derived signal is still allowed in, but
only as a small, explicitly bounded modifier -- never as the primary driver
-- and its contribution is logged separately so it can be ablated in your
evaluation (run with/without the LLM modifier to show it isn't load-bearing).
"""

from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Weight table. Keep these as named constants (not magic numbers scattered
# through the code) so they can be cited, tuned, and unit-tested.
# ---------------------------------------------------------------------------

ASSET_CRITICALITY_WEIGHTS = {
    "critical": 0.25,
    "high": 0.20,
    "medium": 0.12,
    "low": 0.05,
    "unknown": 0.10,  # unknown asset is treated as a mild risk-up, not zero
}

SEVERITY_WEIGHTS = {
    "critical": 0.30,
    "high": 0.20,
    "medium": 0.10,
    "low": 0.03,
}

MITRE_TECHNIQUE_PRESENT_WEIGHT = 0.15
CORRELATION_WEIGHT_PER_ALERT = 0.08
CORRELATION_WEIGHT_CAP = 0.24  # cap so 5+ correlated alerts don't blow past 1.0
KNOWN_BENIGN_PENALTY = -0.35   # strong pull toward false_positive if matched

# LLM qualitative modifier is intentionally small and bounded. It represents
# "does the free-text narrative contain anything the rule engine wouldn't
# see" (e.g. an unusual argument pattern in a commandline) -- not the
# primary decision.
LLM_MODIFIER_BOUND = 0.10

# Disposition thresholds. Centralized here so decision_node cannot diverge
# from mitigation_node's assumptions about what "action_recommended" means.
THRESHOLD_FALSE_POSITIVE = 0.35
THRESHOLD_ACTION_RECOMMENDED = 0.65


@dataclass
class ScoreBreakdown:
    asset_component: float = 0.0
    severity_component: float = 0.0
    mitre_component: float = 0.0
    correlation_component: float = 0.0
    benign_penalty: float = 0.0
    llm_modifier: float = 0.0
    llm_modifier_reasoning: Optional[str] = None
    raw_total: float = 0.0
    final_score: float = 0.0  # clipped to [0, 1]
    notes: list = field(default_factory=list)

    def as_dict(self):
        return {
            "asset_component": round(self.asset_component, 4),
            "severity_component": round(self.severity_component, 4),
            "mitre_component": round(self.mitre_component, 4),
            "correlation_component": round(self.correlation_component, 4),
            "benign_penalty": round(self.benign_penalty, 4),
            "llm_modifier": round(self.llm_modifier, 4),
            "llm_modifier_reasoning": self.llm_modifier_reasoning,
            "raw_total": round(self.raw_total, 4),
            "final_score": round(self.final_score, 4),
            "notes": self.notes,
        }


def compute_confidence(
    *,
    asset_criticality: str,
    severity: str,
    has_mitre_technique: bool,
    correlated_alert_count: int,
    is_known_benign: bool,
    llm_modifier: float = 0.0,
    llm_modifier_reasoning: Optional[str] = None,
) -> ScoreBreakdown:
    """
    Compute a deterministic confidence score in [0.0, 1.0].

    All inputs are evidence gathered by earlier nodes (enrichment,
    correlation, triage) -- nothing here calls an LLM.
    """
    bd = ScoreBreakdown()

    bd.asset_component = ASSET_CRITICALITY_WEIGHTS.get(
        (asset_criticality or "unknown").lower(), ASSET_CRITICALITY_WEIGHTS["unknown"]
    )

    sev_key = (severity or "").lower()
    if sev_key not in SEVERITY_WEIGHTS:
        bd.notes.append(f"unrecognized severity '{severity}', treated as 'low'")
        sev_key = "low"
    bd.severity_component = SEVERITY_WEIGHTS[sev_key]

    if has_mitre_technique:
        bd.mitre_component = MITRE_TECHNIQUE_PRESENT_WEIGHT

    # Fix: Prevent negative values if upstream count is improperly initialized
    bd.correlation_component = max(
        0.0, 
        min(
            correlated_alert_count * CORRELATION_WEIGHT_PER_ALERT,
            CORRELATION_WEIGHT_CAP,
        )
    )

    if is_known_benign:
        bd.benign_penalty = KNOWN_BENIGN_PENALTY

    # Bound and record the LLM's advisory contribution.
    clipped_modifier = max(-LLM_MODIFIER_BOUND, min(LLM_MODIFIER_BOUND, llm_modifier))
    if clipped_modifier != llm_modifier:
        bd.notes.append(
            f"llm_modifier {llm_modifier} clipped to {clipped_modifier} (bound={LLM_MODIFIER_BOUND})"
        )
    bd.llm_modifier = clipped_modifier
    bd.llm_modifier_reasoning = llm_modifier_reasoning

    bd.raw_total = (
        bd.asset_component
        + bd.severity_component
        + bd.mitre_component
        + bd.correlation_component
        + bd.benign_penalty
        + bd.llm_modifier
    )
    bd.final_score = max(0.0, min(1.0, bd.raw_total))

    return bd


def determine_disposition(
    confidence_score: float,
    *,
    remediation_available: bool,
    required_action_fields_present: bool,
) -> str:
    """
    Disposition is derived from the score by CODE, not trusted from the LLM
    (fixes Issue #2). This is the single source of truth mitigation_node
    should defer to.
    """
    if confidence_score < THRESHOLD_FALSE_POSITIVE:
        return "false_positive"
    
    # Fix: Explicit condition for the escalation mid-tier
    elif THRESHOLD_FALSE_POSITIVE <= confidence_score < THRESHOLD_ACTION_RECOMMENDED:
        return "escalate"

    elif confidence_score >= THRESHOLD_ACTION_RECOMMENDED:
        if remediation_available and required_action_fields_present:
            return "action_recommended"
        # High confidence but no safe/complete remediation path -> human eyes.
        return "escalate"

    return "escalate"
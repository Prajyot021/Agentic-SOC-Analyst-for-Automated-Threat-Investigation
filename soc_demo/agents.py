import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from soc_demo.models import AgentState, Alert
from soc_demo.llm_config import get_llm
from soc_demo.rag import get_retriever
from soc_demo.data_loader import load_alerts
from soc_demo.llm_utils import call_llm_with_timeout, parse_llm_json, LLMTimeoutError, LLMParseError
from soc_demo.validation import validate_alert, validate_ip
from soc_demo.scoring import compute_confidence, determine_disposition

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"

# ---------------------------------------------------------------------------
# Config loading (Issues #3, #4)
# ---------------------------------------------------------------------------

_DEFAULT_ASSET_INVENTORY = {
    "target-win10": {"criticality": "high", "owner": "Security Lab"},
    "desktop-abc123": {"criticality": "medium", "owner": "Engineering"},
    "srv-app-003": {"criticality": "high", "owner": "IT Operations"},
}

_DEFAULT_BENIGN_PATTERNS = {
    "scheduled_scan": ["sec-scanner", "nmap", "vulnerability scan"],
    "maintenance": ["svc_patch_mgmt", "scheduled maintenance"],
}


def load_asset_inventory() -> Dict[str, Dict[str, str]]:
    """
    Load asset inventory from data/assets.json.

    Fix for Issue #3: the original silently fell back to three fake demo
    hostnames on ANY load problem, including a present-but-empty file, and
    never told you it had done so. This version logs loudly on fallback (so
    a misconfigured deployment is visible in the logs, not just in wrong
    guardrail decisions later), and normalizes hostnames to lowercase so
    lookups aren't case-sensitive-fragile against real Wazuh hostnames.
    """
    assets_file = DATA_DIR / "assets.json"
    if not assets_file.exists():
        logger.warning(
            "assets.json not found at %s -- falling back to %d demo assets. "
            "Real hostnames will resolve as 'unknown' criticality.",
            assets_file, len(_DEFAULT_ASSET_INVENTORY),
        )
        return dict(_DEFAULT_ASSET_INVENTORY)

    try:
        with open(assets_file, "r") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load/parse assets.json (%s) -- falling back to demo assets", e)
        return dict(_DEFAULT_ASSET_INVENTORY)

    # Fix: Prevent startup crash if the JSON is valid but not a dictionary
    if not raw or not isinstance(raw, dict):
        logger.warning("assets.json is empty or invalid format -- falling back to demo assets")
        return dict(_DEFAULT_ASSET_INVENTORY)

    return {host.lower(): info for host, info in raw.items()}


def load_benign_patterns() -> Dict[str, List[str]]:
    """Load known-benign keyword patterns from config (Issue #4)."""
    patterns_file = DATA_DIR / "benign_patterns.json"
    if not patterns_file.exists():
        logger.info("benign_patterns.json not found -- using %d built-in patterns", len(_DEFAULT_BENIGN_PATTERNS))
        return dict(_DEFAULT_BENIGN_PATTERNS)
    try:
        with open(patterns_file, "r") as f:
            raw = json.load(f)
        # Fix: Prevent startup crash if the JSON is valid but not a dictionary
        if not raw or not isinstance(raw, dict):
            return dict(_DEFAULT_BENIGN_PATTERNS)
        return raw
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load benign_patterns.json (%s) -- using built-in patterns", e)
        return dict(_DEFAULT_BENIGN_PATTERNS)


def _parse_alert_timestamp(ts: str) -> Optional[datetime]:
    """
    Parse an Alert.timestamp string into a timezone-aware datetime.

    Real Wazuh timestamps often use an offset without a colon (e.g.
    '+0000') rather than strict ISO-8601 ('+00:00'), which
    datetime.fromisoformat() rejects on Python < 3.11. Falls back to
    python-dateutil (already an installed transitive dependency, per
    requirements.txt) for anything fromisoformat can't handle.

    Always returns a timezone-aware datetime (naive results are assumed
    UTC) -- correlation_node subtracts two of these, and mixing an aware
    and a naive datetime raises TypeError uncaught, which would silently
    crash correlation for any alert whose timestamp took the fallback path
    while another took the strict path.
    """
    if not ts:
        return None

    parsed = None
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        try:
            from dateutil import parser as date_parser
            parsed = date_parser.parse(ts)
        except Exception:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


ASSET_INVENTORY = load_asset_inventory()
BENIGN_PATTERNS = load_benign_patterns()


# Fix: Replaced str | None with Optional[str] for Python 3.9 compatibility
def _matches_benign_pattern(alert: Alert) -> Optional[str]:
    """
    Check summary, process name, and commandline against benign patterns
    (Issue #4 follow-on: original only checked `summary`, so a benign nmap
    invocation logged with the keyword in process_commandline instead of
    summary would be missed).
    """
    haystacks = [
        (alert.summary or ""),
        (getattr(alert, "process_name", "") or ""),
        (getattr(alert, "process_commandline", "") or ""),
    ]
    combined = " ".join(haystacks).lower()

    for pattern_name, keywords in BENIGN_PATTERNS.items():
        for keyword in keywords:
            if keyword.lower() in combined:
                return f"Matches known benign pattern: {pattern_name} (keyword: '{keyword}')"
    return None


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

def router_node(state: AgentState) -> AgentState:
    """Router Agent: Classify alert type, with basic input validation up front (Issue #12)."""
    alert = state.alert

    warnings = validate_alert(alert)
    state.validation_warnings = warnings
    for w in warnings:
        state.audit_trail.append(f"[Router] Validation warning: {w}")
        logger.warning("Validation: %s -> %s", getattr(alert, "event_id", "?"), w)

    routed_type = alert.alert_type or "unknown"
    state.audit_trail.append(f"[Router] Classified as '{routed_type}' alert")
    state.routed_type = routed_type

    logger.info("Router: %s -> %s", alert.event_id, routed_type)
    return state


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

def triage_node(state: AgentState) -> AgentState:
    """
    Triage Agent: Initial false-positive screening.

    Fix for Issue #5: the original always fell through to an LLM call for
    reasoning that never affected any downstream decision (confidence is now
    computed deterministically in decision_node). This version uses rule
    logic only -- benign-pattern match, or a plain "no early signal" note --
    and makes zero LLM calls, cutting latency/cost with no loss of accuracy
    for the pipeline's actual outputs.
    """
    alert = state.alert

    benign_reason = _matches_benign_pattern(alert)
    if benign_reason:
        state.initial_severity_assessment = "likely_benign"
        state.triage_reasoning = benign_reason
        state.audit_trail.append(f"[Triage] {benign_reason}")
        logger.info("Triage: %s -> Benign (pattern match)", alert.event_id)
        return state

    state.initial_severity_assessment = "needs_investigation"
    state.triage_reasoning = "No known-benign pattern matched; proceeding to full analysis."
    state.audit_trail.append(f"[Triage] {state.triage_reasoning}")
    logger.info("Triage: %s -> needs_investigation (rule-based, no LLM call)", alert.event_id)
    return state


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def enrichment_node(state: AgentState) -> AgentState:
    """Enrichment Agent: Add asset context."""
    alert = state.alert

    asset_info = ASSET_INVENTORY.get(
        (alert.hostname or "").lower(), {"criticality": "unknown", "owner": "Unknown"}
    )
    state.asset_criticality = asset_info.get("criticality", "unknown")
    state.asset_owner = asset_info.get("owner", "Unknown")
    state.is_known_benign = state.initial_severity_assessment == "likely_benign"

    state.audit_trail.append(
        f"[Enrichment] Asset: {alert.hostname} "
        f"(criticality={state.asset_criticality}, owner={state.asset_owner})"
    )
    logger.info("Enrichment: %s -> criticality=%s", alert.event_id, state.asset_criticality)
    return state


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlation_node(state: AgentState, *, window_seconds: int = 24 * 3600) -> AgentState:
    """
    Correlation Agent: check for related alerts (Issue #6 -- previously a
    no-op). Looks for alerts in data/alerts.json (the real converted Wazuh
    feed, via data_loader.load_alerts()) sharing hostname, source_ip,
    actor_user, or MITRE technique within a time window of the current
    alert's timestamp.

    Linear scan over the loaded alert set -- matches the "simplified
    prototype" scope (Python rule engine instead of a real correlation
    backend / Elasticsearch). Fine at demo data volumes; if alerts.json
    grows large, swap this for an indexed query without changing the
    node's interface.
    """
    alert = state.alert

    try:
        all_alerts = load_alerts()
    except FileNotFoundError as e:
        logger.warning("Correlation: could not load alerts.json (%s) -- running with no history", e)
        all_alerts = []
    except ValueError as e:
        logger.error("Correlation: alerts.json failed validation (%s) -- running with no history", e)
        all_alerts = []

    current_ts = _parse_alert_timestamp(alert.timestamp)

    related = []

    for past in all_alerts:
        if past.event_id == alert.event_id:
            continue

        past_ts = _parse_alert_timestamp(past.timestamp)

        # Require valid timestamps so temporal relevance can be established.
        if current_ts is None or past_ts is None:
            continue

        time_delta_seconds = (current_ts - past_ts).total_seconds()
        
        if not 0 <= time_delta_seconds <= window_seconds:
            continue

        within_five_minutes = time_delta_seconds <= 5 * 60

        same_host = bool(
            alert.hostname
            and past.hostname
            and past.hostname.strip().lower() == alert.hostname.strip().lower()
        )
        
        same_ip = bool(
            alert.source_ip and past.source_ip == alert.source_ip
        )
        
        same_destination_ip = bool(
            alert.destination_ip
            and past.destination_ip
            and past.destination_ip == alert.destination_ip
        )
        same_user = bool(
            alert.actor_user and past.actor_user == alert.actor_user
        )
        same_technique = bool(
            alert.mitre_technique_id
            and past.mitre_technique_id == alert.mitre_technique_id
        )

        same_host_and_type_nearby = (
            same_host
            and past.alert_type == alert.alert_type
            and within_five_minutes
        )

        same_technique_same_host_nearby = (
            same_technique
            and same_host
            and within_five_minutes
        )

        if (
            same_host_and_type_nearby
            or (same_ip and within_five_minutes)
            or (same_destination_ip and within_five_minutes)
            or (same_user and within_five_minutes)
            or same_technique_same_host_nearby
        ):
            related.append(past.event_id)

    state.related_alerts = related
    state.correlated_alert_count = len(related)
    state.correlation_pattern = (
        f"{len(related)} related alert(s) in the last {window_seconds // 3600}h"
        if related else "No related alerts found"
    )

    state.audit_trail.append(f"[Correlation] {state.correlation_pattern}")
    logger.info("Correlation: %s -> %d related alert(s)", alert.event_id, len(related))
    return state


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

def decision_node(state: AgentState) -> AgentState:
    alert = state.alert
    llm = get_llm()
    mitre_context = ""
    has_mitre_technique = bool(alert.mitre_technique_id)
    state.degraded_context = False

    if has_mitre_technique:
        for attempt in (1, 2):
            try:
                mitre_retriever = get_retriever()
                results = mitre_retriever.retrieve_context(
                    f"{alert.mitre_technique_id} {alert.summary}", k=2
                )
                mitre_context = mitre_retriever.format_for_prompt(results)
                break
            except Exception as e:
                logger.warning(
                    "MITRE retrieval failed (attempt %d/2) for %s: %s", attempt, alert.event_id, e
                )
                if attempt == 2:
                    mitre_context = f"MITRE technique {alert.mitre_technique_id} (retrieval unavailable)"
                    state.degraded_context = True
                    state.audit_trail.append(
                        "[Decision] MITRE retrieval failed after retry -- proceeding with degraded_context=True"
                    )

    # --- LLM call: qualitative signal only, not the score ------------------
    prompt = f"""You are a senior SOC analyst reviewing a security alert for anything a
rule-based system would not catch in the raw fields.

Alert Information:
- Event ID: {alert.event_id}
- Type: {alert.alert_type}
- Severity: {alert.severity}
- Host: {alert.hostname}
- Summary: {alert.summary}
- User: {alert.actor_user or 'N/A'}
- Process: {alert.process_name or 'N/A'}
- Command Line: {alert.process_commandline or 'N/A'}

Context:
- Asset Criticality: {state.asset_criticality}
- Asset Owner: {state.asset_owner}
- Correlated alerts in last 24h: {state.correlated_alert_count}
- Triage note: {state.triage_reasoning}

{mitre_context}

Respond with ONLY a JSON object, no prose before or after it, in exactly
this shape (do not use comments or trailing commas):

{{
  "suspicion_modifier": <number between -0.10 and 0.10, where positive means MORE suspicious than the raw fields alone suggest, negative means LESS>,
  "mitre_techniques": [<list of MITRE technique ID strings, e.g. "T1059">],
  "reasoning": "<one to two sentences explaining the modifier>"
}}
"""

    default_modifier = 0.0
    default_reasoning = "LLM call failed or timed out; no qualitative modifier applied."
    default_techniques = [alert.mitre_technique_id] if has_mitre_technique else []

    try:
        response = call_llm_with_timeout(
            llm, prompt, event_id=alert.event_id, stage="decision"
        )
        result = parse_llm_json(
            getattr(response, "content", response),
            required_keys=["suspicion_modifier", "reasoning"],
        )
        llm_modifier = float(result.get("suspicion_modifier", 0.0))
        llm_reasoning = result.get("reasoning", "")
        
        # Fix: Prevent TypeError if LLM explicitly returns null for mitre_techniques
        mitre_techniques = result.get("mitre_techniques") or default_techniques
        
        # sanitize: only keep well-formed technique IDs
        from soc_demo.validation import validate_mitre_technique_id
        mitre_techniques = [t for t in mitre_techniques if validate_mitre_technique_id(t)]

    except (LLMTimeoutError, LLMParseError, Exception) as e:
        # Issue #9: previously defaulted confidence to an unexplained 0.5.
        # Now the LLM's contribution simply defaults to "no modifier" --
        # the deterministic components still produce a real, explainable
        # score, and the failure is visible in the audit trail rather than
        # hidden behind a plausible-looking number.
        logger.error("Decision LLM call/parse failed for %s: %s", alert.event_id, e)
        llm_modifier = default_modifier
        llm_reasoning = f"{default_reasoning} ({e})"
        mitre_techniques = default_techniques
        state.audit_trail.append(f"[Decision] LLM modifier unavailable: {e}")

    state.llm_confidence_modifier = llm_modifier
    state.llm_modifier_reasoning = llm_reasoning
    state.mitre_mapping = mitre_techniques

    # --- Deterministic scoring ---------------------------------------------
    breakdown = compute_confidence(
        asset_criticality=state.asset_criticality,
        severity=alert.severity,
        has_mitre_technique=has_mitre_technique,
        correlated_alert_count=state.correlated_alert_count,
        is_known_benign=state.is_known_benign,
        llm_modifier=llm_modifier,
        llm_modifier_reasoning=llm_reasoning,
    )
    state.confidence_score = breakdown.final_score
    state.score_breakdown = breakdown.as_dict()

    # --- Disposition, derived in code (Issue #2) ----------------------------
    action_types = {"auth", "process", "network", "file", "malware", "web"}
    remediation_available = state.routed_type in action_types
    required_fields_present = _required_action_fields_present(state)

    state.disposition = determine_disposition(
        state.confidence_score,
        remediation_available=remediation_available,
        required_action_fields_present=required_fields_present,
    )
    state.decision_reasoning = (
        f"Deterministic score {state.confidence_score:.2f} "
        f"(asset={breakdown.asset_component:.2f}, severity={breakdown.severity_component:.2f}, "
        f"mitre={breakdown.mitre_component:.2f}, correlation={breakdown.correlation_component:.2f}, "
        f"benign_penalty={breakdown.benign_penalty:.2f}, llm_modifier={breakdown.llm_modifier:.2f}). "
        f"LLM note: {llm_reasoning}"
    )

    state.audit_trail.append(
        f"[Decision] Confidence: {state.confidence_score:.2f}, "
        f"Disposition: {state.disposition}, "
        f"MITRE: {', '.join(state.mitre_mapping) if state.mitre_mapping else 'none'}"
    )
    logger.info(
        "Decision: %s -> %s (confidence=%.2f)",
        alert.event_id, state.disposition, state.confidence_score,
    )
    return state


def _required_action_fields_present(state: AgentState) -> bool:
    """Check whether the fields mitigation_node would need are valid, before promising an action."""
    alert = state.alert
    routed = state.routed_type
    if routed in ("auth",):
        return validate_ip(getattr(alert, "source_ip", None))
    if routed in ("network",):
        return validate_ip(getattr(alert, "destination_ip", None))
    if routed in ("process", "malware"):
        return bool(getattr(alert, "hostname", None))
    if routed in ("file",):
        return bool(getattr(alert, "hostname", None))
    if routed in ("web",):
        return validate_ip(getattr(alert, "destination_ip", None)) or bool(getattr(alert, "hostname", None))
    return False


# ---------------------------------------------------------------------------
# Mitigation
# ---------------------------------------------------------------------------

def mitigation_node(state: AgentState) -> AgentState:
    """
    Mitigation Agent: propose a remediation action.

    Fixes Issue #7: original action_map built params directly from
    possibly-None fields (e.g. alert.source_ip) and would only fail later,
    deep in the guardrail/action-execution layer, with a confusing error.
    This version validates required fields before proposing an action, and
    covers 'file'/'malware'/'web' alert types that were previously silently
    unhandled.
    """
    alert = state.alert

    if state.disposition != "action_recommended":
        state.audit_trail.append(f"[Mitigation] No action proposed (disposition: {state.disposition})")
        return state

    routed = state.routed_type
    action_name = None
    params = None

    if routed == "auth" and validate_ip(getattr(alert, "source_ip", None)):
        action_name, params = "block_ip", {"ip": alert.source_ip, "duration": "24h"}
    elif routed == "network" and validate_ip(getattr(alert, "destination_ip", None)):
        action_name, params = "block_ip", {"ip": alert.destination_ip, "duration": "24h"}
    elif routed in ("process", "malware") and getattr(alert, "hostname", None):
        action_name, params = "isolate_host", {"hostname": alert.hostname}
    elif routed == "file" and getattr(alert, "hostname", None):
        action_name, params = "quarantine_file", {
            "hostname": alert.hostname,
            "file_path": getattr(alert, "file_path", None),
        }
    elif routed == "web":
        if validate_ip(getattr(alert, "destination_ip", None)):
            action_name, params = "block_ip", {"ip": alert.destination_ip, "duration": "24h"}
        elif getattr(alert, "hostname", None):
            action_name, params = "isolate_host", {"hostname": alert.hostname}

    if not action_name:
        # Decision node's _required_action_fields_present should have
        # prevented this, but don't silently proceed if it happens anyway.
        state.disposition = "escalate"
        state.audit_trail.append(
            f"[Mitigation] Disposition was action_recommended but no valid action could be built "
            f"for type '{routed}' (missing/invalid required fields) -- downgraded to 'escalate'"
        )
        logger.warning("Mitigation: %s -> could not build action, downgraded to escalate", alert.event_id)
        return state

    state.proposed_action = action_name
    state.action_parameters = params

    from soc_demo.guardrail import GuardrailEngine
    engine = GuardrailEngine()
    state.action_tier = engine.classify_action_tier(action_name)

    state.audit_trail.append(
        f"[Mitigation] Proposed: {action_name} with params {params} (Tier {state.action_tier})"
    )
    logger.info("Mitigation: %s -> %s", alert.event_id, action_name)
    return state


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def reporting_node(state: AgentState) -> AgentState:
    """Reporting Agent: generate final case summary (Issue #13: log, don't print)."""
    alert = state.alert

    confidence_str = f"{state.confidence_score:.2f}" if state.confidence_score is not None else "N/A"
    mitre_str = ", ".join(state.mitre_mapping) if state.mitre_mapping else "None"

    summary = f"""
Case Summary for {alert.event_id}
{'=' * 60}

Alert Details:
- Type: {alert.alert_type}
- Severity: {alert.severity}
- Host: {alert.hostname}
- Summary: {alert.summary}

Analysis:
- Confidence Score: {confidence_str}
- Score Breakdown: {state.score_breakdown}
- Degraded Context: {state.degraded_context}
- Disposition: {state.disposition or 'Not determined'}
- MITRE Techniques: {mitre_str}

Decision Reasoning:
{state.decision_reasoning or 'No decision reasoning (auto-closed)'}

Proposed Action:
{state.proposed_action or 'None'} {state.action_parameters or ''}

Guardrail Decision:
{state.guardrail_decision or 'Not evaluated'}

Validation Warnings:
{state.validation_warnings or 'None'}

{'=' * 60}
"""

    state.audit_trail.append("[Reporting] Case summary generated")
    logger.info("Reporting: %s -> Case summary generated (disposition=%s)", alert.event_id, state.disposition)
    logger.info(summary)
    return state
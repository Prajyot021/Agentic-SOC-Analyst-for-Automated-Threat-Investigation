"""
Streamlit UI for the Agentic SOC Assistant.
Provides alert dashboard, agent reasoning viewer, and HITL approval interface.
"""

import html
import json
import os
import re
from datetime import datetime, timezone

import streamlit as st

# Initialize database first
from soc_demo.db import SessionLocal, Case, init_db
init_db()

from soc_demo.data_loader import load_alerts
from soc_demo.graph import run_alert_through_pipeline
from soc_demo.simulation_lab import show_simulation_lab


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Agentic SOC Assistant",
    page_icon=":material/shield:",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Design tokens + global styling
#
# One color language is used everywhere a status appears (severity, tier,
# disposition, guardrail decision, human decision) so a color always means
# the same risk level no matter which page it's on. Badges are light-tint
# background + saturated text (not solid fills) -- easier on the eyes for
# a screen an analyst is expected to stare at for a while, and the standard
# convention in real ops tooling (Linear, GitHub, Datadog) rather than an
# AI-generated-demo look.
# ---------------------------------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

/*
Colors here are intentionally the SAME values as .streamlit/config.toml's
[theme] block. config.toml themes Streamlit's native widgets (multiselect, inputs, dropdowns) -- CSS alone can't reach those reliably. This block only
adds what config.toml can't: badges, monospace treatment, card borders,
and spacing. Keep both files in sync if you change the palette.
*/
:root {
    --ink: #E6EDF3;
    --ink-muted: #9BA7B4;
    --ink-faint: #6E7681;
    --surface: #141922;
    --app-bg: #0B0E14;
    --border: #262C36;
    --accent: #4C8BF5;
    --accent-hover: #6FA0F7;

    --critical-bg: rgba(248, 81, 73, 0.15);  --critical-fg: #FF7B72;
    --high-bg: rgba(255, 159, 67, 0.15);     --high-fg: #FFA657;
    --medium-bg: rgba(227, 179, 65, 0.16);   --medium-fg: #E3B341;
    --low-bg: rgba(63, 185, 80, 0.15);       --low-fg: #56D364;
    --neutral-bg: rgba(139, 148, 158, 0.15); --neutral-fg: #9BA7B4;
    --info-bg: rgba(88, 166, 255, 0.15);     --info-fg: #79C0FF;
}

/* Base typography */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}
[data-testid="block-container"] { padding-top: 2rem; max-width: 1200px; }

h1, h2, h3 { font-weight: 600; letter-spacing: -0.01em; }
h1 { font-size: 1.5rem !important; }
h2 { font-size: 1.15rem !important; }
h3 { font-size: 1rem !important; }

/* Sidebar */
[data-testid="stSidebar"] { border-right: 1px solid var(--border); }

/* Cards (st.container(border=True)) */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-color: var(--border) !important;
    border-radius: 10px !important;
}

/* Buttons */
.stButton > button { border-radius: 6px; font-weight: 500; }
.stButton > button[kind="primary"]:hover {
    background-color: var(--accent-hover);
    border-color: var(--accent-hover);
}

/* Metrics */
[data-testid="stMetric"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.9rem 1rem;
}
[data-testid="stMetricLabel"] {
    color: var(--ink-muted);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

/* Tabs */
.stTabs [data-baseweb="tab"] { font-weight: 500; }

/* Expanders */
[data-testid="stExpander"] {
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
}

/* Badges */
.soc-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.18rem 0.65rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    white-space: nowrap;
}
.soc-mono {
    font-family: 'JetBrains Mono', 'SFMono-Regular', monospace;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--ink);
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
    font-size: 0.85em;
}
.soc-muted { color: var(--ink-muted); }
.soc-label {
    color: var(--ink-faint);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-weight: 600;
    margin-bottom: 0.15rem;
}
.soc-header-eyebrow {
    color: var(--ink-faint);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
    margin-bottom: 0.1rem;
}
.soc-status-row { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; }
.soc-status-item { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; color: var(--ink-muted); }
.soc-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Presentation helpers -- pure functions, no data/logic side effects.
# Centralizing the color mapping here is what keeps "critical" the same
# red everywhere it appears, instead of each page picking its own scheme.
# ---------------------------------------------------------------------------

_SEVERITY_STYLE = {
    "critical": ("critical-bg", "critical-fg"),
    "high": ("high-bg", "high-fg"),
    "medium": ("medium-bg", "medium-fg"),
    "low": ("low-bg", "low-fg"),
}

_DISPOSITION_STYLE = {
    "action_recommended": ("info-bg", "info-fg"),
    "escalate": ("medium-bg", "medium-fg"),
    "false_positive": ("neutral-bg", "neutral-fg"),
}

_TIER_STYLE = {
    1: ("low-bg", "low-fg"),
    2: ("medium-bg", "medium-fg"),
    3: ("critical-bg", "critical-fg"),
}

_GUARDRAIL_STYLE = {
    "auto_approve": ("low-bg", "low-fg"),
    "require_human_approval": ("medium-bg", "medium-fg"),
    "deny": ("critical-bg", "critical-fg"),
    "no_action_proposed": ("neutral-bg", "neutral-fg"),
}

_HUMAN_STYLE = {
    "approved": ("low-bg", "low-fg"),
    "rejected": ("critical-bg", "critical-fg"),
}


# Log fields (hostnames, event IDs, rule text, command lines) and LLM output derived
# from them are attacker-influenced. Everything rendered through
# unsafe_allow_html or markdown goes through these helpers so it cannot inject
# HTML (fake badges, hidden content) or markdown links/images (tracking beacons).
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-!|~<>])")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def md_text(value):
    """Escape a value for safe inline display in st.markdown (HTML or markdown)."""
    if value is None or value == "":
        return "N/A"
    return _MD_SPECIAL.sub(r"\\\1", html.escape(str(value), quote=False))


def md_block(value):
    """Like md_text, but keeps line breaks (for multi-line text)."""
    return md_text(value).replace("\n", "  \n")


def badge(value, style_map=None, label=None):
    """Render a small colored pill. Falls back to a neutral badge for
    unmapped/missing values instead of erroring or rendering blank."""
    text = label if label is not None else (value if value else "N/A")
    bg, fg = ("neutral-bg", "neutral-fg")
    if style_map and value in style_map:
        bg, fg = style_map[value]
    return (
        f'<span class="soc-badge" style="background:var(--{bg});color:var(--{fg});">'
        f'{md_text(text)}</span>'
    )


def severity_badge(value):
    return badge(value.lower() if value else None, _SEVERITY_STYLE, (value or "N/A").upper())


def mono(text):
    return f'<span class="soc-mono">{md_text(text)}</span>'


def status_dot(ok: bool) -> str:
    color = "var(--low-fg)" if ok else "var(--critical-fg)"
    return f'<span class="soc-dot" style="background:{color};"></span>'


# ---------------------------------------------------------------------------
# System health
# ---------------------------------------------------------------------------

def _normalize_url(value, default):
    url = (value or default).strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.replace("://0.0.0.0", "://localhost")


OLLAMA_URL = _normalize_url(os.getenv("OLLAMA_HOST"), "http://localhost:11434")
QDRANT_URL = _normalize_url(os.getenv("QDRANT_URL"), "http://localhost:6333")


# Cached for 10s so the UI isn't slowed down, but never permanently frozen.
# Returns (health, errors). Errors are returned instead of being drawn with
# st.sidebar.* inside the cached function, because Streamlit replays elements
# drawn inside cached functions, which is brittle.
@st.cache_data(ttl=10, show_spinner=False)
def check_system_health():
    """Check if all systems are reachable."""
    health = {'ollama': False, 'qdrant': False, 'alerts': False}
    errors = {}

    # Ollama: a cheap HTTP ping instead of a full LLM generation every 10s.
    # Falls back to the original LLM call in case get_llm() points elsewhere.
    try:
        import httpx
        httpx.get(f"{OLLAMA_URL}/api/tags", timeout=3.0).raise_for_status()
        health['ollama'] = True
    except Exception as ping_error:
        try:
            from soc_demo.llm_config import get_llm
            get_llm().invoke("ping")
            health['ollama'] = True
        except Exception as e:
            errors['ollama'] = (str(e) or str(ping_error))[:150]

    try:
        import httpx
        httpx.get(f"{QDRANT_URL}/collections", timeout=3.0).raise_for_status()
        health['qdrant'] = True
    except Exception as ping_error:
        try:
            from soc_demo.rag import get_retriever
            get_retriever()
            health['qdrant'] = True
        except Exception as e:
            errors['qdrant'] = (str(e) or str(ping_error))[:150]

    try:
        load_alerts()
        health['alerts'] = True
    except Exception as e:
        errors['alerts'] = str(e)[:150]

    return health, errors


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _norm(value):
    """Stable string form of a value, for comparing action parameters."""
    if value is None:
        return None
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except Exception:
        return str(value)


def _action_signature(action, params, guardrail):
    return (action, _norm(params), guardrail)


def tier_badge(tier):
    return badge(tier, _TIER_STYLE, f"Tier {tier}" if tier is not None else None)


def existing_event_ids():
    db = SessionLocal()
    try:
        return {row[0] for row in db.query(Case.event_id).all()}
    finally:
        db.close()


def get_or_create_case(alert, final_state):
    """Save or update a case in the database."""
    if not final_state:
        raise ValueError("The analysis pipeline returned no result.")

    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.event_id == alert.event_id).first()
        is_existing = case is not None

        if not case:
            case = Case(event_id=alert.event_id)
            db.add(case)

        old_signature = (
            _action_signature(case.proposed_action, case.action_parameters, case.guardrail_decision)
            if is_existing else None
        )

        # Descriptive fields are refreshed too, not only set on creation.
        case.alert_type = alert.alert_type
        case.severity = alert.severity
        case.hostname = alert.hostname
        case.summary = alert.summary

        case.confidence_score = final_state.get('confidence_score')
        case.score_breakdown = final_state.get('score_breakdown')
        case.disposition = final_state.get('disposition')
        case.mitre_mapping = final_state.get('mitre_mapping')
        case.decision_reasoning = final_state.get('decision_reasoning')
        case.degraded_context = final_state.get('degraded_context', False)
        case.correlated_alert_count = final_state.get('correlated_alert_count', 0)
        case.proposed_action = final_state.get('proposed_action')
        case.action_parameters = final_state.get('action_parameters')
        case.action_tier = final_state.get('action_tier')
        case.guardrail_decision = final_state.get('guardrail_decision')
        case.audit_trail = final_state.get('audit_trail')

        # A re-analysis that changes the proposed action invalidates any earlier
        # human decision. Otherwise an approval given for action A would silently
        # carry over to a different action B.
        new_signature = _action_signature(
            case.proposed_action, case.action_parameters, case.guardrail_decision
        )
        if is_existing and old_signature != new_signature:
            case.human_decision = None
            case.human_decision_timestamp = None
            case.human_decision_note = None

        db.commit()
        db.refresh(case)
        return case
    finally:
        db.close()


def _record_decision(case_id, decision, note="", expected=None):
    """Record an analyst decision exactly once.

    Returns (ok, message). Refuses if the case is gone, was already decided
    (e.g. double-click or second tab), or if the proposed action changed after
    the analyst's page was rendered (`expected` is the signature they saw).
    """
    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            return False, "This case no longer exists."
        if case.human_decision:
            return False, f"This case was already {case.human_decision}."
        if expected is not None and _action_signature(
            case.proposed_action, case.action_parameters, case.guardrail_decision
        ) != expected:
            return False, "The proposed action changed after this page loaded. Please review it again."

        # Conditional update keeps the "only once" rule even with concurrent clicks.
        updated = (
            db.query(Case)
            .filter(Case.id == case_id, Case.human_decision.is_(None))
            .update(
                {
                    "human_decision": decision,
                    "human_decision_timestamp": datetime.now(timezone.utc),
                    "human_decision_note": note,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        if not updated:
            return False, "This case was already decided."
        return True, ""
    finally:
        db.close()


def approve_action(case_id, note="", expected=None):
    return _record_decision(case_id, "approved", note, expected)


def reject_action(case_id, note="", expected=None):
    return _record_decision(case_id, "rejected", note, expected)


def _flash(kind, message):
    """Queue a message that survives st.rerun()."""
    st.session_state["flash"] = (kind, message)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    st.markdown('<div class="soc-header-eyebrow">Security Operations</div>', unsafe_allow_html=True)
    st.title("Agentic SOC Assistant")
    st.markdown('<p class="soc-muted" style="margin-top:-0.6rem;">AI-assisted triage, correlation, and response recommendations</p>', unsafe_allow_html=True)

    flash = st.session_state.pop("flash", None)
    if flash:
        st.toast(flash[1])

    health, health_errors = check_system_health()
    llm_ok = health['ollama']

    if not all(health.values()):
        with st.container(border=True):
            st.markdown(
                '<div class="soc-status-row">'
                f'<div class="soc-status-item">{status_dot(health["ollama"])} Ollama (LLM)</div>'
                f'<div class="soc-status-item">{status_dot(health["qdrant"])} Qdrant (MITRE RAG)</div>'
                f'<div class="soc-status-item">{status_dot(health["alerts"])} Alert data</div>'
                '</div>',
                unsafe_allow_html=True,
            )
            for name, message in health_errors.items():
                st.caption(f"{name}: {message}")
        if not llm_ok:
            # Reviewing cases and approvals needs no LLM, so don't hide the whole app.
            st.warning(
                "Ollama isn't responding. Start it with `ollama serve`, then reload this page. "
                "Alert analysis is disabled until then; Case Review and Approval Queue still work."
            )

    st.sidebar.markdown('<div class="soc-header-eyebrow">Navigate</div>', unsafe_allow_html=True)
    page = st.sidebar.radio(
        "Navigate", ["Alert Dashboard", "Simulation Lab", "Case Review", "Approval Queue", "System Status"],
        label_visibility="collapsed",
    )

    st.write("")

    if page == "Alert Dashboard":
        show_alert_dashboard(llm_ok)
    elif page == "Simulation Lab":
        if llm_ok:
            show_simulation_lab(lambda alert: get_or_create_case(alert, run_alert_through_pipeline(alert)))
        else:
            st.header("Simulation Lab")
            st.warning("The simulation lab needs the LLM to analyze alerts. Start Ollama and reload this page.")
    elif page == "Case Review":
        show_case_review()
    elif page == "Approval Queue":
        show_approval_queue()
    elif page == "System Status":
        show_system_status()


def show_alert_dashboard(llm_ok=True):
    st.header("Alert Dashboard")

    try:
        alerts = load_alerts()
    except Exception as e:
        st.error(f"Failed to load alerts: {e}")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.multiselect(
            "Severity", ["critical", "high", "medium", "low"], default=[]
        )
    with col2:
        type_filter = st.multiselect(
            "Alert type", sorted(set(a.alert_type for a in alerts)), default=[]
        )
    with col3:
        limit = st.number_input("Show alerts", min_value=5, max_value=50, value=10)

    filtered_alerts = [
        a for a in alerts
        if (not severity_filter or a.severity in severity_filter)
        and (not type_filter or a.alert_type in type_filter)
    ][:limit]

    st.markdown(
        f'<p class="soc-muted">Showing {len(filtered_alerts)} of {len(alerts)} alerts</p>',
        unsafe_allow_html=True,
    )

    # Result of the previous batch run (survives the st.rerun() below).
    batch = st.session_state.pop("dash_batch_result", None)
    if batch:
        if batch["ok"]:
            st.success(f"Processed {batch['ok']} alert(s)." + (f" Skipped {batch['skipped']} that already had a case." if batch["skipped"] else ""))
        elif batch["skipped"] and not batch["failed"]:
            st.info(f"Nothing to do: all {batch['skipped']} visible alert(s) already have a case.")
        if batch["failed"]:
            st.error("Some alerts failed:\n\n" + "\n".join(f"- {md_text(f)}" for f in batch["failed"]))

    skip_existing = st.checkbox(
        "Skip alerts that already have a case", value=True,
        help="Re-analysis re-runs the LLM and can change the proposed action.",
    )

    if st.button(
        "Process all visible alerts", type="primary", icon=":material/play_arrow:",
        disabled=(not llm_ok) or (not filtered_alerts),
    ):
        done_ids = existing_event_ids() if skip_existing else set()
        to_run = [a for a in filtered_alerts if a.event_id not in done_ids]
        result = {"ok": 0, "skipped": len(filtered_alerts) - len(to_run), "failed": []}

        progress_bar = st.progress(0)
        status_text = st.empty()
        for i, alert in enumerate(to_run):
            status_text.markdown(
                f'<span class="soc-muted">Processing {i + 1}/{len(to_run)} — {mono(alert.event_id)}</span>',
                unsafe_allow_html=True,
            )
            try:
                final_state = run_alert_through_pipeline(alert)
                get_or_create_case(alert, final_state)
                result["ok"] += 1
            except Exception as e:
                result["failed"].append(f"{alert.event_id}: {e}")
            progress_bar.progress((i + 1) / len(to_run))

        st.session_state["dash_batch_result"] = result
        st.rerun()

    st.write("")

    for idx, alert in enumerate(filtered_alerts):
        with st.container(border=True):
            top = st.columns([5, 2, 2, 2])
            with top[0]:
                st.markdown(f"**{md_text((alert.summary or '')[:90])}**")
                st.markdown(mono(alert.event_id), unsafe_allow_html=True)
            with top[1]:
                st.markdown(severity_badge(alert.severity), unsafe_allow_html=True)
            with top[2]:
                st.markdown(f'<span class="soc-muted">{md_text(alert.alert_type)}</span>', unsafe_allow_html=True)
            with top[3]:
                st.markdown(f'<span class="soc-muted">{md_text(alert.hostname)}</span>', unsafe_allow_html=True)

            with st.expander("Details", icon=":material/expand_more:"):
                dcol1, dcol2 = st.columns([2, 1])
                with dcol1:
                    st.markdown(f"**User**  \n{md_text(alert.actor_user)}")
                    st.markdown(f"**MITRE technique**  \n{md_text(alert.mitre_technique_id)}")
                with dcol2:
                    st.markdown("**Summary**")
                    st.info(md_block(alert.summary))

                if st.button("Analyze", key=f"analyze_{idx}", icon=":material/search:", disabled=not llm_ok):
                    with st.spinner("Running agent analysis..."):
                        try:
                            final_state = run_alert_through_pipeline(alert)
                            get_or_create_case(alert, final_state)
                            st.success("Analysis complete — view it in Case Review.")
                        except Exception as e:
                            st.error(f"Analysis failed: {e}")


def show_case_review():
    st.header("Case Review")

    db = SessionLocal()
    try:
        cases = db.query(Case).order_by(Case.created_at.desc()).all()
    finally:
        db.close()

    if not cases:
        st.info("No cases yet. Process alerts from the Alert Dashboard.")
        return

    # Keyed by case id, so two cases with the same event ID / summary never collapse into one entry.
    labels = {c.id: f"#{c.id} · {c.event_id} — {(c.summary or '')[:50]}" for c in cases}
    case_id = st.selectbox("Select case", list(labels.keys()), format_func=labels.get)

    if case_id is None:
        return

    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == case_id).first()
    finally:
        db.close()

    if not case:
        return

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="soc-label">Severity</div>', unsafe_allow_html=True)
        st.markdown(severity_badge(case.severity), unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="soc-label">Confidence</div>', unsafe_allow_html=True)
        st.markdown(
            f"**{case.confidence_score:.2f}**" if case.confidence_score is not None else "N/A"
        )
    with col3:
        st.markdown('<div class="soc-label">Disposition</div>', unsafe_allow_html=True)
        st.markdown(
            badge(case.disposition, _DISPOSITION_STYLE, (case.disposition or "N/A").replace("_", " ")),
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown('<div class="soc-label">Guardrail</div>', unsafe_allow_html=True)
        st.markdown(
            badge(case.guardrail_decision, _GUARDRAIL_STYLE,
                  (case.guardrail_decision or "N/A").replace("_", " ")),
            unsafe_allow_html=True,
        )

    st.write("")
    tab1, tab2, tab3, tab4 = st.tabs(["Summary", "Agent analysis", "Proposed action", "Audit trail"])

    with tab1:
        st.markdown(f"**Event ID**  \n{mono(case.event_id)}", unsafe_allow_html=True)
        st.markdown(f"**Type**  \n{md_text(case.alert_type)}")
        st.markdown(f"**Host**  \n{mono(case.hostname)}", unsafe_allow_html=True)
        st.markdown(f"**Summary**  \n{md_text(case.summary)}")

    with tab2:
        st.subheader("Decision reasoning")
        # Reasoning is LLM output derived from attacker-influenced log data, so it is
        # shown as plain text (no links, images or HTML).
        st.markdown(md_block(case.decision_reasoning) if case.decision_reasoning else "No reasoning available")

        if case.degraded_context:
            st.warning("MITRE context retrieval failed for this case — the decision was made without it.")

        if case.score_breakdown:
            st.subheader("Confidence score breakdown")
            st.json(case.score_breakdown)

        st.markdown(f"**Correlated alerts**  \n{case.correlated_alert_count or 0}")

        if case.mitre_mapping:
            st.subheader("MITRE ATT&CK techniques")
            techniques = case.mitre_mapping if isinstance(case.mitre_mapping, (list, tuple)) else [case.mitre_mapping]
            for technique in techniques:
                tid = str(technique).strip().upper()
                if _TECHNIQUE_RE.match(tid):
                    st.markdown(f"- [{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')})")
                else:
                    st.markdown(f"- {md_text(technique)}")

    with tab3:
        if case.proposed_action:
            st.subheader(md_text(case.proposed_action))
            st.markdown(f"**Tier**  \n{tier_badge(case.action_tier)}", unsafe_allow_html=True)
            st.markdown(f"**Parameters**  \n{mono(case.action_parameters)}", unsafe_allow_html=True)
            st.markdown(f"**Guardrail decision**  \n{badge(case.guardrail_decision, _GUARDRAIL_STYLE, (case.guardrail_decision or 'N/A').replace('_', ' '))}", unsafe_allow_html=True)

            if case.human_decision:
                if case.human_decision == "approved":
                    st.success(f"Approved by analyst at {case.human_decision_timestamp} UTC")
                else:
                    st.error(f"Rejected by analyst at {case.human_decision_timestamp} UTC")
                if case.human_decision_note:
                    st.info(f"Note: {md_text(case.human_decision_note)}")
        else:
            st.info("No action proposed for this case.")

    with tab4:
        st.subheader("Agent execution trace")
        if case.audit_trail:
            trail = case.audit_trail if isinstance(case.audit_trail, (list, tuple)) else [case.audit_trail]
            # st.code shows entries verbatim: nothing in a log line can be rendered as HTML.
            st.code("\n".join(str(entry) for entry in trail), language="text")
        else:
            st.info("No audit trail available")


def show_approval_queue():
    st.header("Approval Queue")

    db = SessionLocal()
    try:
        pending_cases = db.query(Case).filter(
            Case.guardrail_decision == 'require_human_approval',
            Case.human_decision.is_(None)
        ).order_by(Case.created_at).all()
    finally:
        db.close()

    if not pending_cases:
        st.success("No pending approvals.")
        return

    # Most severe first (sort is stable, so oldest-first within a severity).
    pending_cases.sort(key=lambda c: -_SEVERITY_RANK.get(str(c.severity or "").lower(), 0))

    st.markdown(
        f'<p class="soc-muted">{len(pending_cases)} action(s) awaiting approval</p>',
        unsafe_allow_html=True,
    )

    for case in pending_cases:
        # What the analyst is looking at right now; the decision is refused if it changes.
        expected = _action_signature(case.proposed_action, case.action_parameters, case.guardrail_decision)

        with st.container(border=True):
            header_cols = st.columns([4, 1])
            with header_cols[0]:
                st.markdown(f"**{mono(case.event_id)}**", unsafe_allow_html=True)
            with header_cols[1]:
                st.markdown(severity_badge(case.severity), unsafe_allow_html=True)

            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown(f"**Alert**  \n{md_text(case.summary)}")
                confidence_str = f"{case.confidence_score:.2f}" if case.confidence_score is not None else "N/A"
                st.markdown(f"**Confidence**  \n{confidence_str}")
                st.markdown(
                    f"**Proposed action**  \n{mono(case.proposed_action)} &nbsp; "
                    f"{tier_badge(case.action_tier)}",
                    unsafe_allow_html=True,
                )
                st.markdown(f"**Parameters**  \n{mono(case.action_parameters)}", unsafe_allow_html=True)

                if case.degraded_context:
                    st.warning("MITRE context retrieval failed for this case — review the reasoning carefully.")

                with st.expander("View reasoning", icon=":material/expand_more:"):
                    st.markdown(md_block(case.decision_reasoning))

            with col2:
                note = st.text_area("Note (optional)", key=f"note_{case.id}", height=80)

                # Extra friction for the highest-impact tier.
                confirmed = True
                if case.action_tier == 3:
                    confirmed = st.checkbox(
                        "I understand this is a Tier 3 (high-impact) action",
                        key=f"confirm_{case.id}",
                    )

                col_a, col_b = st.columns(2)
                with col_a:
                    if st.button("Approve", key=f"approve_{case.id}", type="primary",
                                 icon=":material/check:", disabled=not confirmed):
                        ok, message = approve_action(case.id, note, expected)
                        _flash("success" if ok else "error",
                               f"Approved {case.event_id}." if ok else message)
                        st.rerun()
                with col_b:
                    if st.button("Reject", key=f"reject_{case.id}", icon=":material/close:"):
                        ok, message = reject_action(case.id, note, expected)
                        _flash("success" if ok else "error",
                               f"Rejected {case.event_id}." if ok else message)
                        st.rerun()


def show_system_status():
    st.header("System Status")

    db = SessionLocal()
    try:
        total_cases = db.query(Case).count()
        pending_approvals = db.query(Case).filter(
            Case.guardrail_decision == 'require_human_approval',
            Case.human_decision.is_(None)
        ).count()
        approved_count = db.query(Case).filter(Case.human_decision == 'approved').count()
        rejected_count = db.query(Case).filter(Case.human_decision == 'rejected').count()
    finally:
        db.close()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total cases", total_cases)
    col2.metric("Pending approvals", pending_approvals)
    col3.metric("Approved", approved_count)
    col4.metric("Rejected", rejected_count)

    st.write("")
    header_col, button_col = st.columns([4, 1])
    header_col.subheader("Component status")
    if button_col.button("Re-check", icon=":material/refresh:"):
        check_system_health.clear()
        st.rerun()

    # Same (cached) check as the banner, so the two can never disagree, and a
    # component is only "connected" if it actually answered.
    health, errors = check_system_health()

    with st.container(border=True):
        if health['qdrant']:
            st.markdown(f'{status_dot(True)} **Qdrant (MITRE RAG)** — connected', unsafe_allow_html=True)
        else:
            st.markdown(f'{status_dot(False)} **Qdrant (MITRE RAG)** — {md_text(errors.get("qdrant", "unreachable"))}', unsafe_allow_html=True)

        if health['ollama']:
            st.markdown(f'{status_dot(True)} **Ollama (LLM)** — connected', unsafe_allow_html=True)
        else:
            st.markdown(f'{status_dot(False)} **Ollama (LLM)** — {md_text(errors.get("ollama", "unreachable"))}', unsafe_allow_html=True)

        if health['alerts']:
            try:
                count = len(load_alerts())
                st.markdown(f'{status_dot(True)} **Alert data** — {count} alerts loaded', unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'{status_dot(False)} **Alert data** — {md_text(e)}', unsafe_allow_html=True)
        else:
            st.markdown(f'{status_dot(False)} **Alert data** — {md_text(errors.get("alerts", "unavailable"))}', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
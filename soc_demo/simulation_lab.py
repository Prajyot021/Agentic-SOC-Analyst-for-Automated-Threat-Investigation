"""Streamlit Simulation Lab for approved Atomic Red Team tests on target-win10."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import streamlit as st

try:  # Imported once at module level; a missing package is reported in the UI.
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

from soc_demo.wazuh_converter import WazuhConverter

TARGET_AGENT_NAME = "target-win10"
TARGET_AGENT_ID = "002"
DEFAULT_VM_URL = "http://192.168.220.129:8765"
DEFAULT_WAZUH_CONTAINER = "single-node-wazuh.manager-1"
WAZUH_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"

# Detection tuning
CLOCK_SKEW_MARGIN = timedelta(seconds=2)  # absorbs host / manager clock differences
DETECTION_WAIT_SECONDS = 120              # max wait after a fresh run
RECHECK_WAIT_SECONDS = 45                 # max wait for "Check Wazuh again"
POLL_INTERVAL_SECONDS = 5
SETTLE_SECONDS = 10                       # keep collecting after the first relevant alert
MAX_ALERTS_TO_PROCESS = 5

SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# "indicators" are lowercase substrings looked for in process name, command line
# and raw log. They are used (together with the MITRE ID) to decide whether an
# alert was caused by the simulation or is unrelated background noise.
SIMULATIONS = {
    "T1082 — System Information Discovery": {
        "technique": "T1082",
        "indicators": ["systeminfo"],
        "description": "Runs a predefined system-information discovery test in the Windows 10 lab VM.",
        "risk": "Low-impact discovery activity; run only in your isolated lab VM.",
    },
    "T1057 — Process Discovery": {
        "technique": "T1057",
        "indicators": ["tasklist", "get-process", "wmic process"],
        "description": "Runs a predefined process-discovery test in the Windows 10 lab VM.",
        "risk": "Low-impact discovery activity; run only in your isolated lab VM.",
    },
    "T1016 — System Network Configuration Discovery": {
        "technique": "T1016",
        "indicators": ["ipconfig", "netsh", "arp -a", "route print"],
        "description": "Discovers network configuration on the Windows lab VM.",
        "risk": "Discovery activity; run only in your isolated lab VM.",
    },
    "T1033 — System Owner/User Discovery": {
        "technique": "T1033",
        "indicators": ["whoami", "quser", "query user"],
        "description": "Discovers information about the current user.",
        "risk": "Discovery activity; run only in your isolated lab VM.",
    },
    "T1083 — File and Directory Discovery": {
        "technique": "T1083",
        "indicators": ["dir /s", "tree /f", "get-childitem"],
        "description": "Runs a predefined file and directory discovery test.",
        "risk": "May enumerate files and directories; run only in your isolated lab VM.",
    },
    "T1518.001 — Security Software Discovery": {
        "technique": "T1518.001",
        "indicators": ["securitycenter", "advfirewall", "antivirusproduct", "get-mppreference", "virus"],
        "description": "Checks for installed security software.",
        "risk": "Discovery activity; run only in your isolated lab VM.",
    },
    "T1124 — System Time Discovery": {
        "technique": "T1124",
        "indicators": ["net time", "w32tm", "get-date"],
        "description": "Discovers system time information.",
        "risk": "Discovery activity; run only in your isolated lab VM.",
    },
    "T1012 — Query Registry": {
        "technique": "T1012",
        "indicators": ["reg query", "reg.exe query", "get-itemproperty"],
        "description": "Runs a predefined Windows Registry query test.",
        "risk": "Registry discovery; run only in your isolated lab VM.",
    },
    "T1059.001 — PowerShell Execution": {
        "technique": "T1059.001",
        "indicators": ["powershell"],
        "description": "Runs a predefined PowerShell execution test.",
        "risk": "Executes commands on the target VM; run only in your isolated lab VM.",
    },
    "T1059.003 — Windows Command Shell": {
        "technique": "T1059.003",
        "indicators": ["cmd.exe", "cmd /c"],
        "description": "Runs a predefined Windows command-shell test.",
        "risk": "Executes commands on the target VM; run only in your isolated lab VM.",
    },
}


class DockerUnavailableError(RuntimeError):
    """Docker or the Wazuh container cannot be reached; retrying will not help."""


# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------
def _parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO-8601 timestamps, including Wazuh's '+0000' offset style.

    datetime.fromisoformat() only accepts offsets without a colon from
    Python 3.11 onward, so the offset is normalised first.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    # +0000 -> +00:00
    candidate = re.sub(r"(?<=\d)([+-]\d{2})(\d{2})$", r"\1:\2", candidate)
    # Trim fractional seconds to 6 digits (older fromisoformat rejects more)
    candidate = re.sub(r"(\.\d{6})\d+", r"\1", candidate)
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Wazuh access
# --------------------------------------------------------------------------
def _read_recent_wazuh_alerts(container: str, lines: int = 3000) -> list[dict[str, Any]]:
    """Read recent alert NDJSON from the local Dockerized Wazuh manager."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "tail", "-n", str(lines), WAZUH_ALERTS_PATH],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerUnavailableError(
            "The 'docker' command was not found. Install Docker or add it to PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Timed out reading Wazuh alerts via docker exec.") from exc

    if result.returncode != 0:
        message = result.stderr.strip() or f"docker exec exited with code {result.returncode}"
        if "no such container" in message.lower() or "is not running" in message.lower():
            raise DockerUnavailableError(message)
        raise RuntimeError(message)

    records: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _is_target_agent(raw: dict[str, Any]) -> bool:
    agent = raw.get("agent") or {}
    return (
        str(agent.get("id", "")).strip() == TARGET_AGENT_ID
        or str(agent.get("name", "")).strip().lower() == TARGET_AGENT_NAME
    )


def _fresh_target_alerts(started_at: datetime, container: str) -> list[Any]:
    """Return converted alerts from the target agent newer than started_at,
    sorted by their real (parsed) event time."""
    converter = WazuhConverter()
    fresh: list[tuple[datetime, Any]] = []
    seen: set[str] = set()
    for raw in _read_recent_wazuh_alerts(container):
        if not _is_target_agent(raw):
            continue
        event_time = _parse_timestamp(raw.get("timestamp"))
        if event_time is None or event_time < started_at:
            continue
        raw_id = str(raw.get("id") or raw.get("_id") or "")
        if raw_id and raw_id in seen:
            continue
        converted = converter.convert_alert(raw)
        if converted is None:
            continue
        if raw_id:
            seen.add(raw_id)
        fresh.append((event_time, converted))
    fresh.sort(key=lambda pair: pair[0])
    return [alert for _, alert in fresh]


def _is_relevant(alert: Any, technique: str, indicators: list[str]) -> bool:
    """True if the alert plausibly resulted from the simulated technique."""
    mitre = str(getattr(alert, "mitre_technique_id", "") or "").upper()
    if mitre and mitre.split(".")[0] == technique.split(".")[0].upper():
        return True
    blob = " ".join(
        str(getattr(alert, field, "") or "")
        for field in ("process_name", "process_commandline", "raw_log")
    ).lower()
    return any(ind in blob for ind in indicators)


def _priority_key(alert: Any) -> tuple[int, str]:
    severity = str(getattr(alert, "severity", "") or "").lower()
    # Highest severity first, then earliest time
    return (-SEVERITY_RANK.get(severity, 0), str(getattr(alert, "timestamp", "")))


# --------------------------------------------------------------------------
# Small UI / settings helpers
# --------------------------------------------------------------------------
def _get_setting(name: str, default: str = "") -> str:
    value = os.getenv(name, "").strip()
    return value if value else default


def _show_table(rows: list[dict[str, Any]]) -> None:
    try:
        st.dataframe(rows, width="stretch", hide_index=True)
    except TypeError:  # older Streamlit
        st.dataframe(rows, use_container_width=True, hide_index=True)


def _primary_button(label: str, **kwargs: Any) -> bool:
    try:
        return st.button(label, type="primary", icon=":material/play_arrow:", **kwargs)
    except TypeError:  # older Streamlit without icon=
        return st.button(label, type="primary", **kwargs)


def _alert_rows(alerts: list[Any], relevant_ids: set[str] | None = None) -> list[dict[str, Any]]:
    rows = []
    for alert in alerts:
        row = {
            "Event ID": getattr(alert, "event_id", ""),
            "Time": getattr(alert, "timestamp", ""),
            "Host": getattr(alert, "hostname", ""),
            "Severity": getattr(alert, "severity", ""),
            "Type": getattr(alert, "alert_type", ""),
            "Summary": getattr(alert, "summary", ""),
        }
        if relevant_ids is not None:
            row["Matches test"] = "yes" if getattr(alert, "event_id", "") in relevant_ids else "no"
        rows.append(row)
    return rows


def _process_alerts(process_alert, alerts: list[Any]) -> tuple[list[Any], list[str]]:
    """Run alerts through the SOC workflow, skipping ones already processed."""
    done: set[str] = st.session_state.setdefault("simlab_processed_ids", set())
    processed: list[Any] = []
    errors: list[str] = []
    for alert in alerts:
        event_id = str(getattr(alert, "event_id", ""))
        if event_id and event_id in done:
            continue
        try:
            process_alert(alert)
        except Exception as exc:
            errors.append(f"{event_id or 'unknown'}: {exc}")
            continue
        processed.append(alert)
        if event_id:
            done.add(event_id)
    return processed, errors


# --------------------------------------------------------------------------
# Detection phase (runs after a simulation, or on demand via "Check again")
# --------------------------------------------------------------------------
def _detect_and_process(process_alert, run: dict[str, Any], container: str, max_wait: int) -> None:
    started_at = datetime.fromisoformat(run["started_at"])
    technique = run["technique"]
    indicators = run["indicators"]

    progress = st.progress(0)
    status = st.empty()
    status.info(f"Waiting for new Wazuh alerts from {TARGET_AGENT_NAME} matching {technique}…")

    found: list[Any] = []
    last_error: str | None = None
    first_relevant_at: float | None = None
    begin = time.monotonic()
    deadline = begin + max_wait

    while True:
        try:
            found = _fresh_target_alerts(started_at, container)
            last_error = None
        except DockerUnavailableError as exc:
            progress.empty()
            status.error(f"The test ran, but Wazuh logs cannot be queried: {exc}")
            return
        except Exception as exc:
            last_error = str(exc)

        now = time.monotonic()
        if first_relevant_at is None and any(_is_relevant(a, technique, indicators) for a in found):
            first_relevant_at = now
            status.info("Relevant alert detected. Collecting related alerts…")

        # Stop once relevant alerts have had time to "settle", or on timeout.
        if first_relevant_at is not None and now - first_relevant_at >= SETTLE_SECONDS:
            break
        if now >= deadline:
            break

        progress.progress(min(0.9, 0.1 + (now - begin) / max_wait * 0.8))
        time.sleep(min(POLL_INTERVAL_SECONDS, max(0.0, deadline - now)))

    if last_error and not found:
        progress.empty()
        status.warning(f"The test ran, but Wazuh logs could not be queried: {last_error}")
        st.info("The simulation and detection are separate outcomes. Check Docker access and the Wazuh manager container name.")
        return

    relevant = sorted(
        (a for a in found if _is_relevant(a, technique, indicators)), key=_priority_key
    )
    unrelated = [a for a in found if a not in relevant]

    if not relevant:
        progress.progress(1.0)
        if not found:
            status.warning(
                f"No new alert from {TARGET_AGENT_NAME} was found in Wazuh within {max_wait} seconds."
            )
            st.write(
                "This does not prove the runner failed. The relevant Windows telemetry or "
                "Wazuh detection rule may not be enabled for this test, or detection may "
                "just be slow. You can use **Check Wazuh again** below."
            )
            st.session_state.pop("simlab_unverified", None)
        else:
            status.warning(
                f"{len(found)} new alert(s) arrived from {TARGET_AGENT_NAME}, but none match "
                f"{technique} by MITRE ID or command-line indicators. They may be unrelated "
                "background activity, so they were NOT processed automatically."
            )
            _show_table(_alert_rows(found, set()))
            st.session_state["simlab_unverified"] = found[:MAX_ALERTS_TO_PROCESS]
        return

    st.session_state.pop("simlab_unverified", None)
    to_process = relevant[:MAX_ALERTS_TO_PROCESS]
    status.success(
        f"Found {len(relevant)} alert(s) matching {technique}. Processing up to "
        f"{len(to_process)} through the SOC workflow…"
    )
    processed, errors = _process_alerts(process_alert, to_process)
    progress.progress(1.0)

    if processed:
        st.success(
            f"Processed {len(processed)} newly detected alert(s). "
            "Open Case Review to inspect agent analysis and the audit trail."
        )
        _show_table(_alert_rows(processed))
    elif not errors:
        st.info("These alerts were already processed earlier. Open Case Review to inspect them.")
    if len(relevant) > len(to_process):
        st.caption(f"{len(relevant) - len(to_process)} additional matching alert(s) were not processed (limit {MAX_ALERTS_TO_PROCESS}).")
    if unrelated:
        st.caption(f"{len(unrelated)} unrelated alert(s) from the same agent were ignored.")
    if errors:
        st.error("Some alerts could not be processed:\n\n" + "\n".join(errors))


# --------------------------------------------------------------------------
# Simulation phase
# --------------------------------------------------------------------------
def _run_simulation(chosen: dict[str, Any], chosen_label: str, vm_url: str, token: str) -> dict[str, Any] | None:
    """Ask the VM runner to execute the test. Returns the run record, or None on failure."""
    if requests is None:
        st.error(
            "The Python 'requests' package is missing. Install it in the project's "
            "active virtual environment: python -m pip install requests"
        )
        return None
    if not token:
        st.error("Simulation token is not configured. Set SOC_SIMULATION_AGENT_TOKEN on the host and VM before starting a test.")
        return None

    started_at = datetime.now(timezone.utc) - CLOCK_SKEW_MARGIN
    run_record = {
        "started_at": started_at.isoformat(),
        "technique": chosen["technique"],
        "indicators": chosen.get("indicators", []),
        "label": chosen_label,
        "run_id": None,
        "output": "",
    }

    status = st.empty()
    status.info("Contacting the Windows 10 simulation agent…")
    try:
        response = requests.post(
            f"{vm_url}/run",
            json={"test_id": chosen["technique"]},
            headers={
                "X-Simulation-Token": token.strip(),
                "Accept": "application/json",
            },
            # Fail quickly if the host cannot connect; allow time for the
            # approved test itself to finish on the VM.
            timeout=(5, 180),
        )

        def _body() -> str:
            text = (response.text or "").strip().replace("\r", " ").replace("\n", " ")
            return text[:500] if text else "<empty response body>"

        if not response.ok:
            raise RuntimeError(f"Simulation runner returned HTTP {response.status_code}: {_body()}")

        try:
            run_result = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Runner returned HTTP {response.status_code}, but its response was not valid JSON: {_body()}"
            ) from exc

        if not isinstance(run_result, dict):
            raise RuntimeError(
                f"Runner returned JSON of type {type(run_result).__name__}; expected a JSON object."
            )
        if not run_result.get("ok"):
            raise RuntimeError(
                str(run_result.get("error") or "The VM runner reported a failed test.")
            )

        actual_target = str(run_result.get("target", "")).strip().lower()
        if actual_target != TARGET_AGENT_NAME:
            raise RuntimeError(
                f"Runner reported target '{actual_target or 'unknown'}', expected "
                f"'{TARGET_AGENT_NAME}'. No Wazuh alerts will be processed."
            )

    except requests.exceptions.ConnectTimeout as exc:
        status.error(
            f"Timed out connecting to the simulation runner at {vm_url}. "
            "Verify the VM IP, port 8765 listener, and host-only network."
        )
        st.caption(f"Diagnostic detail: {type(exc).__name__}: {exc}")
        return None
    except requests.exceptions.ReadTimeout as exc:
        # The test may well have executed, so keep the run for a Wazuh re-check.
        status.warning(
            "The simulation runner accepted the connection but did not return a response "
            "within 180 seconds. The test may still have run: check the VM runner terminal, "
            "then use **Check Wazuh again** below."
        )
        st.caption(f"Diagnostic detail: {type(exc).__name__}: {exc}")
        run_record["output"] = "Runner response timed out; result unknown."
        return run_record
    except requests.exceptions.ConnectionError as exc:
        status.error(
            "The TCP port may be reachable, but the HTTP connection to the simulation "
            "runner was closed or reset. Check the VM runner terminal while clicking "
            "Start simulation, and verify that it handles POST /run and returns an HTTP response."
        )
        st.caption(f"Diagnostic detail: {type(exc).__name__}: {exc}")
        return None
    except Exception as exc:
        status.error(f"Could not start or verify the test on {TARGET_AGENT_NAME}: {exc}")
        st.caption(
            f"Runner URL: {vm_url}. Confirm the runner is running, the shared token "
            "matches on the host and VM, and the runner returns JSON containing "
            "'ok' and 'target'. The token is not displayed or logged."
        )
        return None

    run_record["run_id"] = run_result.get("run_id")
    run_record["output"] = str(run_result.get("output", "No output returned."))[-5000:]
    status.empty()
    st.success(
        f"Test command completed on {TARGET_AGENT_NAME}. "
        f"Run ID: {run_result.get('run_id', 'not provided')}"
    )
    with st.expander("Simulation execution output", expanded=False):
        st.code(run_record["output"])
    return run_record


# --------------------------------------------------------------------------
# Page
# --------------------------------------------------------------------------
def show_simulation_lab(process_alert) -> None:
    st.header("Simulation Lab")
    st.caption("Launch an allow-listed Atomic Red Team test on the isolated Windows 10 VM, then look for the resulting Wazuh alert and process it through the existing SOC workflow.")

    vm_url = _get_setting("SOC_SIMULATION_AGENT_URL", DEFAULT_VM_URL).rstrip("/")
    token = _get_setting("SOC_SIMULATION_AGENT_TOKEN")
    container = _get_setting("WAZUH_MANAGER_CONTAINER", DEFAULT_WAZUH_CONTAINER)

    col1, col2, col3 = st.columns(3)
    col1.metric("Target agent", TARGET_AGENT_NAME)
    col2.metric("Wazuh agent ID", TARGET_AGENT_ID)
    col3.metric("Simulation mode", "Allow-listed tests")

    st.info("Only the predefined tests below can be started. This page does not accept arbitrary shell commands.")

    chosen_label = st.selectbox("Select simulation", list(SIMULATIONS.keys()))
    chosen = SIMULATIONS[chosen_label]
    st.write(chosen["description"])
    st.caption(chosen["risk"])

    with st.expander("Connection settings", expanded=False):
        st.code(f"Simulation agent: {vm_url}\nWazuh container: {container}\nTarget: {TARGET_AGENT_NAME} (ID {TARGET_AGENT_ID})")
        st.caption("The shared token is read from SOC_SIMULATION_AGENT_TOKEN and is never displayed.")

    left, right = st.columns([1, 2])
    with left:
        confirmed = st.checkbox("I confirm the target is my isolated Windows 10 lab VM.", key="simlab_confirm_target")
    with right:
        st.caption("Keep the VM on your lab/host-only network. Do not expose the simulation endpoint to the public internet.")

    if _primary_button("Start simulation", disabled=not confirmed, key="simlab_start"):
        # New run: reset state tied to the previous one.
        st.session_state.pop("simlab_unverified", None)
        run_record = _run_simulation(chosen, chosen_label, vm_url, token)
        if run_record is not None:
            st.session_state["simlab_last_run"] = run_record
            _detect_and_process(process_alert, run_record, container, DETECTION_WAIT_SECONDS)

    # ---- Re-check / unverified alert handling (survives Streamlit reruns) ----
    last_run = st.session_state.get("simlab_last_run")
    if last_run:
        st.divider()
        st.subheader("Last simulation run")
        st.caption(
            f"{last_run['label']} · started {last_run['started_at']} · "
            f"Run ID: {last_run.get('run_id') or 'not provided'}"
        )
        if st.button("Check Wazuh again", key="simlab_recheck"):
            _detect_and_process(process_alert, last_run, container, RECHECK_WAIT_SECONDS)

    unverified = st.session_state.get("simlab_unverified")
    if unverified:
        st.warning(
            f"{len(unverified)} unverified alert(s) from {TARGET_AGENT_NAME} are waiting. "
            "They did not match the selected technique and may be unrelated."
        )
        if st.button("Process unverified alerts anyway", key="simlab_process_unverified"):
            processed, errors = _process_alerts(process_alert, unverified)
            if processed:
                st.success(f"Processed {len(processed)} alert(s). Treat them as unverified in your case notes.")
                _show_table(_alert_rows(processed, set()))
                st.session_state.pop("simlab_unverified", None)
            elif not errors:
                st.info("These alerts were already processed.")
            if errors:
                st.error("Some alerts could not be processed:\n\n" + "\n".join(errors))
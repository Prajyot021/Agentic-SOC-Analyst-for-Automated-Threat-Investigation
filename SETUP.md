# SETUP.md: Agentic AI SOC Assistant

How to build the lab and run the project from a clean machine. Follow the parts in order. Each part ends with a check, so you know it worked before moving on.

> **Safety first.** This project deliberately runs attacker-style tests. Run them only inside a disposable VM that you own, on an isolated network, with a snapshot taken first. Never run Atomic Red Team on your everyday PC.

---

## 0. What you are setting up

```
Windows lab VM                      Wazuh server (Docker)         Your workstation
--------------                      ---------------------         ----------------
simulation agent  -> runs allow-    Wazuh manager + indexer  ->   capture scripts  -> SOC app (LangGraph)
listed Atomic Red Team test         + dashboard                   (fetch, convert)     + Ollama (local model)
Wazuh agent  ------------------->   raises alerts (JSON)                              + Streamlit UI
```

| Part | What it is | Code in this repo? |
|---|---|---|
| `soc-demo/` | SOC application: 7-node LangGraph workflow, guardrail, Streamlit UI | Yes |
| `capture/` | Scripts that pull Wazuh alerts and convert them | Yes |
| Wazuh server, Wazuh agent, Atomic Red Team | Third-party tools you install | No (install steps below) |
| Simulation agent (PowerShell) and Simulation Lab (Streamlit) | Your own components | **No. Add your own steps in Part 7** |

---

## 1. Prerequisites

| Need | Notes |
|---|---|
| Python **3.10 or newer** | The capture scripts use `str \| None` type hints, which need 3.10+ |
| Git | To clone the Wazuh Docker repo |
| Docker with Compose v2 | Runs the Wazuh server. Docker Desktop on Windows is fine |
| Ollama | Runs the local language model |
| A hypervisor (VirtualBox, VMware or Hyper-V) | Hosts the Windows target VM |
| A Windows 10/11 VM | The monitored target |
| RAM and disk | Record your actual numbers in the report. Wazuh plus an 8B model plus a VM is heavy, so close other apps |

Record the exact versions you install (`python --version`, `docker --version`, `ollama --version`, Wazuh version, Windows build). You will need them for the reproducibility tables in the report and paper.

---

## 2. Project layout

```
soc-demo/
  app.py                 Streamlit analyst UI
  run_cli_demo.py        Terminal runner, good for a first test
  sample_alerts.json     5 mock alerts (development data only)
  requirements.txt
  soc_demo/
    state.py  llm.py  guardrail.py  agents.py  graph.py
capture/
  run_log.py             Log each simulation run (for ground truth)
  fetch_wazuh_alerts.py  Pull alerts from the Wazuh indexer
  convert_to_mini_ocsf.py Convert Wazuh JSON to the project's alert format
  raw/                   Raw Wazuh dumps go here
```

Always run the `soc-demo` commands **from inside the `soc-demo/` folder**. `run_cli_demo.py` and the Correlation agent open `sample_alerts.json` by relative path.

---

## 3. Python environment

**PowerShell (Windows)**
```powershell
cd soc-demo
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install requests
```

**bash (Linux or macOS)**
```bash
cd soc-demo
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install requests
```

`requests` is only needed by `capture/fetch_wazuh_alerts.py`.

If PowerShell blocks the activate script: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Check:** `python -c "import langgraph, langchain_ollama, streamlit; print('ok')"` prints `ok`.

---

## 4. Choose the language-model backend

The backend is chosen by the `SOC_DEMO_BACKEND` environment variable.

| Value | What it does | Use for |
|---|---|---|
| `ollama` (code default) | Local model through Ollama | Real runs |
| `nvidia` | NVIDIA hosted API | Optional alternative |
| `simulated` | No model. Rule-based stand-in | Wiring tests only |

> **Do not use `simulated` for any measurement.** In that mode the agents read the alert's `ground_truth` field to produce their answer, so the output says nothing about triage quality.

### 4a. Ollama (recommended)

1. Install Ollama from https://ollama.com and start it.
2. Pull a model:
   ```bash
   ollama pull llama3.1:8b
   ```
3. Set the variables **before** launching anything:

   **PowerShell**
   ```powershell
   $env:SOC_DEMO_BACKEND = "ollama"
   $env:OLLAMA_MODEL = "llama3.1:8b"          # must match the model you pulled
   # $env:OLLAMA_BASE_URL = "http://localhost:11434"   # only if Ollama is elsewhere
   ```
   **bash**
   ```bash
   export SOC_DEMO_BACKEND=ollama
   export OLLAMA_MODEL=llama3.1:8b
   ```

> **Important:** the settings are read once, when the app starts. The backend dropdown and model box in the Streamlit sidebar do **not** change them while the app is running, and if you do not set `SOC_DEMO_BACKEND`, the sidebar shows `simulated` while the code actually uses `ollama`. Always set the environment variables first, then start the app.

### 4b. NVIDIA hosted API (optional)

```powershell
$env:SOC_DEMO_BACKEND = "nvidia"
$env:NVIDIA_API_KEY   = "<your key>"          # never commit this
$env:NVIDIA_MODEL     = "meta/llama3-8b-instruct"
```

### 4c. LangSmith tracing (optional)

```powershell
$env:LANGCHAIN_TRACING_V2 = "true"
$env:LANGCHAIN_API_KEY    = "<your key>"
$env:LANGCHAIN_PROJECT    = "soc-agentic-assistant"
```

---

## 5. Smoke test without the lab

This checks the code and the model before you build any infrastructure.

```bash
cd soc-demo
python run_cli_demo.py
streamlit run app.py        # opens http://localhost:8501
```

**Check:** all 5 sample alerts print an agent trace and a final disposition. In the UI, pick an alert, click **Run agent pipeline**, and read the trace. If the guardrail asks for approval, the Approve and Reject buttons appear. Approval decisions are kept in memory only and are lost on restart. Nothing is executed on any machine. Actions are proposals.

---

## 6. Wazuh server (Docker, single node)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.5
cd wazuh-docker/single-node
sudo sysctl -w vm.max_map_count=262144
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

- Use the release tag you actually deploy and record it. `v4.14.5` is the one used in the project instructions.
- **Docker Desktop on Windows:** run the `sysctl` line inside the Docker VM instead: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`.
- Give the indexer a minute to start. Some connection errors in the logs during start-up are normal.
- Open `https://localhost:443`. The default login in the Wazuh Docker docs is `admin` / `SecretPassword`. **Change it** before you do anything else, and use the new password everywhere below.

**Check:** `docker ps` shows the indexer, manager and dashboard as `Up`, and you can log in to the dashboard.

---

## 7. Windows target VM

1. Create a Windows 10/11 VM. Use a **host-only or otherwise isolated** network with a route to the Wazuh server and nothing else.
2. Install the **Wazuh agent** from the Wazuh dashboard (Agents, Deploy new agent), pointing at your Wazuh manager's IP.
3. In the dashboard, confirm the agent shows **Active**.
4. *(Optional, lab VM only)* Turn off Defender real-time protection if it silently blocks tests before Wazuh can see them. Do this only on the isolated VM.
5. **Take a VM snapshot.** Revert to it after destructive tests.

**Check:** the agent is Active, and you can find its name in the dashboard. You will use that name as `--agent` later.

### 7a. Simulation agent and Simulation Lab (your own components)

These are not in this repository. Add your own steps here, for example:

- How to start the PowerShell simulation agent on the VM and where its allowlist lives: `{{fill in}}`
- How the authentication token or credential is set: `{{fill in, never write the secret here}}`
- How to start the Simulation Lab and which URL and port it uses: `{{fill in}}`
- The ten allow-listed test IDs: `{{fill in}}`

---

## 8. Atomic Red Team (inside the VM)

Open PowerShell **as Administrator**. Check the title bar says "Administrator".

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

**Always look before you run:**
```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

Lessons from the first runs in this project:

| Situation | What happened | What to do |
|---|---|---|
| `Invoke-AtomicTest T1110` | `T1110.yaml does not exist` | Parent technique has no atomics. Use a sub-technique, and note that some need an Active Directory domain |
| `T1059.001 -TestNumbers 1` | Ran a Mimikatz test | Check what a test does first. A gentler choice is test 10 (fileless script execution) |
| `T1490 -TestNumbers 1` | `vssadmin` permission error | Session was not elevated. Relaunch as Administrator |
| T1490 with admin rights | Deletes the VM's shadow copies | Intended. Snapshot first |

Do not infer which test an alert came from. Record it (Part 9).

---

## 9. Capture real alerts

Run these from `capture/` on your workstation. Do **one technique at a time**: log, trigger, wait, fetch, convert. The converter attributes an alert to a logged run if it arrives within 10 minutes on the same host, so running two techniques before fetching can mix their labels.

One-time variables:

**PowerShell**
```powershell
$env:WAZUH_INDEXER_PASS = "<the indexer password you set>"
# optional overrides (defaults shown):
# $env:WAZUH_INDEXER_URL     = "https://localhost:9200"
# $env:WAZUH_INDEXER_USER    = "admin"
# $env:WAZUH_INDEX_PATTERN   = "wazuh-alerts-*"
```

Per technique:

```bash
# 1. log the run BEFORE triggering it
python run_log.py add --technique T1059.001 --host <AGENT-NAME> \
    --category suspicious_process_activity --severity medium --notes "short note"

# 2. trigger the test in the VM (elevated PowerShell), then wait about 60 seconds

# 3. fetch what Wazuh raised
python fetch_wazuh_alerts.py --minutes 15 --agent <AGENT-NAME> --out raw/t1059_run1.json

# 4. convert and append
python convert_to_mini_ocsf.py --in raw/t1059_run1.json --out captured_alerts.json --append
```

For benign activity, log the run with `--ground-truth false_positive`. You need benign alerts to measure false positives.

**Check:** `captured_alerts.json` exists, has the alerts you expect, and no entry has `"ground_truth": "UNLABELED"` (fix those by hand). If a fetch returns 0 alerts, see Troubleshooting.

---

## 10. Point the assistant at the captured data

1. In `soc-demo/`, back up and replace the data file. Both the runner, the UI and the Correlation agent read this exact name:
   ```bash
   mv sample_alerts.json sample_alerts_backup.json
   cp ../capture/captured_alerts.json sample_alerts.json
   ```
2. Add your real host names to `ASSET_INVENTORY` in `soc_demo/agents.py`, for example `"WIN11-LAB": "medium"`. A host that is not listed gets criticality `unknown`.
3. Run it, with the backend variables from Part 4 already set:
   ```bash
   python run_cli_demo.py
   streamlit run app.py
   ```

---

## 11. Before you measure anything

These come from reading the code. Fix them before you report any result.

1. **Label leakage.** The prompts include the whole alert record. If the record carries `ground_truth` or `notes` (the converter adds both), the model can see the answer. Strip those fields from the input and keep labels in a separate file.
2. **Do not evaluate in `simulated` mode.** It reads the label.
3. **Unknown criticality is not treated as high.** A Tier 2 action on an unlisted host can be auto-approved at confidence 0.85 or higher. Decide whether to treat unknown as high.
4. **Labels from time matching need a manual check.** Background alerts near a logged run can pick up its label.
5. **Confidence is the model's own number**, not a calibrated probability.

---

## 12. Environment variable reference

| Variable | Default | Purpose |
|---|---|---|
| `SOC_DEMO_BACKEND` | `ollama` | `ollama`, `nvidia` or `simulated` |
| `OLLAMA_MODEL` | `llama3.1:8b` | Model name Ollama serves |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama address |
| `NVIDIA_API_KEY` | empty | Key for the NVIDIA backend |
| `NVIDIA_MODEL` | `meta/llama3-8b-instruct` | NVIDIA model name |
| `LANGCHAIN_TRACING_V2`, `LANGCHAIN_API_KEY`, `LANGCHAIN_PROJECT` | unset | Optional LangSmith tracing |
| `WAZUH_INDEXER_URL` | `https://localhost:9200` | Wazuh indexer |
| `WAZUH_INDEXER_USER` | `admin` | Indexer user |
| `WAZUH_INDEXER_PASS` | none (required) | Indexer password |
| `WAZUH_INDEX_PATTERN` | `wazuh-alerts-*` | Index to search |
| `ART_RUN_LOG` | `run_log.json` | Run-log file path |

---

## 13. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: langgraph` | venv not active or install skipped | Activate the venv, `pip install -r requirements.txt` |
| Every case ends as "escalate" and traces look generic | Model calls are failing and the code is using fallback defaults | Check Ollama is running (`ollama list`), the model name matches `OLLAMA_MODEL`, and the URL is right |
| `connection refused` to port 11434 | Ollama not running | Start Ollama |
| UI says `simulated` but you expected a model | Env var not set before launch | Set `SOC_DEMO_BACKEND`, then restart Streamlit |
| `WAZUH_INDEXER_PASS is not set` | Variable missing in this terminal | Export it again (variables are per terminal) |
| `401` from the indexer | Wrong password | Use the password you set after first login |
| SSL warnings from `requests` | Self-signed lab certificate | Expected in the lab. The script disables verification |
| Fetch returns 0 alerts | Test did not run, agent not Active, wrong `--agent` name, or window too short | Check the agent in the dashboard, widen `--minutes`, wait longer |
| Dashboard or indexer will not start | `vm.max_map_count` too low | Re-run the `sysctl` step |
| `vssadmin` permission error | PowerShell not elevated | Relaunch as Administrator |
| Port 8501 already in use | Old Streamlit still running | Close it or use `--server.port 8502` |

---

## 14. Security notes

- Keep the lab isolated from production networks.
- Do not commit passwords, API keys or the indexer password. Use environment variables.
- Change the default Wazuh password.
- Remove secrets, tokens and internal addresses from screenshots and logs before they go into a report.
- Raw Wazuh alerts can contain user names and command lines. Treat the capture files as sensitive.

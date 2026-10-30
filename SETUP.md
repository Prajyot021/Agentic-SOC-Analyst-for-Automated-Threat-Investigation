# Simulation Lab setup

This adds a Simulation Lab page to the existing Streamlit SOC app. It uses an allow-listed PowerShell runner on the isolated Windows 10 VM, checks recent Wazuh manager alerts for agent `002` / `target-win10`, and passes newly converted alerts to the existing LangGraph pipeline.

## 1. Copy the module into the project

Copy `soc_demo/simulation_lab.py` into your project's `soc_demo` directory. Keep your existing files.

## 2. Add the page to `app.py`

From the project root, run:

```powershell
python .\integrate_simulation_lab.py .\app.py
```

The script creates a timestamped backup before editing `app.py`. It fails without writing if its expected code anchors are not found. If you prefer, inspect the script first.

## 3. Configure the shared token on the host

Generate a long random token in PowerShell:

```powershell
$token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$env:SOC_SIMULATION_AGENT_TOKEN = $token
$env:SOC_SIMULATION_AGENT_URL = 'http://192.168.220.129:8765'
$env:WAZUH_MANAGER_CONTAINER = 'single-node-wazuh.manager-1'
```

Keep this PowerShell session open and launch Streamlit from it so the variables are inherited. If your actual manager container has a different name, use that name.

## 4. Prepare the Windows 10 VM runner

Copy `vm_simulation_agent.ps1` to the Windows 10 VM. Confirm the module exists at `C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1`. In an elevated PowerShell session on the VM, set the exact same token value generated on the host, then start the runner:

```powershell
$env:SOC_SIMULATION_AGENT_TOKEN = 'PASTE_THE_SAME_TOKEN_HERE'
Set-ExecutionPolicy -Scope Process Bypass
.\vm_simulation_agent.ps1
```

The runner supports only two predefined tests, `T1082` and `T1057`; it does not accept arbitrary commands. Run it only on the isolated lab VM. Do not expose port 8765 to the public internet. If the host cannot reach the VM, configure a host-only network and a narrowly scoped Windows Firewall rule for the host's IP.

## 5. Launch the application

On the host, in the same PowerShell session that has the environment variables:

```powershell
streamlit run app.py
```

Open **Simulation Lab**, confirm the target VM, and start one test. The page polls the local Dockerized Wazuh manager's `/var/ossec/logs/alerts/alerts.json` for up to 75 seconds and only accepts fresh alerts from `target-win10` / agent ID `002`. It then sends up to five new alerts through the existing `run_alert_through_pipeline` and `get_or_create_case` functions.

## Important limitations

- The module assumes the host can run `docker exec` against the Wazuh manager container and that the container name and log path are correct.
- Atomic execution completing does **not** mean Wazuh detected it. If no new alert appears, the page reports that separately; confirm the relevant Windows telemetry and Wazuh rules are enabled.
- If the VM's Atomic module is at a different path, edit `$AtomicModule` in the runner to match the actual file.
- The runner uses plain HTTP and a shared token for a lab-only network. Do not bind/expose it to a public or untrusted network.

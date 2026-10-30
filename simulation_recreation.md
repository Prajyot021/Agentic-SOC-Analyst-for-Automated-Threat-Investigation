# Recreating the SOC Attack Simulation Lab

## 1. Overview

The SOC simulation workflow uses the following components:

- **Sysmon (System Monitor):** Records system activity on the Windows VM.
- **SOC simulation token:** Authenticates communication between the required components.
- **`vm_simulation_agent.ps1`:** Determines which attack scenario is requested and whether it is allowed.
- **Red Team YAML playbooks:** Define the attack scenarios executed when authorized.

Run simulations only in your authorized SOC lab environment.

## 2. Prerequisites

Before starting, ensure that:

1. Sysmon is installed on the Windows VM.
2. The simulation agent exists at `C:\SOC-Lab\vm_simulation_agent.ps1`.
3. The relevant YAML playbooks are available in the Red Team folder.
4. You have the required simulation token.
5. The SOC monitoring components are configured to collect and process the resulting events.

## 3. Set the Simulation Token

Set the token in PowerShell on the **main computer**:

```powershell
$env:SOC_SIMULATION_AGENT_TOKEN="paste_your_token_here"
```

Repeat this step on the **Windows VM** if the simulation workflow requires the token there.

Replace `paste_your_token_here` with your actual token.

**Important:** Environment variables set using `$env:` belong to the current PowerShell session. If you open a new terminal, you must set the token again in that terminal.

## 4. Verify the Token

Run the following command in the same PowerShell terminal where you set the token:

```powershell
if ($env:SOC_SIMULATION_AGENT_TOKEN -and $env:SOC_SIMULATION_AGENT_TOKEN.Trim()) {
    Write-Host "TOKEN PRESENT"
} else {
    Write-Host "TOKEN MISSING"
}
```

Expected output:

- `TOKEN PRESENT` — A non-empty token value is available.
- `TOKEN MISSING` — The variable is unset or empty.

This check confirms only that a value exists. It does not verify whether the token is valid.

## 5. Start the VM Simulation Agent

In the same PowerShell terminal where the token was set and verified, run:

```powershell
& "C:\SOC-Lab\vm_simulation_agent.ps1"
```

Keep using this terminal for commands that depend on the environment variable.

If you open another terminal, set and verify the token again.

## 6. How Attack Simulation Works

The simulation workflow follows these steps:

1. A simulation request is received.
2. `vm_simulation_agent.ps1` determines which attack scenario is requested.
3. The script checks whether the requested scenario is allowed.
4. If authorized, the corresponding YAML playbook in the Red Team folder is executed.
5. The activity occurs on the Windows VM.
6. Sysmon records supported activity according to its configuration.
7. Wazuh processes relevant events and may generate alerts.
8. The SOC application ingests and analyzes the resulting alerts, provided the required integrations are running.

The script's authorization rules and scenario-to-playbook mappings should be verified against the actual implementation.

## 7. SOC Dashboard Sections

The application provides five main sections.

### 7.1 Alert Dashboard

The Alert Dashboard displays alerts available to the SOC application.

Depending on the configured implementation, alert details may include:

- Event ID and timestamp
- Severity
- Hostname
- Alert type
- Event summary
- MITRE ATT&CK technique

The data may originate from Wazuh, imported alert records, or configured sample data.

**Important:** Not every alert displayed on the dashboard necessarily originates from the attack simulation.

### 7.2 Simulation Lab

The Simulation Lab is used to initiate approved attack scenarios for testing the SOC monitoring workflow.

The VM simulation agent checks the requested scenario and executes the corresponding Red Team YAML playbook when the scenario is permitted.

Sysmon and Wazuh can then record and process the resulting activity.

**Purpose:** Test how the monitoring and analysis pipeline responds to controlled attack scenarios.

A simulated attack does not guarantee that an alert will be generated. Detection depends on the activity, Sysmon configuration, Wazuh rules, and alert-ingestion pipeline.

### 7.3 Case Review

Case Review allows the operator to inspect cases created by the SOC workflow.

Depending on the information recorded by the application, a case may include:

- Alert details
- Confidence score
- Final disposition
- Proposed action
- Guardrail decision
- Audit trail

**Purpose:** Understand how the system analyzed an alert and why it reached a particular outcome.

An alert is an input event; a case records the application's handling or analysis of that event.

### 7.4 Approval Queue

The Approval Queue provides a human-review stage for proposed actions that require approval.

The reviewer can inspect the proposed action and make a decision, such as approving or rejecting it, where supported by the application.

**Purpose:** Keep a human involved in decisions about potentially consequential response actions.

Approval should not be described as executing a response action unless the implementation actually performs that action.

### 7.5 System Status

System Status provides information about the operational state of the services and dependencies monitored by the application.

Depending on the implementation, these checks may include services such as Ollama and Qdrant.

**Purpose:** Help identify unavailable dependencies that could affect alert processing or agent execution.

A healthy status indicator alone does not prove that the entire SOC pipeline works end to end.

## 8. End-to-End Demonstration Workflow

Follow this sequence when demonstrating the system:

1. Open **System Status** and check the required dependencies.
2. Open **Alert Dashboard** and confirm that alerts are available.
3. Open **Simulation Lab** and run an authorized simulation scenario.
4. Check Sysmon and Wazuh to determine whether the activity generated relevant events and alerts.
5. Return to **Alert Dashboard** and check whether the resulting alerts were ingested.
6. Open **Case Review** to inspect the analysis and disposition of any created cases.
7. Open **Approval Queue** to review any proposed actions requiring human approval.
8. Return to **System Status** if a component fails and investigate the relevant dependency.

This demonstrates the relationship between controlled simulation, security monitoring, agent-based analysis, and human review.

## 9. Troubleshooting

### Token is missing

Set the token again in the current PowerShell terminal and repeat the verification command.

### Authentication fails

Confirm that the required components have the correct token configured. Do not print or expose the token while troubleshooting.

### The simulation script cannot be found

Verify that this file exists:

`C:\SOC-Lab\vm_simulation_agent.ps1`

### The requested attack does not run

Check the script's authorization logic, the scenario-to-playbook mapping, and the presence of the required YAML file.

Do not bypass the authorization checks to force execution.

### No alert appears on the dashboard

Check the following:

- Sysmon is installed, running, and configured appropriately.
- Wazuh is collecting and processing the relevant events.
- The Wazuh alert-forwarding mechanism is operational.
- The SOC application's alert-ingestion path is working.
- The simulated activity is expected to trigger a configured detection.

Not every simulated action necessarily produces an alert.

## 10. Files Required for Reproduction

The project package should include the relevant files required by the implemented workflow:

- `vm_simulation_agent.ps1`
- Required YAML playbooks from the Red Team folder
- Sysmon configuration or setup instructions, if applicable
- Simulation-agent configuration, with secrets removed
- Wazuh integration and alert-ingestion components
- SOC application and agent workflow
- Required Python dependencies
- Instructions for setting up external services

Do not include the actual simulation token in the Markdown file, scripts, screenshots, or conference submission.

## 11. Conference Submission Notes

Before sharing the project with the guide:

1. Verify the instructions against the final scripts and YAML playbooks.
2. Remove real credentials, tokens, and other secrets.
3. Identify which alerts come from live monitoring, imported historical data, and synthetic testing.
4. Keep the authorization checks in the simulation agent.
5. Document the scenarios tested and the resulting events, alerts, and SOC decisions.
6. Verify all claims about detection, agent execution, and response actions against actual test results.

The goal is to make the simulation workflow reproducible while accurately documenting the implemented functionality.
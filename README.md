# Agentic SOC Analyst for Automated Threat Investigation

An agentic AI-based Security Operations Center (SOC) assistant designed to automate security alert investigation, threat analysis, and response recommendations using a multi-agent workflow.

## Overview

Security Operations Centers receive large volumes of alerts from endpoint monitoring and security tools. Manually investigating every alert can be time-consuming and may delay incident response.

This project uses **AI agents, security event data, and workflow orchestration** to assist with alert triage and investigation. It processes security alerts, gathers relevant context, evaluates potential threats, and presents investigation results through a dashboard.

The system integrates with Wazuh for security monitoring, Ollama for local language model inference, Qdrant for vector storage, and LangGraph for workflow orchestration.

## Key Features

- **Security Alert Dashboard:** View and inspect security alerts available to the application.
- **Automated Alert Triage:** Analyze incoming alerts and assess their potential severity.
- **Multi-Agent Investigation:** Coordinate specialized agents to investigate alerts and generate findings.
- **Threat Context Retrieval:** Retrieve relevant contextual information to support investigations.
- **Guardrails and Risk Assessment:** Evaluate proposed actions against configured safety rules.
- **Human Approval Workflow:** Review proposed response actions before executing actions that require approval.
- **Simulation Lab:** Run supported attack simulations through a configured Windows lab environment.
- **Case Review:** Examine investigation findings, confidence scores, decisions, and available audit information.
- **System Status:** Check the availability of configured application dependencies.

## Architecture

The project follows an agent-based investigation workflow.

```text
Security Events
      |
      v
     Wazuh
      |
      v
Alert Ingestion and Normalization
      |
      v
LangGraph Investigation Workflow
      |
      v
+----------------------------+
| Specialized AI Agents      |
|                            |
| Alert Analysis             |
| Threat Investigation       |
| Context Retrieval          |
| Risk Assessment            |
| Response Recommendation    |
+----------------------------+
      |
      v
Guardrails and Decision Logic
      |
      v
Investigation Results
      |
      v
SOC Dashboard
      |
      v
Human Review and Approval
```

The exact execution path depends on the configured workflow and the agents implemented in the codebase.

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Security Monitoring | Wazuh | Collect and analyze endpoint security events |
| Endpoint Telemetry | Sysmon | Record supported activity on Windows endpoints |
| AI Orchestration | LangGraph | Coordinate investigation workflows |
| Language Model Runtime | Ollama | Run locally hosted language models |
| Language Model | Configured Qwen model | Support alert analysis and investigation |
| Vector Database | Qdrant | Store and retrieve contextual information |
| Application | Python | Implement the SOC application and supporting logic |
| Dashboard | Streamlit | Provide the user interface |
| Attack Simulation | Atomic Red Team and PowerShell | Generate controlled security testing activity |

*The technologies listed above describe the intended project stack. Actual functionality depends on the installed dependencies and current configuration.*

## Project Structure

The repository contains the following major components:

```text
Agentic-SOC-Analyst-for-Automated-Threat-Investigation/
│
├── app.py
├── soc_demo/
├── data/
├── wazuh-docker/
├── requirements.txt
├── SETUP.md
├── simulation_recreation.md
├── .streamlit/
├── .gitignore
│
├── add_high_severity_alerts.py
├── check_alerts.py
├── integrate_simulation_lab.py
│
├── test_agent_pipeline.py
├── test_data_load.py
└── test_with_mock_attack.py
```

### Main Components

- `app.py` — Main application entry point.
- `soc_demo/` — Supporting SOC application and investigation components.
- `data/` — Alert data, configuration files, and supporting security information.
- `wazuh-docker/` — Wazuh deployment configuration.
- `requirements.txt` — Python dependencies.
- `SETUP.md` — Additional setup instructions.
- `simulation_recreation.md` — Instructions for configuring and reproducing the simulation environment.
- `integrate_simulation_lab.py` — Simulation integration script.
- `test_agent_pipeline.py` — Agent pipeline test script.
- `test_data_load.py` — Data-loading test script.
- `test_with_mock_attack.py` — Test script using mock attack activity.

## Prerequisites

Before running the complete environment, ensure you have:

- Windows 10/11 or a compatible environment for the application and lab.
- Python and `pip`.
- Git.
- Docker Desktop with WSL 2 integration, where required.
- Wazuh configured and running.
- Ollama installed with the model configured by the application.
- Qdrant running and accessible.
- A configured Windows test VM for supported simulations.
- Sysmon installed on the Windows endpoint.
- Atomic Red Team and the required simulation playbooks, where applicable.

The full SOC environment requires more configuration than the Python application alone.

## Installation and Setup

### 1. Clone the Repository

```powershell
git clone https://github.com/Prajyot021/Agentic-SOC-Analyst-for-Automated-Threat-Investigation.git
cd Agentic-SOC-Analyst-for-Automated-Threat-Investigation
```

### 2. Create a Virtual Environment

```powershell
python -m venv venv
```

Activate it in PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure the Services

Start and configure the required services:

- Wazuh
- Ollama and the configured language model
- Qdrant

Use the deployment files and instructions included in the repository. Verify that each service is reachable before starting the application.

### 5. Configure Environment Variables

Set any required environment variables and credentials according to the project's setup instructions.

For the simulation integration, the configured simulation token may be required in both the main environment and the Windows test VM.

Set it in PowerShell as follows:

```powershell
$env:SOC_SIMULATION_AGENT_TOKEN="your_token_here"
```

Replace the placeholder with your actual token. Do not commit real tokens, passwords, API keys, or other secrets to GitHub.

### 6. Start the Application

If the project uses Streamlit as configured:

```powershell
streamlit run app.py
```

Open the local address printed in the terminal.

If a dependency or configuration error occurs, consult `SETUP.md` and verify the service status.

## Attack Simulation Lab

The project includes a simulation integration for generating controlled security activity in a Windows lab environment.

The general workflow is:

1. Select a supported simulation in the SOC application.
2. Submit the simulation request through the configured integration.
3. Validate the request and applicable restrictions.
4. Execute the corresponding supported playbook on the configured test VM.
5. Generate endpoint activity.
6. Allow Sysmon and Wazuh to record and process the activity.
7. Inspect any resulting alerts in the SOC application.

**Important:** A simulation request does not guarantee that Wazuh will generate an alert. The result depends on the activity performed, Sysmon configuration, Wazuh rules, event forwarding, and alert ingestion.

Run simulations only in an authorized, isolated test environment.

For detailed setup instructions, see [`simulation_recreation.md`](simulation_recreation.md).

## Dashboard Modules

### Alert Dashboard
Displays the security alerts available to the application for inspection and investigation.

### Investigation and Case Review
Presents available investigation findings, risk assessments, confidence information, and proposed response actions.

### Simulation Lab
Provides an interface for supported security simulations through the configured lab integration.

### Approval Queue
Allows proposed actions requiring human authorization to be reviewed before execution.

### System Status
Provides visibility into the status of configured application dependencies.

The alerts displayed by the application may originate from different configured sources. Not every alert should be assumed to have been generated by a simulation.

## Testing

The repository includes scripts for testing data loading, agent pipeline behavior, and mock attack scenarios.

Run the relevant tests from the project root. For example:

```powershell
python test_data_load.py
python test_agent_pipeline.py
python test_with_mock_attack.py
```

These commands assume the scripts can run independently with the current configuration. Some tests may require additional services, environment variables, or prepared test data.

## Security Considerations

- Run attack simulations only on systems you own or are authorized to test.
- Keep simulation credentials and API keys outside version control.
- Review proposed response actions before allowing them to affect real systems.
- Use human approval for sensitive or disruptive actions.
- Keep Wazuh, Ollama, Qdrant, and the dashboard appropriately restricted.
- Do not expose development services publicly without suitable authentication and network controls.
- Treat AI-generated investigation results as decision support rather than unquestionable ground truth.

## Current Scope and Limitations

This project is a research and development prototype for AI-assisted SOC investigation.

Its effectiveness depends on alert quality, available context, model behavior, workflow configuration, and the security rules used by the underlying monitoring tools.

Automated investigation and response capabilities should be evaluated against controlled test cases before use in operational environments. Human review remains important for validating findings and authorizing consequential actions.

## Research Objective

The project's objective is to explore how an agentic AI workflow can support SOC analysts by coordinating alert triage, threat investigation, contextual retrieval, risk evaluation, and response recommendations.

The broader goal is to reduce repetitive manual investigation while maintaining oversight, traceability, and safeguards around security response actions.

## License

No license is specified in this repository yet. Add an appropriate license before distributing or reusing the project publicly.

## Author

**Prajyot Kumar**  
M.Tech — Computer Science  
Vellore Institute of Technology (VIT), Vellore

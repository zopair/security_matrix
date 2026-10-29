# SecurityMatrix | AI Deception & Threat Neutralization Grid

<p align="center">
  <strong>A defensive cyber-deception reference implementation for observing suspicious automation in a controlled, isolated environment.</strong>
</p>

<p align="center">
  <img alt="Status: MVP" src="https://img.shields.io/badge/status-MVP%20in%20development-blue">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Security: Defense in depth" src="https://img.shields.io/badge/security-defense%20in%20depth-informational">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white">
  <img alt="Automation" src="https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white">
  <img alt="SOC Dashboard" src="https://img.shields.io/badge/UI-SOC%20Dashboard-111827">
</p>

> **Security note:** SecurityMatrix is a defensive monitoring and deception project. A dashboard, risk score, or simulated incident is not proof that a real attacker or AI agent has been identified or neutralized. Deploy behind an appropriately configured reverse proxy and never expose the sandbox to production systems.

## Overview

SecurityMatrix explores how **cyber deception** can help defenders observe suspicious automated reconnaissance without exposing real assets. Requests that match configured risk signals can be routed to a deliberately limited **Deception Sandbox** containing synthetic records and simulated endpoints. Structured telemetry gives defenders a traceable view of the observed activity.

The design prioritizes isolation, bounded resource use, auditable decisions, and safe failure modes over infinite loops or attempts to exhaust an external agent's resources.

### Design goals

- Detect suspicious request patterns using transparent, explainable rules.
- Keep synthetic data and decoy behavior separate from production data and services.
- Capture useful, privacy-conscious event records for investigation.
- Present operational state and simulated events in a dark SOC-style dashboard.
- Run repeatable checks through GitHub Actions.

## Architecture & Components

```text
Client / Test Traffic
        |
Reverse Proxy / TLS / Rate Limits
        |
Deception Gateway (FastAPI)
        |
Risk & Decision Engine
   /                 \
Normal response     Isolated Deception Sandbox
                         |
                 Synthetic data / decoy routes
                         |
              Structured event logging
                         |
               SOC dashboard / analytics
```

### 1. Deception Gateway & Risk Engine

The gateway validates incoming requests and applies explicit, configurable decision rules. Decisions should use multiple signals and context; user-agent strings and IP addresses alone are not reliable proof of an AI agent. Authentication and authorization for real resources must remain independent of the deception layer.

### 2. Isolated Deception Sandbox

The sandbox returns **synthetic, non-sensitive data** for selected decoy routes. It must not share production credentials, databases, filesystem mounts, or unrestricted network access. Apply strict limits to response sizes, request rates, CPU, memory, and session duration. Do not use infinite loops or unbounded payload generation.

### 3. SOC Monitoring & Analytics

Structured events should include a timestamp, request/session identifier, event type, risk decision, and outcome. Redact credentials, authorization headers, cookies, and other secrets before persistence. Restrict access to logs and define retention limits. Dashboard incident indicators represent observed or simulated events and should be labelled accordingly.

## Key Features

- Rule-based detection of suspicious enumeration and probing patterns.
- Risk-based routing to normal handling, monitoring, throttling, or a decoy response.
- Synthetic decoy data designed to avoid disclosure of real user information.
- Structured telemetry for reviewing observed tactics, techniques, and procedures (TTPs).
- Dark SOC dashboard for service health, risk distribution, and event timelines.
- Automated tests and CI checks through GitHub Actions.

**Scope clarification:** Detection is heuristic, not a guarantee of identifying AI-generated traffic. SecurityMatrix does not promise to trap every attacker, prevent all intrusions, or neutralize an agent outside the controlled environment.

## Quick Start

### Requirements

- Python 3.11 or newer
- Git

### Local setup

```bash
git clone https://github.com/zopair/security_matrix.git
cd security_matrix

python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open the API documentation at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). The dashboard entry point and available routes are documented in the repository as they are implemented.

### Run tests

```bash
pytest -q
```

### GitHub Actions

The repository's workflow definitions under `.github/workflows/` can run tests on pushes and pull requests. Actions are CI automation: **they do not host a persistent API service by themselves**. For a public deployment, use a supported application host, configure TLS and secrets in the host's secret manager, and keep production credentials out of Git history and workflow logs.

## Configuration & Operational Safety

- Keep the deception environment isolated from production networks and data stores.
- Use an external reverse proxy or WAF for TLS termination and edge rate limiting.
- Set request, body-size, response-size, and session-duration limits.
- Fail closed for access to real protected resources; a failed risk engine must never bypass authentication or authorization.
- Store logs with least-privilege access, redaction, retention limits, and integrity controls.
- Do not log secrets or send sensitive telemetry to public repositories or workflow artifacts.
- Test false positives with legitimate clients before enabling automatic routing in production.
- Use a kill switch and resource ceilings to disable deception safely if latency or load rises.

## Development Status

SecurityMatrix is an evolving MVP/reference implementation. Features described here are design goals unless they are present in the code and covered by tests. Check the current source and CI results before relying on any capability in a production environment.

## Contributing

Contributions are welcome through focused pull requests. Include tests for behavior changes, document security implications, and avoid committing credentials, real personal data, or production logs.

## License

This project is intended to be distributed under the MIT License. See [LICENSE](LICENSE) when the license file is present.

---

**SecurityMatrix | AI Deception & Threat Neutralization Grid**

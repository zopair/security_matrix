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

## Platform Demo

Watch the SecurityMatrix platform walkthrough below. The video is hosted in this repository and uses a responsive HTML5 player; autoplay may be restricted by browser settings.

<div align="center">
  <video
    controls
    autoplay
    muted
    loop
    playsinline
    preload="metadata"
    width="100%"
    style="max-width:700px;height:auto;border-radius:12px;"
  >
    <source src="https://raw.githubusercontent.com/zopair/security_matrix/main/assets/gemini_generated_video_05cffc5b.mp4" type="video/mp4">
    Your browser does not support HTML5 video. <a href="https://raw.githubusercontent.com/zopair/security_matrix/main/assets/gemini_generated_video_05cffc5b.mp4">Open the demo video directly</a>.
  </video>
</div>

**Video file:** [assets/gemini_generated_video_05cffc5b.mp4](assets/gemini_generated_video_05cffc5b.mp4)

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

## Security Automation

GitHub Actions includes the following workflows:

- `.github/workflows/security-scan.yml`: local Semgrep rules (no hosted rule registry), pip-audit dependency checks, Bandit Python checks, SARIF upload, and a normalized report artifact.
- `.github/workflows/codeql.yml`: GitHub CodeQL security-extended analysis for Python. Runs on pushes, pull requests, weekly schedule, and manual dispatch.
- `.github/workflows/nuclei-dast.yml`: Nuclei scans only the temporary app started on `127.0.0.1` inside the GitHub-hosted runner. It uses bounded request rate/concurrency and disables Interactsh callbacks.
- `.github/workflows/auto-remediation.yml`: reviews pip-audit output and proposes compatible direct-dependency constraint updates in a pull request. It never merges or deploys automatically.
- `.github/dependabot.yml`: weekly dependency and GitHub Actions update proposals.

### Optional SOC ingestion

To stream normalized scanner findings into the SOC dashboard, configure these repository Actions secrets:

- `SECURITYMATRIX_INGEST_URL`: base URL of the deployed SecurityMatrix instance.
- `SECURITYMATRIX_INGEST_TOKEN`: a long random token that must match the `SECURITYMATRIX_INGEST_TOKEN` environment variable on the API service.

The API accepts only bounded finding metadata at `POST /api/security/findings` and requires a Bearer token. The in-memory findings list is intended for MVP use; it is not durable storage. If the secrets are absent, reports remain available as workflow artifacts. Do not point Nuclei at a third-party host or production target without explicit authorization.

## Configuration & Operational Safety

- Keep the deception environment isolated from production networks and data stores.
- Protect telemetry reads (`/api/metrics`, `/api/events`, and all `/api/security/*` routes) with a dedicated `SECURITYMATRIX_READ_TOKEN` Bearer token. Keep it separate from the scanner-only `SECURITYMATRIX_INGEST_TOKEN`.
- For local development only, `SECURITYMATRIX_ALLOW_LOCAL_READS=true` permits unauthenticated reads only when both the TCP peer and Host header are loopback addresses. It is disabled by default; bind the development server to loopback and do not enable this exception behind a reverse proxy.
- Never place `SECURITYMATRIX_READ_TOKEN` in the static dashboard, browser JavaScript, localStorage, or a public GitHub Pages configuration. Remote dashboards need a trusted authenticated reverse proxy/session that injects authorization server-side.
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

## Consent-Based Security Assessment & Remediation

The dashboard includes a consent checkbox and a bounded assessment flow at `POST /api/security/assess`.

- Repository-relative paths are scanned locally with a bounded pattern-based static check (maximum 250 files, 256 KB per file, and 100 findings).
- Optional local Semgrep is enabled only when `SECURITYMATRIX_ENABLE_SEMGREP=true`; the process has a 30-second timeout.
- URL inputs are **passive-only**: they are validated and reported, but the server does not contact the URL or run Nuclei against it. Consent is not proof of ownership and does not make arbitrary active scanning safe.
- The remediation helper provides specific review guidance and a caveat. The approval endpoint records explicit approval for human review; it does **not** modify source code or open a pull request in this version.
- Scan sessions are kept in bounded process memory (up to 100) and disappear when the process restarts. The built-in pattern checks can miss vulnerabilities and produce false positives.
- This is not yet an LLM-backed autonomous patch generator. Do not describe recommendations as verified patches. A future PR integration should use a narrowly scoped GitHub App/token, create a branch and draft PR only, run tests/security checks, and never auto-merge.

Endpoints: `POST /api/security/assess`, `GET /api/security/assess/{scan_id}`, `POST /api/security/assess/{scan_id}/findings/{index}/analyze`, and `POST /api/security/assess/{scan_id}/findings/{index}/approve`.


## Open-source security analysis and remediation

SecurityMatrix does not call hosted LLMs or require external AI API keys. Remediation guidance is generated locally from explicit rule IDs in `app/ai_security.py`; it is advisory only and never edits source code or creates a PR by itself.

### Open-source and GitHub-native components

- **[Semgrep Community Edition](https://github.com/semgrep/semgrep)**: static application security analysis and SARIF output, using rules versioned in this repository (`.semgrep/security.yml`).
- **[Bandit](https://github.com/PyCQA/bandit)**: Python-specific security linting.
- **[pip-audit](https://github.com/pypa/pip-audit)**: known-vulnerability checks for Python dependencies.
- **[Nuclei](https://github.com/projectdiscovery/nuclei)**: DAST checks against the isolated loopback test instance only.
- **[Dependabot](https://github.com/dependabot/dependabot-core)**: native dependency update and security PRs.
- **[GitHub CodeQL](https://github.com/github/codeql) + GitHub Actions**: native static analysis, CI, scheduled scans, artifacts, and review-only dependency-remediation PRs. The PR workflow uses GitHub's built-in `GITHUB_TOKEN`; no personal access token or third-party API key is required.

The `auto-remediation.yml` workflow proposes conservative dependency constraint changes when a compatible fixed version is identified, runs tests, and opens a review-only pull request. It does not merge or deploy. Source-code findings receive deterministic remediation guidance; a developer must implement and review the change. This avoids unsafe generic source rewriting.

Security scans are bounded and do not contact arbitrary URLs. Nuclei targets only `127.0.0.1` in the workflow. Public GitHub repository status is read through the anonymous GitHub REST API; the dashboard does not store credentials in the browser.

## Standalone GitHub dashboard

The dashboard at `app/static/index.html` reads public repository status directly from GitHub's read-only REST API. It refreshes open pull requests and the latest CI, Security Scan, Nuclei DAST, and CodeQL runs every five minutes; it does not store a GitHub token in the browser.

### Enable GitHub Pages

1. Open **Settings → Pages** in this repository.
2. Under **Build and deployment**, set **Source** to **GitHub Actions**.
3. Open **Actions → Deploy SecurityMatrix dashboard to GitHub Pages** and run the workflow, or push a later dashboard change to `main`.
4. After a successful deployment, the site URL will be `https://zopair.github.io/security_matrix/`.

The workflow publishes only `app/static/index.html` as a static site. GitHub Pages cannot run the Python scanner or telemetry API. The remediation guidance is local rule-based logic and does not use an external AI API.

### Connect a FastAPI scanner backend

Deploy the FastAPI application separately over HTTPS, then enter its base URL in the dashboard's **FastAPI backend URL** field. Configure the backend environment variable `SECURITYMATRIX_CORS_ORIGINS=https://zopair.github.io` (include any other exact frontend origins you use, comma-separated). Local development origins are allowed by default. The backend's `/api/config` endpoint exposes only non-secret runtime metadata; No external AI API keys are required; any optional ingestion bearer token remains server-side only.

GitHub's anonymous REST API rate limit applies to public status requests. The dashboard polls GitHub every five minutes and provides a manual refresh button; avoid rapid repeated refreshes.


## Isolated DAST against open-source projects

The `.github/workflows/oss-dast.yml` workflow provides a separate, consent-safe lab for open-source targets:

- Starts the pinned OWASP Juice Shop image `bkimminich/juice-shop:v20.3.0` as a temporary Docker container.
- Publishes the service only on runner loopback (`127.0.0.1:3000`); it does not scan the public demo or any upstream server.
- Runs the pinned Nuclei container `projectdiscovery/nuclei:v3.11.1` with bounded rate/concurrency and the `misconfig,exposure` template tags.
- Removes the target container after the scan and uploads JSONL findings plus a status manifest.

A completed report with zero matching lines means only that the selected templates produced no findings at the configured severities. It is not proof that the target has no vulnerabilities, and it does not cover authenticated business-logic testing or the full OWASP Top 10. The workflow is isolated to the temporary local target and must not be repointed at public or production hosts without explicit authorization.

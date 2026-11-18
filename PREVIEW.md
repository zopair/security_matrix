# SecurityMatrix — Preview Readiness

## What to preview
A defensive cyber-deception MVP with a FastAPI service, synthetic decoy behavior, bounded assessment, security automation, and a static SOC dashboard. Keep simulated findings clearly labelled; a risk score is not proof of an identified attacker.

## Fast local API preview
Requirements: Python 3.11+.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open http://127.0.0.1:8000/docs. The static dashboard is `app/static/index.html`; GitHub Pages publishes only that static asset, not the Python API.

## Suggested 5-minute walkthrough
1. Open the dashboard and distinguish live workflow status from simulated events.
2. Run the consent-based assessment against a repository path inside the isolated preview environment.
3. Inspect bounded findings and the evidence/risk explanation.
4. Review the local Semgrep/CodeQL/pip-audit/Nuclei workflow results.
5. Show that remediation guidance is advisory and requires human implementation/review.

## Preview acceptance
- [ ] `pytest -q` passes.
- [ ] API binds to loopback for local preview.
- [ ] Assessment resource ceilings and consent flow are visible.
- [ ] URL inputs remain passive-only; no arbitrary URL is contacted.
- [ ] Findings and scan sessions are described as in-memory MVP data.
- [ ] Dashboard labels simulated and observed events accurately.
- [ ] No secrets or production telemetry are exposed.

## Known limits to disclose
The built-in scanner is pattern-based and can produce false positives/negatives. Findings and scan sessions are not durable across restarts. Remediation guidance does not modify source code or create code-fix PRs; dependency updates may be proposed for human review. Nuclei is restricted to the temporary loopback test app in CI. A public dashboard requires a separately deployed API with HTTPS, exact CORS origins, secret management, rate limits, and isolation.

## Reviewer evidence
Attach the CI/security workflow links, sanitized assessment response, dashboard screenshot, and deployment configuration with secrets removed. Do not point active scanners at third-party or production systems without explicit authorization.

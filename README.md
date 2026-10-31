# SecurityMatrix

**A simple Arabic/English source-security assessment MVP for public GitHub repositories and local projects.**

SecurityMatrix lets a developer submit a public GitHub repository URL or a local source path, approve a bounded scan, review findings, and read remediation guidance. It is an early-stage static-analysis assistant—not a comprehensive security scanner.

## What is implemented

- Arabic RTL / English LTR responsive interface.
- Consent-gated assessment API protected by a separate read token (or the explicit loopback-only development exception).
- Public GitHub repository import from ZIP archives, including an optional `/tree/branch` URL.
- Local source analysis without executing imported project code.
- Bounded built-in checks for possible hard-coded credentials, `eval()`, `subprocess(..., shell=True)`, and debug settings.
- Optional local Semgrep rules when `SECURITYMATRIX_ENABLE_SEMGREP=true`.
- Findings with severity, file path, line number, evidence excerpt, and remediation guidance.
- Deterministic remediation suggestions for supported rules. Suggestions are advisory; no source files are edited and no fix PR is created automatically.
- GitHub Actions for CI, CodeQL, dependency/security checks, local Nuclei DAST, and an isolated OWASP Juice Shop DAST lab.

## How GitHub repository scanning works

1. The user supplies a public GitHub repository URL and confirms authorization.
2. SecurityMatrix retrieves repository metadata and downloads the source ZIP archive from GitHub.
3. Supported source files are extracted into a temporary local workspace.
4. The bounded static checks run against those files.
5. The UI displays findings and human-reviewed remediation guidance.

The source download is **not** an active security test of the repository owner's website. SecurityMatrix does not probe production hosts, follow URLs found in source files, or execute the downloaded project.

### Import and scan limits

| Limit | Current value |
|---|---:|
| Repository visibility | Public only |
| Repository metadata size | 20 MB |
| ZIP download | 30 MB |
| Extracted supported source | 40 MB |
| Archive entries | 3,000 |
| Files scanned | 250 |
| Maximum individual file | 256 KB |
| Findings returned | 100 |
| Optional Semgrep timeout | 30 seconds |

Unsupported files and oversized files are skipped. The current rules are heuristics: false positives and missed vulnerabilities are possible.

## What is not implemented yet

- Private repository access or GitHub App authorization.
- Dependency installation or full dependency vulnerability analysis for imported projects.
- Build, unit, integration, or regression testing of imported repositories.
- Dynamic testing against a user's staging environment.
- Automatic code fixes, isolated fix branches, or generated remediation pull requests.
- Durable multi-user scan history, workspace isolation between authenticated users, or a hosted production service.

Do not interpret a clean result as proof that a project is secure. Do not submit secrets or private source code to this public-repository-only MVP.

## Run locally

Requirements: Python 3.11+.

```bash
git clone https://github.com/zopair/security_matrix.git
cd security_matrix
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
SECURITYMATRIX_ALLOW_LOCAL_READS=true uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open the interface at [http://127.0.0.1:8000/](http://127.0.0.1:8000/) and API docs at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

The local-read exception is restricted to loopback peer and Host values and must not be enabled behind a reverse proxy. For any remotely reachable deployment, configure `SECURITYMATRIX_READ_TOKEN` and send it as a Bearer token through a trusted server-side session or reverse proxy. Never place it in browser JavaScript or localStorage.

To enable the optional local Semgrep step:

```bash
SECURITYMATRIX_ENABLE_SEMGREP=true
```

Run tests:

```bash
pytest -q
```

## DAST safety boundary

The Nuclei workflows run only against temporary applications started inside GitHub-hosted runners and bound to loopback. The open-source lab workflow uses a pinned OWASP Juice Shop container. It does not accept arbitrary public URLs and must not be repointed at production systems without explicit authorization and a separately reviewed scope.

## Repository workflows

- `.github/workflows/ci.yml` — Python test matrix.
- `.github/workflows/security-scan.yml` — static and dependency checks.
- `.github/workflows/codeql.yml` — CodeQL analysis.
- `.github/workflows/nuclei-dast.yml` — local SecurityMatrix DAST.
- `.github/workflows/oss-dast.yml` — isolated OWASP Juice Shop DAST lab.
- `.github/workflows/auto-remediation.yml` — dependency update proposals only; it does not apply arbitrary source-code fixes.

## Development status

SecurityMatrix is an MVP under active development. The current user journey is **submit public repository/local path → approve → bounded static scan → findings → remediation guidance**. Any capability beyond that is a planned enhancement until implemented and covered by tests.

## License

MIT. See [LICENSE](LICENSE).

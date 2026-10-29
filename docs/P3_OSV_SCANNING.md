# P3: dependency vulnerability scanning with OSV-Scanner

Workflow: `.github/workflows/osv-scanner.yml`

- Runs once weekly (Sunday 03:23 UTC) and supports manual dispatch.
- Runs a differential scan for pull requests that modify dependency manifests.
- Pins Google's official reusable workflow to the immutable commit
  `b1d267aea5211fa648d9d442fa64b90dbdcbdd36` (release v2.7.0).
- Uses least-privilege permissions needed by the reusable workflow:
  `contents: read`, `actions: read`, and `security-events: write` for SARIF.
- Scheduled scans report known vulnerabilities without failing the workflow by
  default; dependency-changing pull requests fail when they introduce new known
  vulnerabilities.
- Concurrency cancels redundant runs in the same workflow/ref group.

OSV-Scanner checks supported manifests/lockfiles against the OSV vulnerability
database. This requires outbound access to OSV services from the GitHub-hosted
runner, but the workflow does not upload source files as a separate artifact.
SARIF results are uploaded to GitHub Code Scanning, and the reusable workflow
retains its SARIF artifact for five days.

The weekly schedule is best-effort and GitHub may delay scheduled workflows.
This configuration has been committed to a feature branch; it is not considered
operational until merged and a real run completes. Review findings before
upgrading dependencies. Do not enable automatic dependency changes as part of
this scanner workflow.

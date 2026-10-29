# Security Policy

## Reporting a vulnerability

Please do not publish exploitable details, credentials, or private user data in a public issue. Open a private vulnerability report through GitHub's Security tab when available, or contact the repository maintainers through a private channel.

Include the affected commit, reproducible steps, impact, and a proposed mitigation where possible. Allow maintainers reasonable time to investigate before public disclosure.

## Automated scanning boundaries

- Static and dependency scans operate on repository contents and declared dependencies.
- Nuclei in CI targets only the loopback test instance started by the workflow.
- Do not point automated scanners at third-party systems or any target without explicit authorization.
- Scanner findings are leads for review, not proof of exploitability.
- Automated remediation creates a pull request for human review; it does not merge or deploy changes.
- Never commit production logs, secrets, credentials, or unredacted HTTP traffic to this repository.

## Reporting quality

When sharing scan output, remove authorization headers, cookies, tokens, personal data, and raw request/response bodies unless they are essential and have been safely redacted.

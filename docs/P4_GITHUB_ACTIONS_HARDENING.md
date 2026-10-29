# P4: GitHub Actions supply-chain and resource hardening

## Immutable action references

Workflow actions are pinned to full commit SHAs, with the upstream release noted
in comments. The OSV reusable workflow is pinned separately in
`.github/workflows/osv-scanner.yml`. Pinning prevents a mutable tag from silently
moving to different action code; it does not eliminate the need to review and
update pins when upstream releases security fixes.

## Permissions and execution limits

- CI has `contents: read`, a 10-minute job timeout, and cancels superseded runs
  for the same ref.
- CodeQL and security-report workflows use read-only repository access plus
  `security-events: write` and `actions: read` only where SARIF upload needs it.
- Pages deployment keeps only `contents: read`, `pages: write`, and
  `id-token: write`, which are required for publishing.
- The dependency-proposal workflow keeps write permissions because it creates a
  review-only PR; it does not merge or deploy automatically.
- Existing scheduled jobs remain weekly. No high-frequency schedule or bulk
  repository activity was added.

## Operational notes

- DAST remains restricted to the loopback test instance, with low request rate
  and concurrency settings.
- Scheduled OSV scans run weekly and PR scans run only when dependency manifests
  change; duplicate workflow/ref runs are cancelled.
- Any pin update should be reviewed against the upstream release and commit
  before merging. Keep the comment's release label synchronized with the SHA.
- These workflow changes are proposals on a feature branch until reviewed and
  merged. Inspect the Actions logs after the first real run; do not infer success
  from the YAML alone.

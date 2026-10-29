# Trend keyword maintenance and safe project promotion

## 1. Every-10-minute keyword refresh

`.github/workflows/trending-keywords.yml` runs on `*/10 * * * *` and can also be run manually. The Python script queries the GitHub Search API for repositories created in the last seven days with at least five stars, then derives normalized, deduplicated terms from repository topics, names, and descriptions. It writes `config/trending_keywords.json`.

**Important scope:** GitHub does not expose a universal free API for “the most searched keywords everywhere.” This script measures a limited proxy—topics appearing in recently created, popular GitHub repositories—not Google search trends or all GitHub searches. The workflow avoids noisy commits: it updates only when the keyword set changes materially or duplicate/non-canonical entries need cleanup.

GitHub scheduled Actions are best-effort, not a real-time SLA; a scheduled run can be delayed or dropped during heavy load. Use this for periodic metadata, not timing-critical jobs.

## 2. Promotion drafts, not automated broadcasting

Run:

```bash
python scripts/generate_promo_drafts.py
```

It writes `promo-kit/drafts.md` with a repository description suggestion and platform-neutral announcement drafts. It **does not** post to GitHub issues, other people's discussions, social networks, or third-party APIs. Review and tailor each post manually.

An external reference worth evaluating is [RepoRoar-skill](https://github.com/fly233338/RepoRoar-skill), which describes generating a local promotion kit for human review rather than auto-posting.

## 3. Safe operating rules

- Keep the keyword workflow restricted to `contents: write`; do not add secrets or third-party API keys.
- Never rotate topics every ten minutes. Set a stable, accurate description/topics manually and review them monthly.
- Do not automatically add trending but unrelated topics, edit other users' content, mass-comment, mass-mention, or solicit artificial stars.
- Avoid unverified claims such as “revolutionary,” “fully autonomous,” or “neutralizes all AI agents.” Prefer specific, testable descriptions.
- GitHub's Acceptable Use Policy allows relevant promotional material in a repository's README/description, but prohibits excessive automated bulk activity and deceptive promotion.

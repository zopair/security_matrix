#!/usr/bin/env python3
"""Refresh a deduplicated keyword list from recently popular GitHub repositories.

This is a proxy for developer-topic momentum, not a claim to measure global search trends.
Uses only the GitHub REST Search API and Python's standard library.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "config" / "trending_keywords.json"
TOP_N = 25
MIN_STARS = 5
WINDOW_DAYS = 7
MIN_SET_CHANGES = 3
STOPWORDS = {
    "the", "and", "for", "with", "from", "into", "using", "use", "used",
    "tool", "tools", "project", "projects", "repo", "repository", "github",
    "open", "source", "open-source", "awesome", "best", "new", "simple",
    "app", "application", "library", "libraries", "framework", "based",
    "build", "built", "make", "made", "your", "you", "that", "this", "are",
    "was", "will", "can", "all", "not", "how", "what", "when", "where",
    "about", "more", "free", "easy", "fast", "code", "coding", "software",
    "python", "javascript", "typescript", "html", "css", "api",
}
TOKEN_RE = re.compile(r"[a-z][a-z0-9+#.-]{2,}")

def normalize(value: str) -> str:
    value = value.strip().lower().replace("_", "-")
    value = re.sub(r"\s+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")

def fetch_repositories() -> list[dict]:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required (pass github.token from Actions).")
    since = (datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)).date().isoformat()
    query = f"created:>={since} stars:>={MIN_STARS}"
    params = urlencode({"q": query, "sort": "stars", "order": "desc", "per_page": 30})
    request = Request(
        f"https://api.github.com/search/repositories?{params}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SecurityMatrix-keyword-maintenance",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"GitHub Search API request failed: {exc}") from exc
    return payload.get("items", [])

def derive_keywords(repositories: list[dict]) -> list[str]:
    scores: Counter[str] = Counter()
    for repo in repositories:
        # Search results may include topics; do not make extra API calls per repository.
        for topic in repo.get("topics") or []:
            keyword = normalize(topic)
            if len(keyword) >= 3 and keyword not in STOPWORDS:
                scores[keyword] += 3
        name = str(repo.get("name") or "").replace("_", "-")
        for token in TOKEN_RE.findall(name.lower()):
            keyword = normalize(token)
            if keyword not in STOPWORDS:
                scores[keyword] += 2
        description = str(repo.get("description") or "").lower()
        for token in TOKEN_RE.findall(description):
            keyword = normalize(token)
            if keyword not in STOPWORDS:
                scores[keyword] += 1
    # Deterministic tie-breaking keeps file diffs stable.
    return [word for word, _ in sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:TOP_N]]

def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    repositories = fetch_repositories()
    proposed = derive_keywords(repositories)
    if not proposed:
        print("No usable keywords found; leaving the existing file unchanged.")
        return 0

    existing = {}
    if OUTPUT.exists():
        try:
            existing = json.loads(OUTPUT.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}
    raw_current = existing.get("keywords", [])
    if not isinstance(raw_current, list):
        raw_current = []
    current = [normalize(str(word)) for word in raw_current if normalize(str(word))]
    deduped_current = list(dict.fromkeys(current))
    changed_count = len(set(proposed) ^ set(deduped_current))
    needs_cleanup = current != deduped_current or raw_current != deduped_current
    if OUTPUT.exists() and not needs_cleanup and changed_count < MIN_SET_CHANGES:
        print(f"Trend changed by only {changed_count} keyword(s); skip commit to avoid noisy history.")
        return 0

    output = {
        "source": "GitHub Search API: repositories created in the last 7 days, sorted by stars",
        "window_days": WINDOW_DAYS,
        "minimum_stars": MIN_STARS,
        "keywords": proposed,
    }
    OUTPUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(proposed)} unique keywords from {len(repositories)} repositories to {OUTPUT.relative_to(ROOT)}.")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"keyword refresh failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

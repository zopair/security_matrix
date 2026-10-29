#!/usr/bin/env python3
"""Generate factual promotion drafts for human review; never posts to external services."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYWORDS = ROOT / "config" / "trending_keywords.json"
README = ROOT / "README.md"
OUT = ROOT / "promo-kit" / "drafts.md"

def main() -> None:
    data = json.loads(KEYWORDS.read_text(encoding="utf-8")) if KEYWORDS.exists() else {"keywords": []}
    keywords = [str(k) for k in data.get("keywords", [])[:8]]
    keyword_line = ", ".join(keywords) if keywords else "application security, Python, DevSecOps"
    readme = README.read_text(encoding="utf-8") if README.exists() else ""
    # Keep claims tied to the repository's stated scope; do not invent metrics or capabilities.
    if "cyber deception" in readme.lower():
        positioning = "SecurityMatrix is an open-source defensive cyber-deception reference implementation for observing suspicious automated reconnaissance in a controlled, isolated environment."
    else:
        positioning = "SecurityMatrix is an open-source security project; review the README and current implementation before making capability claims."
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(f"""# SecurityMatrix — promotion drafts (human review required)

Generated locally from repository content and the current keyword snapshot. **Nothing is published automatically.**

## Repository description suggestion

{positioning}

## Short announcement

We're building SecurityMatrix, an open-source defensive cyber-deception reference implementation focused on observable signals, synthetic decoys, and bounded, auditable behavior. It is an evolving MVP—not a claim of autonomous AI threat neutralization. Contributions and security-focused feedback are welcome.

## Technical community post draft

Project: https://github.com/zopair/security_matrix

SecurityMatrix explores defensive cyber deception in an isolated environment, with a Python/FastAPI implementation and GitHub Actions security checks. The current implementation is a reference/MVP, so please review the documented limitations before using it beyond a lab. Feedback on detection rules, isolation boundaries, and reproducible tests is welcome.

## Discovery terms to consider (not all should be applied as GitHub topics)

{keyword_line}

## Before publishing

- Adapt the message to the destination community and follow its self-promotion rules.
- Do not post repeatedly, mass-mention users, create engagement-bait issues, or ask for artificial stars.
- Only keep topics that accurately describe this repository; trending terms are suggestions, not automatic metadata.
- Verify every capability claim against code and tests.
""", encoding="utf-8")
    print(f"Drafts written to {OUT.relative_to(ROOT)}. Review manually; no posting was performed.")

if __name__ == "__main__":
    main()

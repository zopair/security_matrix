"""Normalize Semgrep SARIF, pip-audit JSON, Bandit JSON and Nuclei JSONL.

Only concise metadata is exported. Raw HTTP requests/responses and secrets are
intentionally excluded from the SOC payload.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "security-findings.json"
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


def severity(value: Any) -> str:
    value = str(value or "unknown").lower()
    return value if value in SEVERITIES else "unknown"


def add(items: list[dict[str, str]], source: str, sev: Any, title: Any,
        rule_id: Any = "", target: Any = "", details: Any = "") -> None:
    items.append({
        "source": source[:40],
        "severity": severity(sev),
        "title": str(title or "Security finding")[:240],
        "rule_id": str(rule_id or "")[:120],
        "target": str(target or "")[:300],
        "details": str(details or "")[:500],
    })


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def main() -> None:
    findings: list[dict[str, str]] = []
    sarif = load_json(ROOT / "semgrep.sarif")
    if isinstance(sarif, dict):
        for run in sarif.get("runs", []):
            rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})
                location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
                artifact = location.get("artifactLocation", {}).get("uri", "")
                region = location.get("region", {})
                target = f"{artifact}:{region.get('startLine', '')}".rstrip(":")
                level = result.get("level", "warning")
                sev = {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "unknown")
                add(findings, "semgrep", sev, result.get("message", {}).get("text") or rule.get("shortDescription", {}).get("text"), rule_id, target)

    audit = load_json(ROOT / "pip-audit.json")
    if isinstance(audit, dict):
        for dep in audit.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                fixes = vuln.get("fix_versions") or []
                add(findings, "pip-audit", "high", vuln.get("id", "Dependency vulnerability"),
                    vuln.get("id", ""), dep.get("name", ""), "Fixed versions: " + ", ".join(map(str, fixes[:5])))

    bandit = load_json(ROOT / "bandit.json")
    if isinstance(bandit, dict):
        for issue in bandit.get("results", []):
            sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(str(issue.get("issue_severity", "")).upper(), "unknown")
            target = f"{issue.get('filename', '')}:{issue.get('line_number', '')}".rstrip(":")
            add(findings, "bandit", sev, issue.get("issue_text"), issue.get("test_id"), target)

    nuclei_path = ROOT / "nuclei-results.jsonl"
    try:
        lines = nuclei_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines[:1000]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        add(findings, "nuclei", info.get("severity"), info.get("name") or item.get("template-id"),
            item.get("template-id"), item.get("matched-at") or item.get("host"), info.get("description", ""))

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "securitymatrix-github-actions",
        "findings": findings[:500],
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Normalized {len(payload['findings'])} scanner findings into {OUT.name}")


if __name__ == "__main__":
    main()

"""Consent-gated, bounded security assessment and remediation proposal helpers.

Only scans paths inside the configured local checkout. URL targets are validated
but never contacted by this MVP, preventing SSRF and unauthorized active scans.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 250
MAX_FILE_BYTES = 256_000
ALLOWED_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".json", ".yml", ".yaml", ".toml", ".ini", ".env.example"}
SECRET_PATTERNS = [
    ("possible-hardcoded-secret", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "Potential hard-coded credential. Move it to a secret manager and rotate it if real."),
    ("unsafe-eval", re.compile(r"\beval\s*\("), "Avoid evaluating untrusted input; replace with a constrained parser or explicit dispatch."),
    ("subprocess-shell", re.compile(r"subprocess\.(?:run|Popen|call)\([^\n]*shell\s*=\s*True"), "Avoid shell=True with untrusted values; pass an argument list and validate inputs."),
    ("debug-mode", re.compile(r"(?i)(?:debug\s*=\s*True|DEBUG\s*=\s*['\"]?true)"), "Disable debug mode in production and configure safe error handling."),
]


def _inside_repo(path: Path) -> bool:
    """Containment check after resolving symlinks and relative path segments."""
    return path == REPO_ROOT or REPO_ROOT in path.parents


def validate_target(target: str) -> dict[str, str]:
    value = (target or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("Invalid scan target.")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Invalid scan target.")
        # Deliberately no outbound request: URL checks are passive-only in this MVP.
        return {"kind": "url", "target": value}

    supplied_path = Path(value)
    if supplied_path.is_absolute() or ".." in supplied_path.parts:
        raise ValueError("Invalid scan target.")
    try:
        resolved = (REPO_ROOT / supplied_path).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise ValueError("Invalid scan target.") from None
    if not _inside_repo(resolved):
        raise ValueError("Invalid scan target.")
    if not (resolved.is_file() or resolved.is_dir()):
        raise ValueError("Invalid scan target.")
    if resolved.is_file() and resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        raise ValueError("Unsupported scan target type.")
    return {"kind": "path", "target": str(resolved)}


def scan_target(target: str) -> dict[str, Any]:
    validated = validate_target(target)
    findings: list[dict[str, Any]] = []
    if validated["kind"] == "url":
        findings.append({
            "id": "url-passive-only", "severity": "info", "title": "URL accepted for passive review only",
            "rule_id": "SAFETY-URL-001", "target": validated["target"],
            "details": "No network request or active probe was sent. Provide a repository-relative source path for local static analysis.",
            "recommendation": "Run a separately authorized scan from an isolated environment if active testing is required.",
            "patch": None,
        })
        return {"target": validated["target"], "mode": "passive-url-only", "findings": findings}

    root = Path(validated["target"])
    if not _inside_repo(root):
        raise ValueError("Invalid scan target.")
    if root.is_file():
        files = [root]
    else:
        # Resolve each discovered entry and reject symlinks escaping the checkout.
        files = []
        for candidate in root.rglob("*"):
            try:
                if candidate.is_file() and candidate.suffix.lower() in ALLOWED_SUFFIXES:
                    resolved_candidate = candidate.resolve(strict=True)
                    if _inside_repo(resolved_candidate) and resolved_candidate.is_file():
                        files.append(resolved_candidate)
            except (OSError, RuntimeError, ValueError):
                continue
        files.sort(key=lambda item: item.as_posix())
    files = files[:MAX_FILES]
    for file in files:
        try:
            if not _inside_repo(file) or file.stat().st_size > MAX_FILE_BYTES:
                continue
            content = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = file.relative_to(REPO_ROOT).as_posix()
        for line_no, line in enumerate(content.splitlines(), start=1):
            for rule_id, pattern, recommendation in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "id": f"{rule_id}:{relative}:{line_no}", "severity": "high" if rule_id == "possible-hardcoded-secret" else "medium",
                        "title": rule_id.replace("-", " ").title(), "rule_id": rule_id, "target": relative,
                        "line": line_no, "details": line.strip()[:240], "recommendation": recommendation,
                        "patch": None,
                    })
                    if len(findings) >= 100:
                        break
            if len(findings) >= 100:
                break
        if len(findings) >= 100:
            break
    # Optional Semgrep: local repository only, bounded timeout, no network rules.
    if os.getenv("SECURITYMATRIX_ENABLE_SEMGREP", "").lower() == "true":
        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config", str(REPO_ROOT / ".semgrep" / "security.yml"), "--json", "--metrics", "off", str(root)],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
                env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
            )
            import json
            report = json.loads(result.stdout or "{}")
            for item in report.get("results", [])[:100]:
                findings.append({
                    "id": "semgrep:" + str(item.get("check_id", "")) + ":" + str(item.get("start", {}).get("line", 0)),
                    "severity": str(item.get("extra", {}).get("severity", "WARNING")).lower(),
                    "title": str(item.get("extra", {}).get("message", "Semgrep finding"))[:240],
                    "rule_id": str(item.get("check_id", ""))[:120],
                    "target": str(item.get("path", ""))[:300],
                    "line": item.get("start", {}).get("line"),
                    "details": "Local Semgrep static-analysis result.",
                    "recommendation": "Review the rule documentation and validate a minimal patch in tests.",
                    "patch": None,
                })
        except (OSError, subprocess.TimeoutExpired, ValueError):
            findings.append({
                "id": "semgrep-unavailable", "severity": "info", "title": "Optional Semgrep scan unavailable",
                "rule_id": "SCANNER-OPTIONAL", "target": root.relative_to(REPO_ROOT).as_posix(),
                "details": "The built-in bounded pattern scan completed; Semgrep was not available or timed out.",
                "recommendation": "Install Semgrep and set SECURITYMATRIX_ENABLE_SEMGREP=true to enable the optional local scan.",
                "patch": None,
            })
    return {"target": root.relative_to(REPO_ROOT).as_posix(), "mode": "local-static-analysis", "files_checked": len(files), "findings": findings}


def propose_remediation(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a human-reviewed remediation plan, not an automatically applied patch."""
    rule = str(finding.get("rule_id", ""))
    plans = {
        "possible-hardcoded-secret": ("Move the value to an environment variable or secret manager, rotate the credential if real, and add a safe example to documentation.", "No safe universal source patch can be inferred from a single matching line."),
        "unsafe-eval": ("Replace eval with a strict parser or a fixed mapping of permitted operations.", "The correct patch depends on the expected input grammar; no source is modified automatically."),
        "subprocess-shell": ("Use subprocess.run([program, arg1, arg2], check=True, shell=False) and validate each argument.", "Review quoting and command semantics before applying a change."),
        "debug-mode": ("Disable debug mode by default and read deployment configuration from a validated environment setting.", "Confirm the production configuration and test error handling."),
    }
    recommendation, caveat = plans.get(rule, ("Review the finding and implement the smallest validated fix.", "No source files were changed."))
    return {"finding_id": str(finding.get("id", ""))[:300], "rule_id": rule[:120], "recommendation": recommendation, "caveat": caveat, "patch": None, "requires_human_review": True}

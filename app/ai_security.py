"""Consent-gated bounded static checks for local code and public GitHub archives.

Imported source is stored in temporary local workspaces and never executed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
IMPORTED_ROOTS: set[Path] = set()
IMPORTED_REPOSITORIES: dict[str, Path] = {}
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
    roots = (REPO_ROOT, *tuple(IMPORTED_ROOTS))
    return any(path == root or root in path.parents for root in roots)


class _GitHubRedirectGuard(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in {"api.github.com", "codeload.github.com"}:
            raise ValueError("Unexpected repository archive redirect.")
        return super().redirect_request(request, response, code, message, headers, newurl)


def import_github_repository(value: str) -> tuple[Path, dict[str, str]]:
    """Import a public GitHub source archive with strict download and extraction bounds."""
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Only public HTTPS GitHub repository URLs are supported.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) not in {2, 4} or (len(parts) == 4 and parts[2] != "tree"):
        raise ValueError("Enter a GitHub repository URL, optionally with /tree/branch.")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo):
        raise ValueError("Invalid GitHub repository URL.")
    key = owner + "/" + repo
    branch_hint = parts[3] if len(parts) == 4 else ""
    cache_key = key + "@" + branch_hint
    cached = IMPORTED_REPOSITORIES.get(cache_key)
    if cached and cached.exists():
        return cached, {"repository": key, "branch": branch_hint or "default", "source": "cached public archive"}
    opener = urllib.request.build_opener(_GitHubRedirectGuard())
    headers = {"User-Agent": "SecurityMatrix-Local-Scanner/1.0", "Accept": "application/vnd.github+json"}
    try:
        req = urllib.request.Request("https://api.github.com/repos/" + key, headers=headers)
        with opener.open(req, timeout=12) as response:
            if urlparse(response.geturl()).hostname not in {"api.github.com"}:
                raise ValueError("Unexpected GitHub metadata redirect.")
            metadata = json.loads(response.read(262144).decode("utf-8"))
        if metadata.get("private") or metadata.get("archived") or int(metadata.get("size", 0) or 0) > 20000:
            raise ValueError("Repository is private, archived, or exceeds the 20 MB repository limit.")
        branch = parts[3] if len(parts) == 4 else str(metadata.get("default_branch") or "main")
        if not re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", branch) or ".." in PurePosixPath(branch).parts:
            raise ValueError("Invalid repository branch.")
        archive_url = "https://api.github.com/repos/" + key + "/zipball/" + branch
        req = urllib.request.Request(archive_url, headers=headers)
        with opener.open(req, timeout=20) as response:
            if urlparse(response.geturl()).hostname not in {"codeload.github.com", "api.github.com"}:
                raise ValueError("Unexpected GitHub archive redirect.")
            archive_data = response.read(30 * 1024 * 1024 + 1)
    except ValueError:
        raise
    except Exception:
        raise ValueError("Could not access or download this public GitHub repository.") from None
    if len(archive_data) > 30 * 1024 * 1024:
        raise ValueError("Repository archive exceeds the 30 MB download limit.")
    workspace = Path(tempfile.mkdtemp(prefix="securitymatrix-oss-"))
    extracted = workspace / "source"
    extracted.mkdir()
    count = total = 0
    try:
        with zipfile.ZipFile(BytesIO(archive_data)) as archive:
            members = archive.infolist()
            if len(members) > 3000:
                raise ValueError("Repository contains too many archive entries.")
            for member in members:
                if member.is_dir():
                    continue
                rel = PurePosixPath(member.filename)
                if rel.is_absolute() or ".." in rel.parts or len(rel.parts) < 2:
                    continue
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000 or Path(rel.name).suffix.lower() not in ALLOWED_SUFFIXES:
                    continue
                if member.file_size > MAX_FILE_BYTES:
                    continue
                total += member.file_size
                if total > 40 * 1024 * 1024:
                    raise ValueError("Extracted repository source exceeds the 40 MB limit.")
                destination = extracted.joinpath(*rel.parts[1:])
                destination.parent.mkdir(parents=True, exist_ok=True)
                data = archive.read(member)
                if len(data) == member.file_size:
                    destination.write_bytes(data)
                    count += 1
        if count == 0:
            raise ValueError("No supported source files were found.")
    except Exception:
        shutil.rmtree(workspace, ignore_errors=True)
        raise
    extracted = extracted.resolve()
    IMPORTED_ROOTS.add(extracted)
    IMPORTED_REPOSITORIES[cache_key] = extracted
    while len(IMPORTED_REPOSITORIES) > 5:
        old_key = next(iter(IMPORTED_REPOSITORIES))
        old_path = IMPORTED_REPOSITORIES.pop(old_key)
        IMPORTED_ROOTS.discard(old_path)
        shutil.rmtree(old_path.parent, ignore_errors=True)
    return extracted, {"repository": key, "branch": branch, "files_imported": str(count), "source": "public GitHub ZIP archive"}


def validate_target(target: str):
    value = (target or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("Invalid scan target.")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        imported, metadata = import_github_repository(value)
        return {"kind": "github", "target": str(imported), **metadata}

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
                "rule_id": "SCANNER-OPTIONAL", "target": validated.get("repository", root.relative_to(REPO_ROOT).as_posix()),
                "details": "The built-in bounded pattern scan completed; Semgrep was not available or timed out.",
                "recommendation": "Install Semgrep and set SECURITYMATRIX_ENABLE_SEMGREP=true to enable the optional local scan.",
                "patch": None,
            })
    imported = validated["kind"] == "github"
    return {
        "target": validated.get("repository", root.relative_to(REPO_ROOT).as_posix()),
        "mode": "github-repository-static-analysis" if imported else "local-static-analysis",
        "repository": validated.get("repository"),
        "branch": validated.get("branch"),
        "files_imported": int(validated.get("files_imported", 0)) if imported else None,
        "files_checked": len(files),
        "findings": findings,
        "limitations": ["Public GitHub repositories only", "30 MB archive download and 40 MB extracted source limits", "3,000 archive entries maximum", "At most 250 supported files and 100 findings", "Static checks only; no code execution, build, dependency installation, or active DAST"],
    }


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

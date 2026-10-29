"""Create a conservative requirements.txt patch from pip-audit JSON.

Only direct dependencies with a published fixed version are considered.
Changes are proposed in a pull request and are never merged automatically.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
REQ_FILE = ROOT / "requirements.txt"
AUDIT_FILE = ROOT / "pip-audit.json"


def main() -> int:
    try:
        audit = json.loads(AUDIT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("No valid pip-audit report; no remediation proposed.")
        return 0

    lines = REQ_FILE.read_text(encoding="utf-8").splitlines()
    requirements: dict[str, tuple[int, Requirement, str]] = {}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(("-", ".")):
            continue
        try:
            req = Requirement(stripped)
        except Exception:
            continue
        requirements[req.name.lower().replace("_", "-")] = (index, req, line)

    desired: dict[str, Version] = {}
    for dep in audit.get("dependencies", []):
        key = str(dep.get("name", "")).lower().replace("_", "-")
        if key not in requirements:
            continue
        for vuln in dep.get("vulns", []):
            versions = []
            for raw in vuln.get("fix_versions") or []:
                try:
                    versions.append(Version(str(raw)))
                except InvalidVersion:
                    continue
            if versions:
                candidate = min(versions)
                desired[key] = max(desired.get(key, candidate), candidate)

    changed = False
    for key, fixed in desired.items():
        index, req, original = requirements[key]
        upper_bounds = []
        for spec in req.specifier:
            if spec.operator in {"<", "<="}:
                upper_bounds.append((spec.operator, spec.version))
        upper = min(upper_bounds, key=lambda x: Version(x[1])) if upper_bounds else None
        if upper:
            try:
                if fixed >= Version(upper[1]):
                    print(f"Skip {req.name}: fixed version {fixed} conflicts with upper bound {upper[1]}.")
                    continue
            except InvalidVersion:
                continue
        spec = f">={fixed}" + (f",{upper[0]}{upper[1]}" if upper else "")
        replacement = f"{req.name}{'[' + ','.join(req.extras) + ']' if req.extras else ''}{spec}"
        if replacement != original.strip():
            lines[index] = replacement
            changed = True
            print(f"Proposed {req.name}: {original.strip()} -> {replacement}")

    if changed:
        REQ_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    output_path = os.getenv("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as stream:
            stream.write(f"changed={'true' if changed else 'false'}\n")
    if not changed:
        print("No safe direct-dependency fix could be proposed; no PR will be opened.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

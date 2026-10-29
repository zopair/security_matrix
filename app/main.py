"""SecurityMatrix defensive cyber-deception MVP.

Synthetic data only. Heuristics are not proof that a request came from an AI agent.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from app.ai_security import scan_target, propose_remediation
from app.deception import ENABLED as DECEPTION_ENABLED
from app.deception import router as deception_router

APP_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = APP_ROOT / "static"
LOG_PATH = Path(os.getenv("SECURITYMATRIX_LOG_PATH", "logs/events.jsonl"))
MAX_EVENTS = max(100, min(int(os.getenv("SECURITYMATRIX_MAX_EVENTS", "1000")), 10000))
MAX_LOG_BYTES = max(65536, min(int(os.getenv("SECURITYMATRIX_MAX_LOG_BYTES", "1048576")), 10485760))
MAX_BODY_BYTES = 1_048_576
MAX_ASSESS_BODY_BYTES = 16_384
INGEST_TOKEN = os.getenv("SECURITYMATRIX_INGEST_TOKEN", "")
DECOY_PATHS = {"/api/v1/admin/master-key-dump", "/api/v1/internal/service-registry", "/api/decoy/assets"}
EVENT_LOCK = threading.Lock()
ASSESSMENT_LOCK = threading.Lock()

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("securitymatrix")

EVENTS: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
STARTED_AT = time.time()
ASSESSMENTS: dict[str, dict[str, Any]] = {}

SUSPICIOUS_PATHS = (
    re.compile(r"(^|/)[.]env(?:$|/)", re.I),
    re.compile(r"(^|/)(?:wp-admin|phpmyadmin|admin-console)(?:/|$)", re.I),
    re.compile(r"(^|/)(?:[.]git|server-status)(?:/|$)", re.I),
    re.compile(r"(^|/)(?:swagger[.]json|openapi[.]json)(?:$|/)", re.I),
)
SUSPICIOUS_TERMS = ("union select", "../", "%2e%2e%2f", "<script", " or 1=1")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_request(path: str, query: str, method: str) -> tuple[int, list[str]]:
    """Explainable, low-cost heuristics; never infer agent identity."""
    signals: list[str] = []
    normalized = f"{path}?{query}".lower()
    if any(pattern.search(path) for pattern in SUSPICIOUS_PATHS):
        signals.append("sensitive_path_probe")
    if any(term in normalized for term in SUSPICIOUS_TERMS):
        signals.append("suspicious_input_pattern")
    if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        signals.append("unusual_http_method")
    return min(100, len(signals) * 35), signals


def record_event(event: dict[str, Any]) -> None:
    """Keep event memory bounded and rotate the JSONL file at a fixed size."""
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + chr(10)
    with EVENT_LOCK:
        EVENTS.appendleft(event)
        try:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            if LOG_PATH.exists() and LOG_PATH.stat().st_size + len(line.encode("utf-8")) > MAX_LOG_BYTES:
                backup = LOG_PATH.with_suffix(LOG_PATH.suffix + ".1")
                try:
                    backup.unlink(missing_ok=True)
                    LOG_PATH.replace(backup)
                except OSError:
                    logger.warning("Unable to rotate event log; disk audit output skipped")
                    return
            with LOG_PATH.open("a", encoding="utf-8") as stream:
                stream.write(line)
        except OSError:
            logger.warning("Unable to persist event log; in-memory event retained")


def event_summary() -> dict[str, Any]:
    with EVENT_LOCK:
        snapshot = list(EVENTS)
    by_decision = Counter(str(event.get("decision", "unknown")) for event in snapshot)
    return {
        "event_count": len(snapshot),
        "decisions": dict(by_decision),
        "uptime_seconds": max(0, int(time.time() - STARTED_AT)),
        "sandbox_mode": "synthetic-only",
        "deception_enabled": DECEPTION_ENABLED,
        "security_findings": sum(1 for event in snapshot if event.get("decision") == "finding"),
    }


async def read_limited_body(request: Request, limit: int) -> bytes | None:
    """Read at most limit bytes, including when Content-Length is absent or false."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > limit:
                return None
        except ValueError:
            return None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


app = FastAPI(
    title="SecurityMatrix",
    description="Defensive cyber-deception reference API. Synthetic data only.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
)
CORS_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "SECURITYMATRIX_CORS_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Request-ID", "X-SecurityMatrix-Decision"],
)
app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")
app.include_router(deception_router)


@app.middleware("http")
async def request_gateway(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))[:128]
    path = request.url.path
    query = request.url.query[:2048]
    score, signals = classify_request(path, query, request.method)

    # Detection is telemetry only. Never turn arbitrary suspicious/unknown paths
    # into successful synthetic responses; only explicit opt-in decoy routes do that.
    response = await call_next(request)
    if path not in {"/", "/api/events", "/api/metrics", "/api/security/findings", "/health", "/api/health"}:
        if path in DECOY_PATHS and response.headers.get("X-SecurityMatrix-Decision") == "decoy":
            decision = "decoy"
        elif response.status_code == 404 and score >= 35:
            decision = "suspicious_not_found"
        else:
            decision = "allow"
        record_event({
            "timestamp": utc_now(),
            "request_id": request_id,
            "method": request.method,
            "path": path[:512],
            "decision": decision,
            "risk_score": score,
            "signals": signals,
            "source": "request_metadata_only",
            "outcome": f"http_{response.status_code}",
        })
    response.headers["X-Request-ID"] = request_id
    response.headers.setdefault("X-SecurityMatrix-Decision", "allow")
    return response


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard() -> HTMLResponse:
    index = STATIC_ROOT / "index.html"
    return HTMLResponse(index.read_text(encoding="utf-8"))


@app.get("/health")
@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "securitymatrix", "sandbox": "synthetic-only"}


@app.get("/api/config")
async def public_config() -> dict[str, Any]:
    """Non-secret runtime details for the standalone GitHub Pages frontend."""
    return {
        "service": "securitymatrix",
        "repository": os.getenv("GITHUB_REPOSITORY", "zopair/security_matrix"),
        "github_api": "https://api.github.com/repos/zopair/security_matrix",
        "scanner_enabled": True,
        "remediation_mode": "deterministic-open-source-rules",
        "external_ai_required": False,
        "security_tools": ["Semgrep", "Bandit", "pip-audit", "Nuclei", "Dependabot", "GitHub Actions"],
        "cors_origins_configured": len(CORS_ORIGINS),
        "deception_enabled": DECEPTION_ENABLED,
    }


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    return event_summary()


@app.get("/api/events")
async def events(limit: int = 100) -> dict[str, Any]:
    bounded_limit = max(1, min(limit, 200))
    with EVENT_LOCK:
        snapshot = list(EVENTS)[:bounded_limit]
    return {"events": snapshot, "summary": event_summary()}


@app.get("/api/security/findings")
async def security_findings(limit: int = 100) -> dict[str, Any]:
    """Return bounded scanner findings received by the optional authenticated ingest endpoint."""
    bounded_limit = max(1, min(limit, 200))
    with EVENT_LOCK:
        findings = [event for event in EVENTS if event.get("decision") == "finding"]
    return {"findings": findings[:bounded_limit], "count": len(findings)}


@app.post("/api/security/findings")
async def ingest_security_findings(request: Request) -> JSONResponse:
    """Ingest normalized scanner metadata; never accept raw request/response payloads."""
    if not INGEST_TOKEN:
        return JSONResponse(status_code=503, content={"error": "scanner ingestion is not configured"})
    supplied = request.headers.get("authorization", "")
    if not hmac.compare_digest(supplied, f"Bearer {INGEST_TOKEN}"):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    raw = await read_limited_body(request, MAX_BODY_BYTES)
    if raw is None:
        return JSONResponse(status_code=413, content={"error": "payload too large"})
    try:
        payload = json.loads(raw or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"error": "invalid JSON"})
    if not isinstance(payload, dict) or not isinstance(payload.get("findings", []), list):
        return JSONResponse(status_code=400, content={"error": "expected a findings array"})
    incoming = payload.get("findings", [])[:100]
    accepted = 0
    allowed_severities = {"critical", "high", "medium", "low", "info", "unknown"}
    for item in incoming:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "unknown")).lower()
        if severity not in allowed_severities:
            severity = "unknown"
        record_event({
            "timestamp": utc_now(),
            "decision": "finding",
            "source": str(item.get("source", "scanner"))[:40],
            "severity": severity,
            "title": str(item.get("title", "Security finding"))[:240],
            "rule_id": str(item.get("rule_id", ""))[:120],
            "target": str(item.get("target", ""))[:300],
            "details": str(item.get("details", ""))[:500],
            "outcome": "reported",
        })
        accepted += 1
    return JSONResponse(status_code=202, content={"accepted": accepted, "stored_in_memory": True})


@app.post("/api/security/assess")
async def start_security_assessment(request: Request) -> JSONResponse:
    """Run a consent-gated local static scan; URL inputs are never contacted."""
    raw = await read_limited_body(request, MAX_ASSESS_BODY_BYTES)
    if raw is None:
        return JSONResponse(status_code=413, content={"error": "payload too large"})
    try:
        payload = json.loads(raw or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"error": "invalid JSON"})
    if not isinstance(payload, dict) or payload.get("consent") is not True:
        return JSONResponse(status_code=400, content={"error": "explicit disclaimer consent is required"})
    target = payload.get("target")
    if not isinstance(target, str):
        return JSONResponse(status_code=400, content={"error": "target must be a string"})
    try:
        result = scan_target(target)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "invalid or unavailable scan target"})
    except Exception:
        logger.warning("Local security assessment failed; details withheld")
        return JSONResponse(status_code=500, content={"error": "security assessment failed"})
    scan_id = str(uuid.uuid4())
    assessment = {"scan_id": scan_id, "created_at": utc_now(), **result}
    with ASSESSMENT_LOCK:
        ASSESSMENTS[scan_id] = assessment
        while len(ASSESSMENTS) > 100:
            ASSESSMENTS.pop(next(iter(ASSESSMENTS)))
    return JSONResponse(status_code=200, content=assessment)


@app.get("/api/security/assess/{scan_id}")
async def get_security_assessment(scan_id: str) -> JSONResponse:
    with ASSESSMENT_LOCK:
        assessment = ASSESSMENTS.get(scan_id)
    if not assessment:
        return JSONResponse(status_code=404, content={"error": "assessment not found; assessments are in-memory only"})
    return JSONResponse(content=assessment)


@app.post("/api/security/assess/{scan_id}/findings/{finding_index}/analyze")
async def analyze_security_finding(scan_id: str, finding_index: int) -> JSONResponse:
    """Return deterministic, local remediation guidance without external model/API calls."""
    with ASSESSMENT_LOCK:
        assessment = ASSESSMENTS.get(scan_id)
    if not assessment:
        return JSONResponse(status_code=404, content={"error": "assessment not found"})
    findings = assessment.get("findings", [])
    if finding_index < 0 or finding_index >= len(findings):
        return JSONResponse(status_code=404, content={"error": "finding not found"})
    proposal = propose_remediation(findings[finding_index])
    plan = {
        **proposal,
        "mode": "deterministic-open-source",
        "tools": ["Semgrep", "Bandit", "pip-audit", "Nuclei", "Dependabot", "GitHub Actions"],
        "workflow_url": "https://github.com/zopair/security_matrix/actions/workflows/auto-remediation.yml",
        "message": "Local rule-based guidance only. No external AI API, network scan, source edit, pull request, or deployment was performed.",
    }
    with ASSESSMENT_LOCK:
        if scan_id in ASSESSMENTS:
            ASSESSMENTS[scan_id].setdefault("remediation_plans", {})[str(finding_index)] = plan
    return JSONResponse(content=plan)

"""SecurityMatrix defensive cyber-deception MVP.

This reference app uses synthetic data only. It is not an IDS replacement and
must not be treated as proof that a request originated from an AI agent.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

APP_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = APP_ROOT / "static"
LOG_PATH = Path(os.getenv("SECURITYMATRIX_LOG_PATH", "logs/events.jsonl"))
MAX_EVENTS = int(os.getenv("SECURITYMATRIX_MAX_EVENTS", "1000"))
MAX_EVENTS = max(100, min(MAX_EVENTS, 10000))
MAX_BODY_BYTES = 16_384

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("securitymatrix")

EVENTS: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
STARTED_AT = time.time()

SUSPICIOUS_PATHS = (
    re.compile(r"(^|/)\.env(?:$|/)", re.I),
    re.compile(r"(^|/)(?:wp-admin|phpmyadmin|admin-console)(?:/|$)", re.I),
    re.compile(r"(^|/)(?:\.git|server-status)(?:/|$)", re.I),
    re.compile(r"(^|/)(?:swagger\.json|openapi\.json)(?:$|/)", re.I),
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
    score = min(100, len(signals) * 35)
    return score, signals


def record_event(event: dict[str, Any]) -> None:
    """Keep bounded in-memory events and best-effort JSONL audit output."""
    EVENTS.appendleft(event)
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError:
        # Logging failure is observable, but must not turn the app into a
        # fail-open path to any real resource. Events remain in bounded memory.
        logger.exception("Unable to persist event log")


def event_summary() -> dict[str, Any]:
    by_decision = Counter(event["decision"] for event in EVENTS)
    return {
        "event_count": len(EVENTS),
        "decisions": dict(by_decision),
        "uptime_seconds": max(0, int(time.time() - STARTED_AT)),
        "sandbox_mode": "synthetic-only",
    }


app = FastAPI(
    title="SecurityMatrix",
    description="Defensive cyber-deception reference API. Synthetic data only.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")


@app.middleware("http")
async def request_gateway(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))[:128]
    path = request.url.path
    query = request.url.query[:2048]
    score, signals = classify_request(path, query, request.method)

    # A deliberately small decoy route set; never proxies to real services.
    is_decoy_probe = score >= 35 and path not in {"/health", "/api/health", "/api/events", "/api/metrics"}
    if is_decoy_probe:
        event = {
            "timestamp": utc_now(),
            "request_id": request_id,
            "method": request.method,
            "path": path[:512],
            "decision": "decoy",
            "risk_score": score,
            "signals": signals,
            "source": "request_metadata_only",
            "outcome": "synthetic_response",
        }
        record_event(event)
        return JSONResponse(
            status_code=200,
            headers={"X-SecurityMatrix-Decision": "decoy", "X-Request-ID": request_id},
            content={
                "status": "simulated",
                "message": "Synthetic decoy endpoint. No production data is available.",
                "reference": f"decoy-{request_id[:8]}",
                "records": [
                    {"id": "SYN-1042", "service": "inventory", "state": "synthetic"},
                    {"id": "SYN-1043", "service": "audit-preview", "state": "synthetic"},
                ],
            },
        )

    response = await call_next(request)
    if path not in {"/", "/api/events", "/api/metrics", "/health", "/api/health"}:
        record_event({
            "timestamp": utc_now(),
            "request_id": request_id,
            "method": request.method,
            "path": path[:512],
            "decision": "allow",
            "risk_score": score,
            "signals": signals,
            "source": "request_metadata_only",
            "outcome": f"http_{response.status_code}",
        })
    response.headers["X-Request-ID"] = request_id
    response.headers["X-SecurityMatrix-Decision"] = "allow"
    return response


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard() -> HTMLResponse:
    index = STATIC_ROOT / "index.html"
    return HTMLResponse(index.read_text(encoding="utf-8"))


@app.get("/health")
@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "securitymatrix", "sandbox": "synthetic-only"}


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    return event_summary()


@app.get("/api/events")
async def events(limit: int = 100) -> dict[str, Any]:
    bounded_limit = max(1, min(limit, 200))
    return {"events": list(EVENTS)[:bounded_limit], "summary": event_summary()}


@app.get("/api/decoy/assets")
async def decoy_assets() -> dict[str, Any]:
    """Explicit sample decoy data; all records are invented."""
    return {
        "environment": "isolated-simulation",
        "records": [
            {"id": "SYN-2001", "name": "Synthetic service registry", "classification": "decoy"},
            {"id": "SYN-2002", "name": "Synthetic audit index", "classification": "decoy"},
        ],
    }

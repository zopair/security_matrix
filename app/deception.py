"""Bounded, opt-in synthetic deception endpoints.

No production data, outbound calls, or unbounded response generation is used.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import deque, OrderedDict
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()
ENABLED = os.getenv("SECURITYMATRIX_DECEPTION_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
MAX_RESPONSE_BYTES = max(256, min(int(os.getenv("SECURITYMATRIX_DECEPTION_MAX_RESPONSE_BYTES", "2048")), 8192))
WINDOW_SECONDS = max(10, min(int(os.getenv("SECURITYMATRIX_DECEPTION_WINDOW_SECONDS", "60")), 600))
MAX_HITS_PER_WINDOW = max(1, min(int(os.getenv("SECURITYMATRIX_DECEPTION_MAX_HITS", "8")), 100))
MAX_CLIENT_KEYS = 2000
MAX_EVENTS = 500

_LOCK = threading.Lock()
_HITS: OrderedDict[str, deque[float]] = OrderedDict()
EVENTS: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)


def _client_key(request: Request) -> str:
    # Do not trust forwarded headers unless a trusted proxy sanitizes them.
    host = request.client.host if request.client else "unknown"
    return hashlib.blake2s(host.encode("utf-8", "replace"), digest_size=12).hexdigest()


def _allow_request(key: str, now: float | None = None) -> bool:
    now = time.monotonic() if now is None else now
    with _LOCK:
        hits = _HITS.get(key)
        if hits is None:
            if len(_HITS) >= MAX_CLIENT_KEYS:
                _HITS.popitem(last=False)
            hits = deque()
            _HITS[key] = hits
        else:
            _HITS.move_to_end(key)
        while hits and now - hits[0] >= WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= MAX_HITS_PER_WINDOW:
            EVENTS.append({"event": "rate_limited", "client_key": key, "at": int(now)})
            return False
        hits.append(now)
        EVENTS.append({"event": "decoy_hit", "client_key": key, "at": int(now)})
        return True


def _response(request: Request, kind: str) -> JSONResponse:
    if not ENABLED:
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    if not _allow_request(_client_key(request)):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}, headers={"Retry-After": str(WINDOW_SECONDS)})
    payload = {
        "status": "simulated",
        "environment": "synthetic-only",
        "reference": hashlib.sha256((kind + request.url.path).encode()).hexdigest()[:12],
        "records": [
            {"id": "SYN-1042", "service": "inventory", "state": "synthetic"},
            {"id": "SYN-1043", "service": "audit-preview", "state": "synthetic"},
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # Defensive assertion: templates are fixed and must remain within the configured cap.
    if len(encoded) > MAX_RESPONSE_BYTES:
        return JSONResponse(status_code=500, content={"detail": "Synthetic response exceeds configured limit"})
    return JSONResponse(
        status_code=200,
        content=payload,
        headers={"Cache-Control": "no-store", "X-SecurityMatrix-Decision": "decoy"},
    )


@router.get("/api/v1/admin/master-key-dump")
async def synthetic_master_key_dump(request: Request) -> JSONResponse:
    """Return bounded synthetic data only; never expose or read real keys."""
    return _response(request, "admin")


@router.get("/api/v1/internal/service-registry")
async def synthetic_service_registry(request: Request) -> JSONResponse:
    """Return a fixed synthetic registry only."""
    return _response(request, "registry")

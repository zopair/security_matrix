"""Bounded, local-only risk scoring and evidence correlation.

This engine records metadata only, uses deterministic heuristics, and never
blocks traffic or infers that a request came from an AI agent.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter, deque
from typing import Any

MAX_ENGINE_EVENTS = 2000
MAX_INCIDENTS = 250
CORRELATION_WINDOW_SECONDS = 300
MAX_SIGNALS_PER_EVENT = 12
MAX_PATH_CHARS = 256


def _safe_text(value: Any, limit: int) -> str:
    return str(value or "")[:limit]


def _bounded_score(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError, OverflowError):
        return 0


def _incident_id(actor_key: str, window_start: int) -> str:
    digest = hashlib.sha256(f"{actor_key}:{window_start}".encode()).hexdigest()[:16]
    return f"inc-{digest}"


class RiskEvidenceEngine:
    """Thread-safe bounded ring buffers for event evidence and short incidents."""

    def __init__(
        self,
        max_events: int = MAX_ENGINE_EVENTS,
        max_incidents: int = MAX_INCIDENTS,
        window_seconds: int = CORRELATION_WINDOW_SECONDS,
    ) -> None:
        self.max_events = max(100, min(int(max_events), 10000))
        self.max_incidents = max(25, min(int(max_incidents), 1000))
        self.window_seconds = max(30, min(int(window_seconds), 3600))
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=self.max_events)
        self._incidents: dict[str, dict[str, Any]] = {}
        self._incident_order: deque[str] = deque()

    def ingest(self, event: dict[str, Any]) -> dict[str, Any]:
        """Store a small sanitized event and return its evidence enrichment."""
        now = time.time()
        actor_key = _safe_text(event.get("actor_key"), 64)
        decision = _safe_text(event.get("decision"), 40) or "unknown"
        signals = [
            _safe_text(signal, 64)
            for signal in event.get("signals", [])[:MAX_SIGNALS_PER_EVENT]
            if isinstance(signal, (str, int, float))
        ] if isinstance(event.get("signals", []), list) else []
        base_score = _bounded_score(event.get("risk_score"))
        if decision == "decoy":
            base_score = max(base_score, 45)
        elif decision == "suspicious_not_found":
            base_score = max(base_score, 35)
        elif decision == "rate_limited":
            base_score = max(base_score, 55)
        elif decision == "finding":
            severity = _safe_text(event.get("severity"), 16).lower()
            base_score = max(base_score, {
                "critical": 95, "high": 80, "medium": 60, "low": 35,
                "info": 10, "unknown": 20,
            }.get(severity, 20))

        event_id = _safe_text(event.get("request_id"), 128) or hashlib.sha256(
            f"{now}:{decision}:{event.get('path', '')}".encode()
        ).hexdigest()[:24]
        sanitized = {
            "event_id": event_id,
            "timestamp": _safe_text(event.get("timestamp"), 40),
            "decision": decision,
            "source": _safe_text(event.get("source"), 40),
            "method": _safe_text(event.get("method"), 12),
            "path": _safe_text(event.get("path"), MAX_PATH_CHARS),
            "outcome": _safe_text(event.get("outcome"), 40),
            "signals": signals,
            "base_risk_score": base_score,
            "actor_key": actor_key,
            "observed_epoch": now,
        }

        correlation_id = None
        evidence_count = 1
        risk_score = base_score
        if actor_key and (base_score >= 25 or signals or decision in {"decoy", "rate_limited", "suspicious_not_found"}):
            window_start = int(now // self.window_seconds) * self.window_seconds
            correlation_id = _incident_id(actor_key, window_start)
            with self._lock:
                incident = self._incidents.get(correlation_id)
                if incident is None:
                    incident = {
                        "incident_id": correlation_id,
                        "actor_key": actor_key,
                        "first_seen": sanitized["timestamp"],
                        "last_seen": sanitized["timestamp"],
                        "window_start_epoch": window_start,
                        "evidence_count": 0,
                        "max_risk_score": 0,
                        "risk_score": 0,
                        "decisions": {},
                        "signals": {},
                        "sequence": deque(maxlen=50),
                    }
                    self._incidents[correlation_id] = incident
                    self._incident_order.append(correlation_id)
                    while len(self._incident_order) > self.max_incidents:
                        old_id = self._incident_order.popleft()
                        self._incidents.pop(old_id, None)
                incident["last_seen"] = sanitized["timestamp"]
                incident["evidence_count"] += 1
                incident["max_risk_score"] = max(incident["max_risk_score"], base_score)
                # Recurrence raises priority modestly; this is triage, not a verdict.
                recurrence_bonus = min(20, max(0, incident["evidence_count"] - 1) * 5)
                incident["risk_score"] = min(100, incident["max_risk_score"] + recurrence_bonus)
                incident["decisions"][decision] = incident["decisions"].get(decision, 0) + 1
                for signal in signals:
                    incident["signals"][signal] = incident["signals"].get(signal, 0) + 1
                incident["sequence"].append({
                    "event_id": event_id,
                    "timestamp": sanitized["timestamp"],
                    "decision": decision,
                    "risk_score": base_score,
                    "signals": signals,
                    "path": sanitized["path"],
                })
                evidence_count = incident["evidence_count"]
                risk_score = incident["risk_score"]
                sanitized["correlation_id"] = correlation_id
                sanitized["evidence_count"] = evidence_count
                sanitized["risk_score"] = risk_score
                self._events.appendleft(sanitized)
        else:
            sanitized["correlation_id"] = None
            sanitized["evidence_count"] = 1
            sanitized["risk_score"] = base_score
            with self._lock:
                self._events.appendleft(sanitized)

        return {
            "correlation_id": correlation_id,
            "evidence_count": evidence_count,
            "risk_score": risk_score,
            "event_id": event_id,
        }

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 200))
        with self._lock:
            rows = list(self._events)[:bounded]
        return [{k: v for k, v in row.items() if k not in {"actor_key", "observed_epoch"}} for row in rows]

    def incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 100))
        with self._lock:
            rows = list(self._incidents.values())
            rows.sort(key=lambda row: (row["risk_score"], row["evidence_count"]), reverse=True)
            result = []
            for row in rows[:bounded]:
                result.append({
                    "incident_id": row["incident_id"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "evidence_count": row["evidence_count"],
                    "risk_score": row["risk_score"],
                    "max_risk_score": row["max_risk_score"],
                    "decisions": dict(row["decisions"]),
                    "signals": dict(row["signals"]),
                    "sequence": list(row["sequence"]),
                    "triage_only": True,
                })
            return result

    def summary(self) -> dict[str, Any]:
        with self._lock:
            events = list(self._events)
            incidents = list(self._incidents.values())
        decisions = Counter(row["decision"] for row in events)
        return {
            "event_count": len(events),
            "incident_count": len(incidents),
            "decisions": dict(decisions),
            "max_event_capacity": self.max_events,
            "max_incident_capacity": self.max_incidents,
            "correlation_window_seconds": self.window_seconds,
            "storage": "bounded-in-memory",
            "external_services": False,
            "automated_blocking": False,
        }

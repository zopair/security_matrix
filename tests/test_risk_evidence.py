"""Regression tests for bounded local risk/evidence correlation."""
from app.risk_evidence import RiskEvidenceEngine


def test_repeated_evidence_correlates_and_increases_triage_score():
    engine = RiskEvidenceEngine(max_events=100, max_incidents=25, window_seconds=300)
    first = engine.ingest({
        "request_id": "r1", "timestamp": "2026-10-29T10:00:00+00:00",
        "actor_key": "actor-hash", "decision": "suspicious_not_found",
        "risk_score": 35, "signals": ["sensitive_path_probe"],
        "path": "/.env", "method": "GET", "outcome": "http_404",
    })
    second = engine.ingest({
        "request_id": "r2", "timestamp": "2026-10-29T10:00:01+00:00",
        "actor_key": "actor-hash", "decision": "decoy",
        "risk_score": 45, "signals": ["sensitive_path_probe"],
        "path": "/api/v1/admin/master-key-dump", "method": "GET", "outcome": "http_200",
    })
    assert first["correlation_id"] == second["correlation_id"]
    assert second["evidence_count"] == 2
    assert second["risk_score"] == 50
    incident = engine.incidents()[0]
    assert incident["evidence_count"] == 2
    assert len(incident["sequence"]) == 2
    assert incident["triage_only"] is True


def test_engine_capacity_is_bounded():
    engine = RiskEvidenceEngine(max_events=100, max_incidents=25)
    for i in range(150):
        engine.ingest({
            "request_id": f"r{i}", "timestamp": "2026-10-29T10:00:00+00:00",
            "actor_key": f"actor-{i}", "decision": "suspicious_not_found",
            "risk_score": 35, "signals": ["sensitive_path_probe"],
            "path": "/.env", "method": "GET", "outcome": "http_404",
        })
    summary = engine.summary()
    assert summary["event_count"] == 100
    assert summary["incident_count"] <= 25


def test_evidence_output_does_not_expose_actor_key():
    engine = RiskEvidenceEngine()
    engine.ingest({
        "request_id": "r1", "timestamp": "2026-10-29T10:00:00+00:00",
        "actor_key": "private-hash", "decision": "suspicious_not_found",
        "risk_score": 35, "signals": ["sensitive_path_probe"],
        "path": "/.env", "method": "GET", "outcome": "http_404",
    })
    assert "actor_key" not in engine.recent_events()[0]

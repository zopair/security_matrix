"""Tests for bounded adaptive synthetic deception profiles."""
from fastapi.testclient import TestClient

from app import deception
from app import main


def test_decoy_profiles_change_but_remain_synthetic_and_bounded(monkeypatch, tmp_path):
    monkeypatch.setattr(deception, "ENABLED", True)
    monkeypatch.setattr(deception, "MAX_RESPONSE_BYTES", 2048)
    monkeypatch.setattr(deception, "MAX_HITS_PER_WINDOW", 8)
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    with deception._LOCK:
        deception._HITS.clear()
        deception.EVENTS.clear()
    client = TestClient(main.app)

    responses = [
        client.get("/api/v1/admin/master-key-dump"),
        client.get("/api/v1/admin/master-key-dump"),
        client.get("/api/v1/admin/master-key-dump"),
    ]
    assert all(response.status_code == 200 for response in responses)
    assert len({response.headers["x-securitymatrix-decoy-profile"] for response in responses}) == 3
    assert all(len(response.content) <= 2048 for response in responses)
    assert all("synthetic" in response.text.lower() or "simulated" in response.text.lower() for response in responses)
    assert all(response.headers["cache-control"] == "no-store" for response in responses)


def test_decoy_rate_limit_is_recorded_as_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(deception, "ENABLED", True)
    monkeypatch.setattr(deception, "MAX_HITS_PER_WINDOW", 1)
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(main, "RISK_ENGINE", __import__("app.risk_evidence", fromlist=["RiskEvidenceEngine"]).RiskEvidenceEngine())
    with deception._LOCK:
        deception._HITS.clear()
        deception.EVENTS.clear()
    client = TestClient(main.app)
    assert client.get("/api/v1/internal/service-registry").status_code == 200
    limited = client.get("/api/v1/internal/service-registry")
    assert limited.status_code == 429
    evidence = client.get("/api/security/evidence").json()["events"]
    assert any(item["decision"] == "rate_limited" for item in evidence)

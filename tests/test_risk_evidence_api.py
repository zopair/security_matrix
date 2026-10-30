from fastapi.testclient import TestClient

from app import main
from app.risk_evidence import RiskEvidenceEngine


def test_suspicious_requests_create_local_correlated_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(main, "RISK_ENGINE", RiskEvidenceEngine())
    with main.EVENT_LOCK:
        main.EVENTS.clear()
    client = TestClient(main.app, headers={"Authorization": "Bearer test-read-secret"})

    first = client.get("/.env", headers={"user-agent": "p1-test-agent"})
    second = client.get("/phpmyadmin", headers={"user-agent": "p1-test-agent"})
    assert first.status_code == 404
    assert second.status_code == 404

    evidence = client.get("/api/security/evidence").json()
    incidents = client.get("/api/security/incidents").json()
    assert evidence["summary"]["event_count"] >= 2
    assert incidents["summary"]["incident_count"] == 1
    assert incidents["incidents"][0]["evidence_count"] == 2
    assert incidents["incidents"][0]["risk_score"] >= 40
    assert incidents["incidents"][0]["triage_only"] is True


def test_actor_hash_is_not_exposed_in_public_event_log(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(main, "RISK_ENGINE", RiskEvidenceEngine())
    with main.EVENT_LOCK:
        main.EVENTS.clear()
    client = TestClient(main.app, headers={"Authorization": "Bearer test-read-secret"})
    client.get("/.env", headers={"user-agent": "privacy-test-agent"})
    payload = client.get("/api/events").json()
    assert "actor_key" not in payload["events"][0]
    assert "actor_key" not in (tmp_path / "events.jsonl").read_text()

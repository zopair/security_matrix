"""Regression tests for P0 resource limits and safe deception defaults."""
from fastapi.testclient import TestClient

from app import deception
from app import main


def test_deception_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(deception, "ENABLED", False)
    client = TestClient(main.app)
    response = client.get("/api/v1/admin/master-key-dump")
    assert response.status_code == 404
    assert "records" not in response.json()


def test_suspicious_unknown_path_is_not_converted_to_success(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    client = TestClient(main.app)
    response = client.get("/.env")
    assert response.status_code == 404
    assert response.headers["x-securitymatrix-decision"] == "allow"


def test_health_route_remains_available(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    client = TestClient(main.app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_deception_rate_limit_is_bounded(monkeypatch, tmp_path):
    monkeypatch.setattr(deception, "ENABLED", True)
    monkeypatch.setattr(deception, "MAX_HITS_PER_WINDOW", 2)
    monkeypatch.setattr(deception, "WINDOW_SECONDS", 60)
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    with deception._LOCK:
        deception._HITS.clear()
        deception.EVENTS.clear()
    client = TestClient(main.app)
    assert client.get("/api/v1/admin/master-key-dump").status_code == 200
    assert client.get("/api/v1/admin/master-key-dump").status_code == 200
    limited = client.get("/api/v1/admin/master-key-dump")
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"


def test_response_body_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(deception, "ENABLED", True)
    monkeypatch.setattr(deception, "MAX_RESPONSE_BYTES", 256)
    client = TestClient(main.app)
    response = client.get("/api/v1/internal/service-registry")
    assert response.status_code == 500
    assert len(response.content) < 256


def test_assessment_body_limit_works_without_content_length(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(main, "MAX_ASSESS_BODY_BYTES", 16)
    client = TestClient(main.app)
    response = client.post(
        "/api/security/assess",
        content=b'{"consent":true,"target":"this body is longer than sixteen bytes"}',
        headers={"content-type": "application/json", "content-length": ""},
    )
    assert response.status_code == 413

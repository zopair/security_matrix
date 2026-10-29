from fastapi.testclient import TestClient

from app.main import app, EVENTS

client = TestClient(app)


def setup_function():
    EVENTS.clear()


def test_health_is_available():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_decoy_path_returns_only_synthetic_data():
    response = client.get("/.env")
    assert response.status_code == 200
    assert response.headers["X-SecurityMatrix-Decision"] == "decoy"
    body = response.json()
    assert body["status"] == "simulated"
    assert all(record["id"].startswith("SYN-") for record in body["records"])


def test_decoy_event_is_recorded():
    client.get("/phpmyadmin")
    response = client.get("/api/events")
    assert response.status_code == 200
    assert response.json()["summary"]["event_count"] == 1
    assert response.json()["events"][0]["decision"] == "decoy"


def test_metrics_are_bounded_and_available():
    response = client.get("/api/metrics")
    assert response.status_code == 200
    assert response.json()["sandbox_mode"] == "synthetic-only"


def test_dashboard_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "SecurityMatrix" in response.text



def test_scanner_ingestion_requires_configuration(monkeypatch):
    import app.main as main_module
    monkeypatch.setattr(main_module, "INGEST_TOKEN", "")
    response = client.post("/api/security/findings", json={"findings": []})
    assert response.status_code == 503


def test_scanner_ingestion_requires_bearer_token(monkeypatch):
    import app.main as main_module
    monkeypatch.setattr(main_module, "INGEST_TOKEN", "test-secret")
    response = client.post("/api/security/findings", json={"findings": []})
    assert response.status_code == 401


def test_scanner_ingestion_stores_sanitized_finding(monkeypatch):
    import app.main as main_module
    monkeypatch.setattr(main_module, "INGEST_TOKEN", "test-secret")
    response = client.post(
        "/api/security/findings",
        headers={"Authorization": "Bearer test-secret"},
        json={"findings": [{
            "source": "semgrep",
            "severity": "high",
            "title": "Test rule",
            "rule_id": "TEST-001",
            "target": "app/main.py",
            "details": "synthetic test result",
        }]},
    )
    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    result = client.get("/api/security/findings")
    assert result.json()["count"] == 1
    assert result.json()["findings"][0]["source"] == "semgrep"

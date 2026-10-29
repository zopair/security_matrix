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


def test_assessment_requires_explicit_consent():
    response = client.post("/api/security/assess", json={"target": "app", "consent": False})
    assert response.status_code == 400


def test_assessment_rejects_path_traversal():
    response = client.post("/api/security/assess", json={"target": "../", "consent": True})
    assert response.status_code == 400


def test_url_assessment_does_not_contact_external_target():
    response = client.post("/api/security/assess", json={"target": "https://example.com", "consent": True})
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "passive-url-only"
    assert data["findings"][0]["rule_id"] == "SAFETY-URL-001"


def test_local_assessment_returns_bounded_results():
    response = client.post("/api/security/assess", json={"target": "app/ai_security.py", "consent": True})
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "local-static-analysis"
    assert "scan_id" in data
    assert len(data["findings"]) <= 100


def test_approval_requires_explicit_approval():
    scan = client.post("/api/security/assess", json={"target": "https://example.com", "consent": True}).json()
    response = client.post(
        f"/api/security/assess/{scan['scan_id']}/findings/0/approve",
        json={"approved": False},
    )
    assert response.status_code == 400


def test_approved_proposal_does_not_modify_source():
    scan = client.post("/api/security/assess", json={"target": "https://example.com", "consent": True}).json()
    response = client.post(
        f"/api/security/assess/{scan['scan_id']}/findings/0/approve",
        json={"approved": True},
    )
    assert response.status_code == 202
    assert response.json()["source_changed"] is False

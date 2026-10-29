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

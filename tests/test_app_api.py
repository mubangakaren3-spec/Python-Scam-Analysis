import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient
import app_api


def _client(monkeypatch):
    monkeypatch.setenv("SCAM_API_KEY", "test-key")
    monkeypatch.setenv("SCAM_API_LOG_TO_DB", "false")
    app = app_api.create_app()
    return TestClient(app)


def test_analyze_requires_api_key(monkeypatch):
    client = _client(monkeypatch)
    response = client.post("/analyze", json={"message": "hello"})
    assert response.status_code == 401
    body = response.json()
    assert body["success"] is False


def test_analyze_success(monkeypatch):
    client = _client(monkeypatch)
    response = client.post(
        "/analyze",
        headers={"X-API-KEY": "test-key"},
        json={"message": "You have won a lottery. Click here to claim."},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert "analysis" in body
    assert isinstance(body["analysis"]["score"], int)


def test_analyze_batch_validation(monkeypatch):
    client = _client(monkeypatch)
    response = client.post(
        "/analyze/batch",
        headers={"X-API-KEY": "test-key"},
        json={"messages": ["ok", ""]},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False


def test_feedback_invalid_label(monkeypatch):
    client = _client(monkeypatch)
    response = client.post(
        "/feedback",
        headers={"X-API-KEY": "test-key"},
        json={"detection_id": 1, "label": "wrong_label"},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False


def test_get_detection_not_found(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr(app_api.storage, "get_detection_by_id", lambda _: None)
    response = client.get("/detections/99999", headers={"X-API-KEY": "test-key"})
    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False

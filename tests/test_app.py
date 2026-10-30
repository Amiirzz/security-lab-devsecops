import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))

import pytest  # noqa: E402

from app import app as flask_app  # noqa: E402


@pytest.fixture
def client():
    flask_app.config.update(TESTING=True)
    return flask_app.test_client()


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_login_invalid_credentials(client):
    response = client.post("/login", json={"username": "amir", "password": "wrong"})
    assert response.status_code == 401


def test_login_valid_credentials(client):
    response = client.post("/login", json={"username": "amir", "password": "Str0ngP@ssword!"})
    assert response.status_code == 200
    assert "token" in response.get_json()


def test_resource_requires_authentication(client):
    response = client.get("/api/resource")
    assert response.status_code == 401


def test_resource_with_valid_token(client):
    login_response = client.post("/login", json={"username": "amir", "password": "Str0ngP@ssword!"})
    token = login_response.get_json()["token"]

    response = client.get("/api/resource", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json()["owner"] == "amir"


def test_login_logs_structured_json(client, caplog):
    caplog.set_level("INFO", logger="app")
    client.post("/login", json={"username": "amir", "password": "wrong"})
    record = json.loads(caplog.records[-1].getMessage())
    assert record["event_type"] == "auth_failure"
    assert record["username"] == "amir"


def test_unknown_user_is_rejected(client):
    response = client.post("/login", json={"username": "inconnu", "password": "x"})
    assert response.status_code == 401


def test_log_contains_severity(client, caplog):
    caplog.set_level("INFO", logger="app")
    client.post("/login", json={"username": "amir", "password": "wrong"})
    record = json.loads(caplog.records[-1].getMessage())
    assert record["severity"] == "WARNING"

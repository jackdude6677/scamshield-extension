import json

from flask import Flask
from flask.testing import FlaskClient

from scamshield.server import app


def test_health_endpoint() -> None:
    client: FlaskClient = app.test_client()
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.data.decode() == "OK"


def test_lookup_missing_param() -> None:
    client = app.test_client()
    resp = client.get("/lookup")
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert "error" in data


def test_lookup_malicious() -> None:
    client = app.test_client()
    resp = client.get("/lookup", query_string={"hash": "bad123"})
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["verdict"] == "malicious"


def test_lookup_clean() -> None:
    client = app.test_client()
    resp = client.get("/lookup", query_string={"hash": "good456"})
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["verdict"] == "clean"

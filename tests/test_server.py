import pytest
from scamshield.server import app as server_app

@pytest.fixture
def client():
    server_app.config["TESTING"] = True
    with server_app.test_client() as client:
        yield client

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.data == b"OK"

def test_lookup_malicious(client):
    resp = client.get("/lookup", query_string={"hash": "bad123"})
    assert resp.json == {"verdict": "malicious"}

def test_lookup_clean(client):
    resp = client.get("/lookup", query_string={"hash": "good"})
    assert resp.json == {"verdict": "clean"}

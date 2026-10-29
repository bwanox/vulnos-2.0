"""Existing unit tests for the sample app (must pass 100% after patching)."""

from app.main import app


def test_app_has_ping_route():
    client = app.test_client()
    resp = client.get("/ping?host=localhost")
    assert resp.status_code == 200


def test_app_has_user_route():
    client = app.test_client()
    resp = client.get("/user?id=1")
    assert resp.status_code == 200

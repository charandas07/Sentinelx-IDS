"""
API endpoint tests.
"""
def test_status_endpoint(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"


def test_stats_endpoint(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "packets_analyzed" in data
    assert "threats_detected" in data


def test_rules_endpoint(client):
    response = client.get("/api/rules")
    assert response.status_code == 200
    rules = response.json()
    assert len(rules) > 0
    assert any(r["attack_type"] == "PORT_SCAN" for r in rules)


def test_demo_endpoint(client):
    start_resp = client.post("/api/demo/start")
    assert start_resp.status_code == 200
    status_resp = client.get("/api/demo/status")
    assert status_resp.json()["active"] is True
    stop_resp = client.post("/api/demo/stop")
    assert stop_resp.status_code == 200


def test_login_endpoint(client):
    from app.config import settings
    settings.ADMIN_USER = "admin"
    settings.ADMIN_PASSWORD = "secretpassword"

    # Wrong credentials
    res = client.post("/api/login", json={"username": "admin", "password": "wrong"})
    assert res.status_code == 401

    res = client.post("/api/login", json={"username": "wronguser", "password": "secretpassword"})
    assert res.status_code == 401

    # Correct credentials
    res = client.post("/api/login", json={"username": "admin", "password": "secretpassword"})
    assert res.status_code == 200
    assert res.json() == {"token": settings.SECRET_KEY}


def test_capture_interfaces_endpoint(client):
    response = client.get("/api/capture/interfaces")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


import pytest


@pytest.mark.asyncio
async def test_whitelist_survives_restart(client, async_db):
    from sqlalchemy import select
    from app.models.whitelist import WhitelistEntry
    from app.services.traffic_processor import traffic_processor

    resp = client.post("/api/whitelist", json={"ip": "10.99.99.99", "comment": "test server"})
    assert resp.status_code == 201
    assert "10.99.99.99" in traffic_processor._whitelist_ips

    # Simulate restart: clear in-memory cache
    traffic_processor._whitelist_ips.clear()
    assert "10.99.99.99" not in traffic_processor._whitelist_ips

    wl_result = await async_db.execute(select(WhitelistEntry.ip))
    for ip in wl_result.scalars().all():
        traffic_processor._whitelist_ips.add(ip)

    assert "10.99.99.99" in traffic_processor._whitelist_ips

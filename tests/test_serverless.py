"""Stateless (Vercel) mode: each request carries incident + sandbox state; approvals round-trip."""
import json

import pytest
from fastapi.testclient import TestClient

from web.serverless import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


HEADERS = {"x-planner-provider": "mock"}


def _events(resp):
    """Parse SSE text into (event, data) pairs."""
    out = []
    for block in resp.text.split("\n\n"):
        ev, data = None, None
        for line in block.splitlines():
            if line.startswith("event: "):
                ev = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
        if ev and data is not None:
            out.append((ev, data))
    return out


def test_world_snapshot_roundtrip():
    from sandbox.world import World
    w = World()
    w.load("s2")
    w.block_ip("203.0.113.66", "t")
    snap = json.loads(json.dumps(w.snapshot()))
    w2 = World()
    w2.restore(snap)
    assert [r["ip"] for r in w2.firewall_rules] == ["203.0.113.66"]
    assert any(a["alert_id"] == "alt-2002" for a in w2.alerts)   # trigger effects survive
    assert w2.fired == w.fired


def test_run_pauses_for_approval_and_resumes(client):
    r = client.post("/api/run", json={"scenario": "s2", "alert_id": "alt-2001"}, headers=HEADERS)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    evs = _events(r)
    kinds = [e for e, _ in evs]
    assert kinds[0] == "open" and kinds[-1] == "state" and kinds.count("trace") > 10
    final = evs[-1][1]
    assert final["incident"]["status"] == "awaiting_approval"
    assert final["incident"]["pending_approval"]["decision"]["action"] == "isolate_host"
    assert final["env"]["truth"]["blocked_ips"] == ["203.0.113.66"]
    state = final["state"]
    assert state["world"]["scenario_id"] == "s2" and state["incident"]["id"].startswith("inc-")

    # a fresh request with the state carries on where it stopped
    r2 = client.post("/api/resume", json={"state": state, "approved": True}, headers=HEADERS)
    final2 = _events(r2)[-1][1]
    assert final2["incident"]["status"] == "closed"
    assert final2["env"]["truth"]["blocked_ips"] == ["198.51.100.23", "203.0.113.66"]
    assert final2["env"]["truth"]["isolated_hosts"] == ["app02"]
    assert final2["env"]["handled"]["alt-2002"]["role"] == "follow-up"


def test_chaos_and_chat_round_trip(client):
    r = client.post("/api/run", json={"scenario": "s1"}, headers=HEADERS)
    final = _events(r)[-1][1]
    assert final["incident"]["status"] == "closed" and final["incident"]["verdict"]["verdict"] == "FAILED"
    state = final["state"]
    c = client.post("/api/chat", json={"state": state, "message": "why?"}, headers=HEADERS).json()
    assert "FAILED" in c["reply"] and not c["needs_run"]
    r2 = client.post("/api/chaos/override", json={"state": state, "payload": {}}, headers=HEADERS)
    f2 = _events(r2)[-1][1]
    assert "198.51.100.77" in f2["env"]["truth"]["allowlist"]


def test_time_box_pauses_and_state_continues(client, monkeypatch):
    import web.serverless as sl
    monkeypatch.setattr(sl, "REQUEST_BUDGET_S", 0.0)   # every request pauses after one step
    r = client.post("/api/run", json={"scenario": "s4"}, headers=HEADERS)
    final = _events(r)[-1][1]
    assert final["incident"]["status"] == "open"
    assert any(t["title"].startswith("Pausing") for t in final["state"]["incident"]["trace"])
    monkeypatch.setattr(sl, "REQUEST_BUDGET_S", 60.0)
    r2 = client.post("/api/resume", json={"state": final["state"]}, headers=HEADERS)
    assert _events(r2)[-1][1]["incident"]["status"] == "escalated"

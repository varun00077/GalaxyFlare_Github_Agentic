"""End-to-end: every scenario through the full loop with the scripted planner and an
in-process sandbox (HTTP semantics via ASGI transport). No network, no API key."""
import pytest

from agent.controller import Controller
from agent.llm import MockLLM
from agent.state import Incident, IncidentStore
from agent.tools import SandboxClient

EXPECT = {
    "s1": {"verdict": "FAILED", "blocked": [], "status": "closed"},
    "s2": {"verdict": "SUCCEEDED", "blocked": ["198.51.100.23", "203.0.113.66"], "status": "closed"},
    "s3": {"verdict": "SUCCEEDED", "blocked": ["203.0.113.140"], "status": "closed"},
    "s4": {"verdict": "INCONCLUSIVE", "blocked": [], "status": "escalated"},
    "s5": {"verdict": "OVERRIDDEN", "blocked": [], "status": "closed"},
    "s6": {"verdict": "SUCCEEDED", "blocked": ["198.51.100.200"], "status": "closed"},
}


@pytest.fixture(scope="module")
def client():
    return SandboxClient("", backoff_s=0.01)


def _run(client, sid, approver=lambda inc, dec: True):
    client.load_scenario(sid)
    alert = client.list_alerts()[0]["alert_id"]
    ctl = Controller(client, MockLLM(), budget=24, approver=approver)
    return ctl.run(sid, alert), client.truth()


@pytest.mark.parametrize("sid", sorted(EXPECT))
def test_scenario_outcome(client, sid):
    inc, truth = _run(client, sid)
    exp = EXPECT[sid]
    assert inc.verdict["verdict"] == exp["verdict"], inc.verdict
    assert truth["blocked_ips"] == exp["blocked"]
    assert inc.status == exp["status"]
    assert inc.steps <= 24
    kinds = {t.kind for t in inc.trace}
    assert {"goal", "decision", "result", "guardrail", "final"} <= kinds
    # every block was verified
    assert sum(1 for t in inc.trace if t.kind == "verification") >= sum(1 for a in inc.actions if a["type"] == "block_ip")


def test_s2_pivot_is_adaptation(client):
    inc, truth = _run(client, "s2")
    titles = [t.title for t in inc.trace if t.kind == "adaptation"]
    assert any("pivot" in t.lower() for t in titles)
    assert inc.followup_alerts == ["alt-2002"]
    assert "app02" in truth["isolated_hosts"]


def test_s3_tool_failure_then_recovery(client):
    inc, truth = _run(client, "s3")
    titles = [t.title for t in inc.trace if t.kind in ("adaptation", "error")]
    assert any("unavailable" in t for t in titles) and any("recovered" in t for t in titles)
    assert any("Reset credentials" in (t.get("reason") or "") for t in truth["tickets"])
    assert any(t.kind == "human" for t in inc.trace)  # critical asset needed approval


def test_s4_escalates_with_missing_evidence(client):
    inc, truth = _run(client, "s4")
    assert truth["tickets"] and truth["tickets"][0]["missing_evidence"]
    assert any("refused" in t.title.lower() for t in inc.trace if t.kind == "guardrail") or not truth["blocked_ips"]


def test_s5_override_reverses_block(client):
    inc, truth = _run(client, "s5")
    types = [a["type"] for a in inc.actions]
    assert "block_ip" in types and "unblock_ip" in types
    assert "203.0.113.9" in truth["allowlist"]
    assert [a["verdict"] for a in truth["assessments"]] == ["SUCCEEDED", "OVERRIDDEN"]
    assert not truth["isolated_hosts"]


def test_s6_verdict_flips_after_kb_update(client):
    inc, truth = _run(client, "s6")
    assert [a["verdict"] for a in truth["assessments"]] == ["FAILED", "SUCCEEDED"]
    assert inc.replan_epoch == 1


def test_approval_deferred_and_resumed(client):
    client.load_scenario("s3")
    store = IncidentStore(":memory:")
    ctl = Controller(client, MockLLM(), store=store, budget=24, approver=lambda inc, dec: None)
    inc = ctl.run("s3", "alt-3001")
    assert inc.status == "awaiting_approval" and inc.pending_approval["decision"]["action"] == "block_ip"
    # persisted state survives a "restart"
    ctl2 = Controller(client, MockLLM(), store=store, budget=24, approver=lambda inc, dec: True)
    loaded = store.load(inc.id)
    assert loaded is not None and loaded.status == "awaiting_approval"
    inc2 = ctl2.approve(loaded, True, who="tester")
    assert inc2.status == "closed" and client.truth()["blocked_ips"] == ["203.0.113.140"]


def test_budget_exhaustion_escalates(client):
    client.load_scenario("s2")
    ctl = Controller(client, MockLLM(), budget=3, approver=lambda inc, dec: True)
    inc = ctl.run("s2", "alt-2001")
    assert inc.status == "escalated" and client.truth()["tickets"]
    assert not client.truth()["blocked_ips"]


def test_pivot_survives_approval_pause(client):
    """S2: block -> pivot detected -> isolation waits for approval -> after approval the pivot is still investigated."""
    client.load_scenario("s2")
    store = IncidentStore(":memory:")
    ctl = Controller(client, MockLLM(), store=store, budget=24, approver=lambda inc, dec: None)
    inc = ctl.run("s2", "alt-2001")
    assert inc.status == "awaiting_approval" and inc.followup_alerts == ["alt-2002"]
    inc = ctl.approve(inc, True)
    assert inc.status == "closed"
    assert client.truth()["blocked_ips"] == ["198.51.100.23", "203.0.113.66"]

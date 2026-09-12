"""Planner plumbing that can be checked without the network."""
import json
import os

import pytest

from agent.llm import GeminiLLM, MockLLM, rule_only_conclusion
from agent.state import HistoryItem, Incident
from agent.tools import PLANNER_TOOLS


def test_tool_declarations_are_valid_gemini_schema():
    json.dumps(PLANNER_TOOLS)  # serialisable
    names = [t["name"] for t in PLANNER_TOOLS]
    assert "conclude_investigation" in names and len(names) == len(set(names))
    for t in PLANNER_TOOLS:
        assert t["parameters"]["type"] == "OBJECT"
        for req in t["parameters"]["required"]:
            assert req in t["parameters"]["properties"]


def test_gemini_contents_alternate_roles_and_carry_events():
    llm = GeminiLLM(api_key="test-key", model="gemini-test")
    inc = Incident.new("s2", "alt-2001", 24)
    inc.history.append(HistoryItem(step=1, kind="call", name="get_alert", args={"alert_id": "alt-2001"}, result={"src_ip": "1.2.3.4"}))
    inc.history.append(HistoryItem(step=2, kind="call", name="search_logs", args={"host": "app02", "source": "auth"}, error="503: down"))
    inc.observe("Advisory revised", type="kb_update")
    inc.add_evidence("context", "x", "y")
    contents = llm._contents(inc)
    roles = [c["role"] for c in contents]
    assert roles[0] == "user" and all(a != b for a, b in zip(roles, roles[1:]))
    fc = contents[1]["parts"][0]["functionCall"]
    assert fc["name"] == "get_alert"
    fr = contents[2]["parts"][0]["functionResponse"]
    assert fr["name"] == "get_alert" and fr["response"]["result"]["src_ip"] == "1.2.3.4"
    assert contents[-1]["parts"][-1]["text"].startswith("[EVIDENCE LEDGER")
    assert any("[ENVIRONMENT EVENT]" in p.get("text", "") for c in contents for p in c["parts"])


def test_gemini_requires_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    from agent import config
    monkeypatch.setattr(config.settings, "gemini_api_key", "")
    with pytest.raises(RuntimeError):
        GeminiLLM()


def test_rule_only_conclusion_paths():
    inc = Incident.new("s0", "alt-0", 24)
    inc.alert = {"src_ip": "9.9.9.9", "dest_ip": "10.0.0.1"}
    inc.asset = {"hostname": "h", "criticality": "high"}
    assert rule_only_conclusion(inc)["verdict"] == "INCONCLUSIVE"
    inc.add_evidence("attack_blocked", "x", "403")
    assert rule_only_conclusion(inc)["verdict"] == "FAILED"
    inc.add_evidence("post_exploitation", "x", "Accepted password for bob from 9.9.9.9", meaning="login")
    c = rule_only_conclusion(inc)
    assert c["verdict"] == "SUCCEEDED" and "bob" in c["escalation_note"]


@pytest.mark.skipif(not os.getenv("GEMINI_API_KEY"), reason="needs GEMINI_API_KEY")
def test_gemini_live_first_step():
    """Smoke test with the real API: the first planner step on s2 must be a tool call."""
    llm = GeminiLLM()
    inc = Incident.new("s2", "alt-2001", 24)
    d = llm.decide(inc)
    assert d.kind == "call" and d.name in {"get_alert", "search_playbooks"}

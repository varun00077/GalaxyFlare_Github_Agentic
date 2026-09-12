from agent.rules import decide_actions, gate_verdict
from agent.state import Incident


def _inc(**kw) -> Incident:
    inc = Incident.new("s0", "alt-0", 24)
    inc.alert = {"src_ip": "203.0.113.1", "dest_ip": "10.20.0.22"}
    inc.asset = {"hostname": "app02", "criticality": kw.pop("criticality", "high")}
    for k, v in kw.items():
        setattr(inc, k, v)
    return inc


def test_succeeded_needs_post_exploitation_evidence():
    inc = _inc(asset_vulnerable=True)
    g = gate_verdict({"verdict": "SUCCEEDED", "confidence": 0.9}, inc)
    assert g.verdict == "INCONCLUSIVE" and g.downgraded
    inc.add_evidence("post_exploitation", "search_logs", "proc=java spawned child=/bin/sh")
    g = gate_verdict({"verdict": "SUCCEEDED", "confidence": 0.9}, inc)
    assert g.verdict == "SUCCEEDED" and not g.downgraded


def test_failed_contradicted_by_traces():
    inc = _inc(asset_vulnerable=False)
    inc.add_evidence("post_exploitation", "search_logs", "Accepted password for x from y")
    g = gate_verdict({"verdict": "FAILED", "confidence": 0.9}, inc)
    assert g.verdict == "INCONCLUSIVE"


def test_failed_needs_block_or_not_vulnerable():
    inc = _inc()
    assert gate_verdict({"verdict": "FAILED", "confidence": 0.8}, inc).verdict == "INCONCLUSIVE"
    inc.add_evidence("attack_blocked", "get_flow", "HTTP 403")
    assert gate_verdict({"verdict": "FAILED", "confidence": 0.8}, inc).verdict == "FAILED"


def test_unknown_asset_forces_inconclusive_and_degraded_caps_confidence():
    inc = _inc(asset_unknown=True)
    inc.add_evidence("post_exploitation", "x", "y")
    assert gate_verdict({"verdict": "SUCCEEDED", "confidence": 0.95}, inc).verdict == "INCONCLUSIVE"
    inc = _inc(logs_degraded=True, asset_vulnerable=True)
    inc.add_evidence("post_exploitation", "x", "y")
    g = gate_verdict({"verdict": "SUCCEEDED", "confidence": 0.95}, inc)
    assert g.verdict == "SUCCEEDED" and g.confidence == 0.6


def test_action_policy():
    inc = _inc(asset_vulnerable=True)
    inc.add_evidence("post_exploitation", "x", "y")
    g = gate_verdict({"verdict": "SUCCEEDED", "confidence": 0.9}, inc)
    d = decide_actions(g, {"proposed_action": "block_ip"}, inc, allowlisted=False)
    assert d[0].action == "block_ip" and d[0].allowed and not d[0].needs_approval
    d = decide_actions(g, {"proposed_action": "block_ip"}, inc, allowlisted=True)
    assert not d[0].allowed
    inc.asset["criticality"] = "critical"
    d = decide_actions(g, {"proposed_action": "block_ip_and_isolate_host"}, inc, allowlisted=False)
    assert d[0].needs_approval and d[1].action == "isolate_host" and d[1].needs_approval
    low = gate_verdict({"verdict": "SUCCEEDED", "confidence": 0.5}, inc)
    d = decide_actions(low, {"proposed_action": "block_ip"}, inc, allowlisted=False)
    assert not d[0].allowed and d[1].action == "escalate"
    # FAILED never blocks
    inc2 = _inc()
    inc2.add_evidence("attack_blocked", "x", "403")
    f = gate_verdict({"verdict": "FAILED", "confidence": 0.9}, inc2)
    d = decide_actions(f, {"proposed_action": "block_ip"}, inc2, allowlisted=False)
    assert not d[0].allowed and d[1].action == "watchlist"

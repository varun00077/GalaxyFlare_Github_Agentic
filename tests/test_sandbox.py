import pytest

from sandbox.world import NotFound, ToolFault, World, version_affected


def test_version_ranges():
    cve = {"affected_from": "2.0", "affected_below": "2.15.0"}
    assert version_affected(cve, "2.14.1")
    assert not version_affected(cve, "2.15.0")
    assert version_affected({"affected_versions": ["2.4.49"]}, "2.4.49")
    assert not version_affected({"affected_versions": ["2.4.49"]}, "2.4.50")


def test_block_stops_flows_and_trigger_pivots():
    w = World()
    w.load("s2")
    assert w.get_asset("10.20.0.22")["hostname"] == "app02"
    assert w.lookup_cves("log4j-core", "2.14.1")["vulnerable"] is True
    res = w.block_ip("203.0.113.66", "test")
    assert res["ok"]
    v = w.verify_block("203.0.113.66")
    assert v["rule_present"] and v["effective"]
    # trigger fired: pivot alert + event
    assert any(a["alert_id"] == "alt-2002" for a in v["new_alerts_since_rule"])
    assert w.get_events()[0]["type"] == "new_alert"
    # new logs are searchable
    hits = w.search_logs("app02", "outbound", "198.51.100.23")
    assert hits["total"] == 1


def test_faults_fail_first_n():
    w = World()
    w.load("s3")
    for _ in range(4):
        with pytest.raises(ToolFault):
            w.search_logs("bastion01", "auth", "Accepted")
    ok = w.search_logs("bastion01", "auth", "Accepted")
    assert ok["total"] == 1
    big = w.search_logs("bastion01", "auth", "Failed password")
    assert big["total"] == 240 and len(big["matches"]) <= 61


def test_unknown_asset_and_allowlist_refusal():
    w = World()
    w.load("s4")
    with pytest.raises(NotFound):
        w.get_asset("10.20.0.99")
    w.allowlist["192.0.2.55"] = "pentest"
    with pytest.raises(ToolFault):
        w.block_ip("192.0.2.55", "should refuse")


def test_retrieval_picks_playbook():
    w = World()
    w.load("s1")
    top = w.search_playbooks("ET WEB_SERVER SQL Injection Attempt UNION SELECT in URI")[0]
    assert top["id"] == "pb-sqli"
    top = w.search_playbooks("alert on host not in asset inventory")[0]
    assert top["id"] == "pb-unknown-asset"


def test_chaos_kinds():
    w = World()
    w.load("s1")
    w.chaos("log_outage", {"count": 1})
    with pytest.raises(ToolFault):
        w.search_logs("web01", "web")
    w.chaos("override", {"ip": "198.51.100.77"})
    assert "198.51.100.77" in w.allowlist
    w.chaos("pivot", {"from_ip": "198.51.100.77", "to_ip": "198.51.100.78"})
    assert w.alerts[-1]["src_ip"] == "198.51.100.78"

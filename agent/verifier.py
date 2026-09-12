"""Independent verification of state-changing actions. No LLM involved.

After a block, re-query the environment: is the rule there, has the source produced
any flow since, and did new alerts appear that should be correlated? A verification that
fails or surfaces new alerts re-enters the investigation loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .state import Incident
from .tools import SandboxClient


@dataclass
class Verification:
    ok: bool
    summary: str
    followup_alert_ids: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    followup_alerts: list[dict[str, Any]] = field(default_factory=list)


def verify_block(client: SandboxClient, inc: Incident, ip: str) -> Verification:
    res = client.verify_block(ip)
    rules_ok = bool(res.get("rule_present"))
    flows = res.get("flows_since_rule", [])
    dest_ips = {ip_ for ip_ in [(inc.alert or {}).get("dest_ip")] if ip_}
    # Correlate: only alerts on the same target host, and only ones we have not handled.
    handled = {inc.alert_id, *inc.followup_alerts, *(h.args.get("alert_id") for h in inc.calls("get_alert"))}
    new_alerts = [a for a in res.get("new_alerts_since_rule", [])
                  if a.get("dest_ip") in dest_ips and a["alert_id"] not in handled and a["src_ip"] not in inc.blocked_ips]
    detail = {"rule_present": rules_ok, "flows_since_rule": len(flows), "new_alerts": [a["alert_id"] for a in new_alerts]}
    if not rules_ok:
        return Verification(False, f"firewall rule for {ip} is missing after the block call", [], detail)
    if flows:
        return Verification(False, f"{len(flows)} flow(s) from {ip} observed after the rule; block not effective", [], detail)
    if new_alerts:
        ids = [a["alert_id"] for a in new_alerts]
        srcs = sorted({a["src_ip"] for a in new_alerts})
        return Verification(True, f"rule effective for {ip}, but {len(ids)} new alert(s) on the same host from {', '.join(srcs)}: {', '.join(ids)}", ids, detail, new_alerts)
    return Verification(True, f"rule present for {ip}; no flows from it since; no new alerts on the host", [], detail)


def verify_unblock(client: SandboxClient, ip: str) -> Verification:
    rules = client.list_rules()
    present = any(r["ip"] == ip for r in rules)
    return Verification(not present, f"rule for {ip} {'still present' if present else 'removed'}", [], {"rule_present": present})

"""Deterministic evidence tagging of tool results.

The LLM decides *what* to look at; this module decides *what a result counts as*, using
the CVE KB's success indicators plus generic post-exploitation and block signatures.
The verdict gates in rules.py only trust categories assigned here or by an explicit
record_evidence call, so the LLM cannot talk itself into a verdict without a line of
evidence behind it.
"""
from __future__ import annotations

import re
from typing import Any

from .state import Incident

GENERIC_POST_EXPLOIT = [
    (r"Accepted (password|publickey) for (\S+) from ([0-9.]+)", "successful login after brute force"),
    (r"spawned child=/bin/(sh|bash)", "service process spawned a shell"),
    (r"conn out .*dst=[0-9.]+:(1389|389|1099|4444|8000|8080)", "outbound connection to attacker-controlled port"),
    (r"lookup jndi:", "JNDI lookup executed"),
    (r"\?cmd=.* 200 ", "web shell executed a command"),
    (r"useradd|usermod -aG (sudo|wheel)", "privileged account created/modified"),
    (r"root:x:0:0", "/etc/passwd content returned"),
]
GENERIC_BLOCKED = [
    (r"\" 403 ", "request answered 403"),
    (r"action=BLOCK", "WAF blocked the request"),
    (r"connection reset|RST", "connection reset before completion"),
    (r"\" (400|404|415) ", "request rejected"),
]
BRUTE_FORCE = r"Failed password"


def _match_indicators(inc: Incident, line: str, source: str) -> tuple[str, str] | None:
    """Per-CVE indicators first (they are precise), then generic ones."""
    for cve in inc.cves_seen.values():
        for ind in cve.get("success_indicators", []):
            if ind.get("source") in (source, None) and re.search(ind["pattern"], line, re.I):
                return "post_exploitation", ind.get("meaning", cve["id"])
        for ind in cve.get("failure_indicators", []):
            if ind.get("source") in (source, None) and re.search(ind["pattern"], line, re.I):
                return "attack_blocked", ind.get("meaning", cve["id"])
    for pat, meaning in GENERIC_POST_EXPLOIT:
        if re.search(pat, line, re.I):
            return "post_exploitation", meaning
    for pat, meaning in GENERIC_BLOCKED:
        if re.search(pat, line, re.I):
            return "attack_blocked", meaning
    return None


def _attacker_ips(inc: Incident) -> set[str]:
    ips = set()
    if inc.alert:
        ips.add(inc.alert.get("src_ip", ""))
    for h in inc.calls("get_alert"):
        if isinstance(h.result, dict) and h.result.get("src_ip"):
            ips.add(h.result["src_ip"])
    return {ip for ip in ips if ip}


def tag_result(inc: Incident, name: str, args: dict[str, Any], result: Any) -> list[str]:
    """Attach evidence derived from a tool result to the incident. Returns new evidence ids."""
    new: list[str] = []
    src = f"{name}({', '.join(str(v) for v in args.values())})"

    if name == "get_alert" and isinstance(result, dict):
        if inc.alert is None or result.get("alert_id") == inc.current_alert_id:
            inc.alert = result
        e = inc.add_evidence("context", src, f"{result['alert']['signature']} from {result['src_ip']} -> {result['dest_ip']}:{result['dest_port']}", 0.2,
                             "alert label only; says an attempt happened, not its outcome")
        new.append(e.id)

    elif name == "get_flow" and isinstance(result, dict):
        http = result.get("http") or {}
        status = http.get("status")
        if status in (403, 400, 404, 415):
            e = inc.add_evidence("attack_blocked", src, f"HTTP {status} for {http.get('method')} {http.get('url')}", 0.8, "request rejected at the edge")
            new.append(e.id)
        elif status == 200:
            e = inc.add_evidence("context", src, f"HTTP 200 ({http.get('length')} bytes) for {http.get('method')} {http.get('url')}", 0.4,
                                 "payload was accepted; outcome still unknown")
            new.append(e.id)
        ssh = result.get("ssh") or {}
        if ssh.get("auth_attempts_observed", 0) > 20:
            e = inc.add_evidence("brute_force", src, f"{ssh['auth_attempts_observed']} SSH auth attempts in one flow", 0.5, "credential guessing burst")
            new.append(e.id)

    elif name == "get_asset" and isinstance(result, dict):
        inc.asset = result
        inc.asset_unknown = False
        svc = ", ".join(f"{s['product']} {s['version']}" for s in result.get("services", []))
        e = inc.add_evidence("context", src, f"{result['hostname']} ({result['criticality']}): {svc}; controls={result.get('controls')}", 0.3, "asset record")
        new.append(e.id)

    elif name == "lookup_cves" and isinstance(result, dict):
        for m in result.get("matches", []):
            if m["affected"]:
                inc.cves_seen[m["id"]] = m
                inc.asset_vulnerable = True
                e = inc.add_evidence("vulnerable", src, f"{result['product']} {result['version']} affected by {m['id']} ({m['title']}, CVSS {m['cvss']})", 0.9, "known exploitable vulnerability")
                new.append(e.id)
        if result.get("matches") and not any(m["affected"] for m in result["matches"]):
            if inc.asset_vulnerable is None:
                inc.asset_vulnerable = False
            e = inc.add_evidence("not_vulnerable", src, f"{result['product']} {result['version']} not in affected range of {', '.join(result['known_cves'])}", 0.7, "version outside affected range per current KB")
            new.append(e.id)

    elif name == "search_logs" and isinstance(result, dict):
        source = result.get("source", "")
        attackers = _attacker_ips(inc)
        failed = 0
        for m in result.get("matches", []):
            line = m.get("line", "")
            if re.search(BRUTE_FORCE, line):
                failed += 1
            tag = _match_indicators(inc, line, source)
            if not tag:
                continue
            cat, meaning = tag
            # Blocked/allowed lines only count when they involve the attacker (or the alert flow).
            if attackers and cat == "attack_blocked" and not any(ip in line for ip in attackers):
                continue
            e = inc.add_evidence(cat, f"search_logs({result['host']}/{source})", line, 1.0 if cat == "post_exploitation" else 0.8, meaning)
            new.append(e.id)
        total = result.get("total", 0)
        if failed >= 20 or (source == "auth" and total >= 50):
            e = inc.add_evidence("brute_force", f"search_logs({result['host']}/{source})", f"{max(failed, total)} failed-password lines from the source", 0.5, "credential guessing burst")
            new.append(e.id)

    elif name == "search_playbooks" and isinstance(result, list) and result:
        top = next((r for r in result if r.get("evidence_plan") is not None), result[0])
        inc.playbook = top

    elif name == "check_allowlist" and isinstance(result, dict):
        if result.get("allowlisted"):
            e = inc.add_evidence("context", src, f"{result['ip']} is allow-listed: {result.get('note')}", 0.9, "source is authorised")
            new.append(e.id)

    return new


def tag_error(inc: Incident, name: str, args: dict[str, Any], status: int, message: str) -> list[str]:
    new: list[str] = []
    src = f"{name}({', '.join(str(v) for v in args.values())})"
    if name == "get_asset" and status == 404:
        inc.asset_unknown = True
        inc.asset = None
        e = inc.add_evidence("asset_unknown", src, f"no asset record for {args.get('key')}", 0.9, "cannot test vulnerability or read host logs")
        new.append(e.id)
    if name == "search_logs" and status == 404:
        e = inc.add_evidence("context", src, f"no log collection for {args.get('host')}", 0.5, "host logs unavailable")
        new.append(e.id)
    return new

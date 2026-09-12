"""The simulated environment. One `World` holds every store for a loaded scenario.

Design notes
- All state changes (block, isolate, ticket) are real inside the simulator: a blocked
  IP stops producing flows, so the agent's verification step can observe the effect.
- Scenarios can script *triggers*: when the agent performs a given action, the
  environment reacts (attacker pivots, analyst overrides, advisory revised). This is
  what makes adaptation demonstrable without a human clicking at the right moment.
- Scenarios can script *faults*: make a tool fail the first N times, so the agent's
  retry/fallback path is exercised deterministically.
- The `chaos()` entry point exposes the same reactions as one-click actions for the
  UI's chaos panel.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

from .retrieval import BM25Index

HERE = Path(__file__).parent
DATA_DIR = HERE / "data"
SCENARIO_DIR = HERE / "scenarios"


class ToolFault(Exception):
    """A simulated tool failure (HTTP status + message)."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class NotFound(Exception):
    pass


def parse_version(v: str) -> tuple[int, ...]:
    parts = []
    for p in re.split(r"[.\-p]", str(v)):
        m = re.match(r"\d+", p)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts)


def version_affected(cve: dict[str, Any], version: str) -> bool:
    if version in cve.get("affected_versions", []):
        return True
    below = cve.get("affected_below")
    if below:
        frm = cve.get("affected_from", "0")
        return parse_version(frm) <= parse_version(version) < parse_version(below)
    return False


def list_scenarios() -> list[dict[str, str]]:
    out = []
    for p in sorted(SCENARIO_DIR.glob("s*.json")):
        sc = json.loads(p.read_text(encoding="utf-8"))
        out.append({"id": sc["id"], "name": sc["name"], "description": sc["description"]})
    return out


def _expand_log_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand `{"repeat": N, "template": ...}` entries into N concrete lines."""
    out: list[dict[str, Any]] = []
    for e in entries:
        if "repeat" not in e:
            out.append(e)
            continue
        n = int(e["repeat"])
        start = dt.datetime.fromisoformat(e["start_ts"].replace("Z", "+00:00"))
        step = float(e.get("step_seconds", 1.0))
        vars_ = e.get("vars", {})
        users = vars_.get("user", ["root"])
        pid = int(vars_.get("pid_start", 1000))
        port = int(vars_.get("port_start", 40000))
        for i in range(n):
            ts = start + dt.timedelta(seconds=step * i)
            line = e["template"].format(
                hms=ts.strftime("%H:%M:%S"),
                pid=pid + i,
                port=port + i,
                user=users[i % len(users)],
                n=i + 1,
            )
            out.append({"ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "line": line})
    return out


class World:
    def __init__(self) -> None:
        self.scenario_id: str | None = None
        self.reset_empty()

    # ------------------------------------------------------------------ loading
    def reset_empty(self) -> None:
        self.meta: dict[str, Any] = {}
        self.expected: dict[str, Any] = {}
        self.assets: dict[str, dict[str, Any]] = {}
        self.ip_index: dict[str, str] = {}
        self.cves: dict[str, dict[str, Any]] = {}
        self.playbooks: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.flows: dict[str, dict[str, Any]] = {}
        self.logs: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self.allowlist: dict[str, str] = {}
        self.watchlist: dict[str, str] = {}
        self.firewall_rules: list[dict[str, Any]] = []
        self.isolated: dict[str, str] = {}
        self.tickets: list[dict[str, Any]] = []
        self.assessments: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.faults: dict[str, dict[str, Any]] = {}
        self.call_counts: dict[str, int] = {}
        self.triggers: list[dict[str, Any]] = []
        self.fired: set[int] = set()
        self.seq = 0
        self.audit: list[dict[str, Any]] = []
        self._index = BM25Index([])

    def load(self, scenario_id: str) -> dict[str, Any]:
        path = SCENARIO_DIR / f"{scenario_id}.json"
        if not path.exists():
            raise NotFound(f"scenario {scenario_id} not found")
        sc = json.loads(path.read_text(encoding="utf-8"))
        self.reset_empty()
        self.scenario_id = scenario_id
        self.meta = {"id": sc["id"], "name": sc["name"], "description": sc["description"]}
        self.expected = sc.get("expected", {})

        for a in json.loads((DATA_DIR / "assets.json").read_text(encoding="utf-8")):
            self._add_asset(a)
        for a in sc.get("assets", []):
            self._add_asset(a)
        for c in json.loads((DATA_DIR / "cves.json").read_text(encoding="utf-8")):
            self.cves[c["id"]] = c
        for c in sc.get("cve_overrides", []):
            self.cves[c["id"]] = c
        self.playbooks = json.loads((DATA_DIR / "playbooks.json").read_text(encoding="utf-8"))
        self._index = BM25Index(self.playbooks + self._advisory_docs())

        for al in sc.get("alerts", []):
            self._add_alert(al)
        for fid, fl in sc.get("flows", {}).items():
            self._add_flow(fl)
        for host, sources in sc.get("logs", {}).items():
            self.logs[host] = {src: _expand_log_entries(entries) for src, entries in sources.items()}
        for ip in sc.get("allowlist", []):
            self.allowlist[ip] = "scenario allow-list"
        self.faults = copy.deepcopy(sc.get("faults", {}))
        self.triggers = copy.deepcopy(sc.get("triggers", []))
        return self.meta

    def _advisory_docs(self) -> list[dict[str, Any]]:
        docs = []
        for c in self.cves.values():
            docs.append({
                "id": c["id"],
                "title": c["title"],
                "tags": [c["product"], "advisory", "cve"],
                "text": f"{c['title']}. Product {c['product']}. {c.get('prerequisites', '')} "
                        + " ".join(i["meaning"] for i in c.get("success_indicators", [])),
                "kind": "advisory",
            })
        return docs

    def _add_asset(self, a: dict[str, Any]) -> None:
        self.assets[a["hostname"]] = a
        for ip in a.get("ips", []):
            self.ip_index[ip] = a["hostname"]

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def _add_alert(self, al: dict[str, Any]) -> None:
        al = copy.deepcopy(al)
        al["seq"] = self._next_seq()
        self.alerts.append(al)

    def _add_flow(self, fl: dict[str, Any]) -> None:
        fl = copy.deepcopy(fl)
        fl["seq"] = self._next_seq()
        self.flows[str(fl["flow_id"])] = fl

    # ------------------------------------------------------------------ faults / triggers
    def _count(self, tool: str) -> None:
        self.call_counts[tool] = self.call_counts.get(tool, 0) + 1
        f = self.faults.get(tool)
        if f and self.call_counts[tool] <= int(f.get("fail_first", 0)):
            raise ToolFault(int(f.get("status", 503)), f.get("message", f"{tool} unavailable"))

    def _fire(self, on: str, **ctx: Any) -> None:
        for i, trig in enumerate(self.triggers):
            if i in self.fired or trig.get("on") != on:
                continue
            if "ip" in trig and trig["ip"] != ctx.get("ip"):
                continue
            if "verdict" in trig and trig["verdict"] != ctx.get("verdict"):
                continue
            if "nth" in trig and self.call_counts.get(on, 0) != int(trig["nth"]):
                continue
            self.fired.add(i)
            for action in trig.get("do", []):
                self._apply(action)

    def _apply(self, action: dict[str, Any]) -> None:
        if "add_alert" in action:
            self._add_alert(action["add_alert"])
        elif "add_flow" in action:
            self._add_flow(action["add_flow"])
        elif "add_logs" in action:
            spec = action["add_logs"]
            host = spec["host"]
            self.logs.setdefault(host, {})
            for src, entries in spec.items():
                if src == "host":
                    continue
                self.logs[host].setdefault(src, []).extend(_expand_log_entries(entries))
        elif "emit_event" in action:
            ev = copy.deepcopy(action["emit_event"])
            ev["seq"] = self._next_seq()
            ev["ts"] = self._now()
            self.events.append(ev)
        elif "allowlist_add" in action:
            spec = action["allowlist_add"]
            self.allowlist[spec["ip"]] = spec.get("note", "analyst")
        elif "cve_upsert" in action:
            c = action["cve_upsert"]
            self.cves[c["id"]] = c
            self._index = BM25Index(self.playbooks + self._advisory_docs())
        elif "fault" in action:
            spec = action["fault"]
            tool = spec["tool"]
            self.faults[tool] = {
                "fail_first": self.call_counts.get(tool, 0) + int(spec.get("count", 1)),
                "status": spec.get("status", 503),
                "message": spec.get("message", f"{tool} unavailable"),
            }
        else:
            raise ValueError(f"unknown trigger action {action}")

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _log(self, tool: str, args: dict[str, Any], ok: bool = True, err: str | None = None) -> None:
        self.audit.append({"seq": self._next_seq(), "ts": self._now(), "tool": tool, "args": args, "ok": ok, "error": err})

    # ------------------------------------------------------------------ read tools
    # ------------------------------------------------------------------ state transport (serverless mode)
    STATE_FIELDS = ("alerts", "flows", "logs", "allowlist", "watchlist", "firewall_rules", "isolated", "tickets",
                    "assessments", "events", "faults", "call_counts", "seq", "audit", "cves")

    def snapshot(self) -> dict[str, Any]:
        """Everything that changes after load(), as JSON: carried by the client between stateless requests."""
        st = {k: copy.deepcopy(getattr(self, k)) for k in self.STATE_FIELDS}
        st["scenario_id"] = self.scenario_id
        st["fired"] = sorted(self.fired)
        return st

    def restore(self, st: dict[str, Any]) -> None:
        self.load(st["scenario_id"])
        for k in self.STATE_FIELDS:
            if k in st:
                setattr(self, k, copy.deepcopy(st[k]))
        self.fired = set(st.get("fired", []))
        self._index = BM25Index(self.playbooks + self._advisory_docs())


    def list_alerts(self, since_seq: int = 0) -> list[dict[str, Any]]:
        self._count("list_alerts")
        return [a for a in self.alerts if a["seq"] > since_seq]

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        self._count("get_alert")
        for a in self.alerts:
            if a["alert_id"] == alert_id:
                return a
        raise NotFound(f"alert {alert_id} not found")

    def get_flow(self, flow_id: int | str) -> dict[str, Any]:
        self._count("get_flow")
        fl = self.flows.get(str(flow_id))
        if not fl:
            raise NotFound(f"flow {flow_id} not found")
        return fl

    def get_asset(self, key: str) -> dict[str, Any]:
        self._count("get_asset")
        host = self.ip_index.get(key, key)
        a = self.assets.get(host)
        if not a:
            raise NotFound(f"no asset record for {key}")
        out = dict(a)
        out["isolated"] = host in self.isolated
        return out

    def lookup_cves(self, product: str, version: str) -> dict[str, Any]:
        self._count("lookup_cves")
        product_l = product.lower()
        matches, known = [], []
        for c in self.cves.values():
            if c["product"].lower() != product_l:
                continue
            known.append(c["id"])
            aff = version_affected(c, version)
            matches.append({
                "id": c["id"], "title": c["title"], "cvss": c.get("cvss"),
                "affected": aff,
                "affected_range": c.get("affected_versions") or f">= {c.get('affected_from', '0')} < {c.get('affected_below')}",
                "prerequisites": c.get("prerequisites"),
                "success_indicators": c.get("success_indicators", []) if aff else [],
            })
        result = {
            "product": product, "version": version,
            "known_cves": known, "matches": matches,
            "vulnerable": any(m["affected"] for m in matches) if matches else None,
            "note": None if matches else "no advisories for this product in the KB (unknown, not proven safe)",
        }
        self._fire("lookup_cves", product=product)
        return result

    def get_cve(self, cve_id: str) -> dict[str, Any]:
        self._count("get_cve")
        c = self.cves.get(cve_id)
        if not c:
            raise NotFound(f"{cve_id} not in KB")
        return c

    def search_logs(self, host: str, source: str, pattern: str | None = None, limit: int = 60) -> dict[str, Any]:
        self._count("search_logs")
        host = self.ip_index.get(host, host)
        if host not in self.assets:
            raise NotFound(f"no log collection for unknown host {host}")
        sources = self.logs.get(host, {})
        if source not in sources:
            return {"host": host, "source": source, "available_sources": sorted(sources), "total": 0, "matches": []}
        entries = sources[source]
        if pattern:
            try:
                rx = re.compile(pattern, re.I)
            except re.error as e:
                raise ToolFault(400, f"bad regex: {e}")
            hits = [e for e in entries if rx.search(e["line"])]
        else:
            hits = list(entries)
        total = len(hits)
        # Keep the head and tail so bursts (240 failed logins) stay readable.
        if total > limit:
            hits = hits[: limit // 2] + [{"ts": "...", "line": f"... {total - limit} lines omitted ..."}] + hits[-(limit // 2):]
        return {"host": host, "source": source, "pattern": pattern, "total": total, "matches": hits}

    def search_playbooks(self, query: str, k: int = 3) -> list[dict[str, Any]]:
        self._count("search_playbooks")
        out = []
        for score, d in self._index.search(query, k=k):
            item = {"id": d["id"], "title": d["title"], "score": round(score, 2), "text": d["text"]}
            if d.get("kind") != "advisory":
                item["evidence_plan"] = d.get("evidence_plan", [])
            out.append(item)
        return out

    def check_allowlist(self, ip: str) -> dict[str, Any]:
        self._count("check_allowlist")
        return {
            "ip": ip,
            "allowlisted": ip in self.allowlist,
            "note": self.allowlist.get(ip),
            "watchlisted": ip in self.watchlist,
            "blocked": any(r["ip"] == ip for r in self.firewall_rules),
        }

    # ------------------------------------------------------------------ state-changing tools
    def block_ip(self, ip: str, reason: str, incident_id: str | None = None) -> dict[str, Any]:
        self._count("block_ip")
        if ip in self.allowlist:
            # The firewall itself refuses allow-listed sources; belt and braces.
            raise ToolFault(409, f"{ip} is allow-listed ({self.allowlist[ip]}); rule refused")
        existing = next((r for r in self.firewall_rules if r["ip"] == ip), None)
        if existing:
            return {"ok": True, "rule": existing, "already_present": True}
        rule = {"rule_id": f"fw-{len(self.firewall_rules) + 1:04d}", "ip": ip, "action": "DROP", "reason": reason,
                "incident_id": incident_id, "created_seq": self._next_seq(), "created_ts": self._now()}
        self.firewall_rules.append(rule)
        self._log("block_ip", {"ip": ip, "reason": reason})
        self._fire("block_ip", ip=ip)
        return {"ok": True, "rule": rule, "already_present": False}

    def unblock_ip(self, ip: str, reason: str) -> dict[str, Any]:
        self._count("unblock_ip")
        before = len(self.firewall_rules)
        self.firewall_rules = [r for r in self.firewall_rules if r["ip"] != ip]
        self._log("unblock_ip", {"ip": ip, "reason": reason})
        return {"ok": True, "removed": before - len(self.firewall_rules)}

    def list_rules(self) -> list[dict[str, Any]]:
        self._count("list_rules")
        return list(self.firewall_rules)

    def verify_block(self, ip: str) -> dict[str, Any]:
        self._count("verify_block")
        rule = next((r for r in self.firewall_rules if r["ip"] == ip), None)
        since = rule["created_seq"] if rule else 0
        # A blocked IP cannot create flows; anything newer from it means the rule is not effective.
        flows_since = [f for f in self.flows.values() if f["src_ip"] == ip and f["seq"] > since]
        new_alerts = [a for a in self.alerts if a["seq"] > since]
        return {
            "ip": ip,
            "rule_present": rule is not None,
            "rule": rule,
            "flows_since_rule": flows_since,
            "new_alerts_since_rule": new_alerts,
            "effective": rule is not None and not flows_since,
        }

    def isolate_host(self, host: str, reason: str) -> dict[str, Any]:
        self._count("isolate_host")
        host = self.ip_index.get(host, host)
        if host not in self.assets:
            raise NotFound(f"unknown host {host}")
        self.isolated[host] = reason
        self._log("isolate_host", {"host": host, "reason": reason})
        return {"ok": True, "host": host, "isolated": True}

    def release_host(self, host: str, reason: str) -> dict[str, Any]:
        self._count("release_host")
        host = self.ip_index.get(host, host)
        self.isolated.pop(host, None)
        self._log("release_host", {"host": host, "reason": reason})
        return {"ok": True, "host": host, "isolated": False}

    def add_watchlist(self, ip: str, reason: str) -> dict[str, Any]:
        self._count("add_watchlist")
        self.watchlist[ip] = reason
        return {"ok": True, "ip": ip}

    def escalate(self, incident_id: str, reason: str, missing_evidence: list[str] | None = None,
                 summary: str | None = None) -> dict[str, Any]:
        self._count("escalate")
        t = {"ticket_id": f"SOC-{1000 + len(self.tickets) + 1}", "incident_id": incident_id, "reason": reason,
             "missing_evidence": missing_evidence or [], "summary": summary, "status": "open", "ts": self._now()}
        self.tickets.append(t)
        self._log("escalate", {"incident_id": incident_id, "reason": reason})
        return t

    def file_assessment(self, incident_id: str, verdict: str, confidence: float, summary: str,
                        evidence_ids: list[str] | None = None) -> dict[str, Any]:
        self._count("file_assessment")
        a = {"assessment_id": f"asm-{len(self.assessments) + 1:03d}", "incident_id": incident_id, "verdict": verdict,
             "confidence": confidence, "summary": summary, "evidence_ids": evidence_ids or [], "ts": self._now()}
        self.assessments.append(a)
        self._log("file_assessment", {"incident_id": incident_id, "verdict": verdict})
        self._fire("file_assessment", verdict=verdict)
        return a

    # ------------------------------------------------------------------ events / chaos
    def get_events(self, since_seq: int = 0) -> list[dict[str, Any]]:
        return [e for e in self.events if e["seq"] > since_seq]

    def chaos(self, kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """One-click disruptions for the UI's chaos panel. Same machinery as scripted triggers."""
        p = payload or {}
        if kind == "pivot":
            src = p.get("from_ip") or (self.alerts[-1]["src_ip"] if self.alerts else None)
            base = next((a for a in reversed(self.alerts) if a["src_ip"] == src), None)
            if not base:
                raise NotFound("no alert to pivot from")
            new_ip = p.get("to_ip", "198.51.100.23")
            al = copy.deepcopy(base)
            al["alert_id"] = f"{base['alert_id']}-pivot"
            al["src_ip"] = new_ip
            al["flow_id"] = int(base["flow_id"]) + 1
            al["timestamp"] = self._now()
            self._apply({"add_alert": al})
            fl = copy.deepcopy(self.flows.get(str(base["flow_id"]), {"flow_id": base["flow_id"], "dest_ip": base["dest_ip"], "dest_port": base["dest_port"], "proto": "TCP"}))
            fl["flow_id"] = al["flow_id"]
            fl["src_ip"] = new_ip
            self._apply({"add_flow": fl})
            self._apply({"emit_event": {"type": "new_alert", "alert_id": al["alert_id"],
                                        "note": f"New alert {al['alert_id']} from {new_ip} against {al['dest_ip']} with the same signature as {base['alert_id']}."}})
            return {"ok": True, "alert_id": al["alert_id"], "src_ip": new_ip}
        if kind == "log_outage":
            self._apply({"fault": {"tool": "search_logs", "count": int(p.get("count", 2)), "status": 503,
                                   "message": "log indexer unavailable (chaos)"}})
            return {"ok": True, "fails_next": int(p.get("count", 2))}
        if kind == "override":
            ip = p.get("ip") or (self.alerts[-1]["src_ip"] if self.alerts else None)
            note = p.get("note", "Authorised penetration test; unblock and record exception.")
            self._apply({"allowlist_add": {"ip": ip, "note": note}})
            self._apply({"emit_event": {"type": "analyst_override", "ip": ip, "analyst": p.get("analyst", "analyst"), "note": note}})
            return {"ok": True, "ip": ip}
        if kind == "kb_update":
            cve_id = p.get("cve", "CVE-2021-42013")
            c = self.cves.get(cve_id)
            if not c:
                raise NotFound(f"{cve_id} not in KB to revise; use a scripted cve_upsert")
            c = copy.deepcopy(c)
            c["affected_versions"] = sorted(set(c.get("affected_versions", []) + p.get("add_versions", [])))
            self._apply({"cve_upsert": c})
            self._apply({"emit_event": {"type": "kb_update", "cve": cve_id, "product": c["product"],
                                        "note": f"Advisory KB revised: {cve_id} affected versions now {c['affected_versions']}."}})
            return {"ok": True, "cve": cve_id}
        if kind == "firewall_reject":
            self._apply({"fault": {"tool": "block_ip", "count": int(p.get("count", 1)), "status": 502,
                                   "message": "firewall API: rule quota exceeded, retry later (chaos)"}})
            return {"ok": True}
        if kind == "new_alert":
            if not self.alerts:
                raise NotFound("no alert to clone")
            base = copy.deepcopy(self.alerts[-1])
            base["alert_id"] = f"{base['alert_id']}-again"
            base["timestamp"] = self._now()
            self._apply({"add_alert": base})
            self._apply({"emit_event": {"type": "new_alert", "alert_id": base["alert_id"],
                                        "note": f"Another alert {base['alert_id']} from {base['src_ip']} against {base['dest_ip']}."}})
            return {"ok": True, "alert_id": base["alert_id"]}
        raise NotFound(f"unknown chaos kind {kind}")

    # ------------------------------------------------------------------ truth (eval only)
    def truth(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario_id,
            "expected": self.expected,
            "blocked_ips": sorted(r["ip"] for r in self.firewall_rules),
            "isolated_hosts": sorted(self.isolated),
            "allowlist": sorted(self.allowlist),
            "watchlist": sorted(self.watchlist),
            "tickets": self.tickets,
            "assessments": self.assessments,
            "call_counts": self.call_counts,
        }

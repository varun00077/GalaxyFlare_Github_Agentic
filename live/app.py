"""Live host environment with the sandbox's HTTP API.

  uvicorn live.app:app --port 8002        then SANDBOX_URL=http://localhost:8002 for the agent/console
  (or ENVIRONMENT=live in .env to mount it in-process)

Alerts are derived from real events on this machine (failed-logon bursts, Defender detections) or
imported from a real Suricata eve.json (LIVE_EVE_JSON=path). Assets, logs and connections are live.
CVEs come from NVD. Firewall actions are real only when elevated and LIVE_ACTIONS=1.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import zlib
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from sandbox.retrieval import BM25Index
from sandbox.world import DATA_DIR, NotFound, ToolFault

from . import host_win as host
from .external import ip_intel, is_private, nvd_lookup

STATE_DIR = Path(os.getenv("LIVE_STATE_DIR", "data/live"))
HERE = Path(__file__).parent


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LiveWorld:
    def __init__(self) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.host = host.hostname()
        self.ips = host.primary_ips()
        self.admin = host.is_admin()
        self.live_actions = os.getenv("LIVE_ACTIONS", "0") == "1" and self.admin
        self.threshold = int(os.getenv("LIVE_BRUTE_THRESHOLD", "5"))
        self.hours = int(os.getenv("LIVE_WINDOW_HOURS", "24"))
        self.seq = 0
        self.alerts: list[dict[str, Any]] = []
        self.flows: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.firewall_rules: list[dict[str, Any]] = []
        self.watchlist: dict[str, str] = {}
        self.tickets = self._load("tickets", [])
        self.assessments = self._load("assessments", [])
        self.allowlist: dict[str, str] = self._load("allowlist", {})
        self.audit: list[dict[str, Any]] = []
        self.call_counts: dict[str, int] = defaultdict(int)
        self.security_available: bool | None = None
        playbooks = json.loads((DATA_DIR / "playbooks.json").read_text(encoding="utf-8"))
        playbooks += json.loads((HERE / "playbooks_windows.json").read_text(encoding="utf-8"))
        self.playbooks = playbooks
        self._index = BM25Index(playbooks)
        self._asset_cache: dict[str, Any] | None = None
        self.scan()

    # ------------------------------------------------------------------ persistence
    def _load(self, name: str, default: Any) -> Any:
        p = STATE_DIR / f"{name}.json"
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
        except json.JSONDecodeError:
            return default

    def _save(self, name: str, value: Any) -> None:
        (STATE_DIR / f"{name}.json").write_text(json.dumps(value, indent=2), encoding="utf-8")

    def _next(self) -> int:
        self.seq += 1
        return self.seq

    # ------------------------------------------------------------------ alert derivation
    def scan(self) -> dict[str, Any]:
        """Derive alerts from real events. Idempotent: existing alert ids keep their seq."""
        existing = {a["alert_id"]: a for a in self.alerts}
        found: list[dict[str, Any]] = []
        dest = self.ips[0] if self.ips else "127.0.0.1"

        # 1. failed-logon bursts (needs elevated read of the Security log)
        ev = host.events("security", ids=[4625], max_events=2000, hours=self.hours)
        if isinstance(ev, dict):
            self.security_available = False
        else:
            self.security_available = True
            groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for e in ev:
                p = e.get("props") or []
                src = (p[19] if len(p) > 19 else "") or (p[13] if len(p) > 13 else "") or "local"
                groups[src].append(e)
            for src, items in groups.items():
                if len(items) < self.threshold:
                    continue
                users = sorted({(i.get("props") or ["", "", "", "", "", "?"])[5] for i in items})
                types = sorted({(i.get("props") or [""] * 11)[10] for i in items})
                first, last = items[-1]["ts"], items[0]["ts"]
                src_ip = src if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", src) else "127.0.0.1"
                port = 3389 if "10" in types else 445
                aid = f"live-brute-{re.sub(r'[^A-Za-z0-9]', '', src)}"
                fid = zlib.crc32(aid.encode()) % 10**9
                found.append({
                    "alert_id": aid, "timestamp": last, "event_type": "alert", "flow_id": fid,
                    "src_ip": src_ip, "src_port": 0, "dest_ip": dest, "dest_port": port, "proto": "TCP", "app_proto": "smb" if port == 445 else "rdp",
                    "alert": {"signature": f"LOCAL Windows logon brute force: {len(items)} failed logons (4625) from {src} in {self.hours}h",
                              "signature_id": 4625, "category": "Attempted User Privilege Gain", "severity": 2},
                    "source": "windows-security-log",
                })
                self.flows[str(fid)] = {"flow_id": fid, "src_ip": src_ip, "dest_ip": dest, "dest_port": port, "proto": "TCP",
                                        "logon": {"failed_attempts": len(items), "usernames_tried": users[:20], "logon_types": types,
                                                  "first": first, "last": last, "source_label": src},
                                        "note": "derived from Windows Security log event 4625"}

        # 2. Defender detections
        ev = host.events("defender", ids=[1116, 1117], max_events=200, hours=self.hours)
        if isinstance(ev, list):
            seen = set()
            for e in ev:
                msg = e.get("message", "")
                m = re.search(r"Name:\s*([^\r\n]+)", " ".join((e.get("props") or [])[:20]) + " " + msg)
                name = (m.group(1).strip() if m else (e.get("props") or ["?"])[7] if len(e.get("props") or []) > 7 else "threat")[:80]
                if name in seen:
                    continue
                seen.add(name)
                aid = f"live-defender-{re.sub(r'[^A-Za-z0-9]', '', name)[:40]}"
                fid = zlib.crc32(aid.encode()) % 10**9
                found.append({
                    "alert_id": aid, "timestamp": e["ts"], "event_type": "alert", "flow_id": fid,
                    "src_ip": "127.0.0.1", "src_port": 0, "dest_ip": dest, "dest_port": 0, "proto": "-", "app_proto": "file",
                    "alert": {"signature": f"LOCAL Windows Defender detection: {name}", "signature_id": e["id"],
                              "category": "A Network Trojan was detected", "severity": 1},
                    "source": "windows-defender-log",
                })
                self.flows[str(fid)] = {"flow_id": fid, "src_ip": "127.0.0.1", "dest_ip": dest, "dest_port": 0, "proto": "-",
                                        "defender": {"event": e["id"], "message": msg[:300], "props": (e.get("props") or [])[:12]},
                                        "note": "derived from Windows Defender operational log"}

        # 3. real Suricata eve.json, if provided
        eve = os.getenv("LIVE_EVE_JSON")
        if eve and Path(eve).exists():
            for line in Path(eve).read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("event_type") == "alert":
                    rec = {**rec, "alert_id": f"eve-{rec.get('flow_id')}-{rec.get('alert', {}).get('signature_id')}", "source": "suricata-eve"}
                    found.append(rec)
                elif rec.get("event_type") in ("flow", "http"):
                    fid = str(rec.get("flow_id"))
                    self.flows.setdefault(fid, {"flow_id": rec.get("flow_id")}).update(rec)

        # merge: keep seq for known alerts, add new ones
        merged = []
        for a in found:
            if a["alert_id"] in existing:
                merged.append(existing[a["alert_id"]])
            else:
                a["seq"] = self._next()
                merged.append(a)
                if existing:  # a genuinely new alert after startup -> environment event
                    self.events.append({"seq": self._next(), "ts": _now(), "type": "new_alert", "alert_id": a["alert_id"],
                                        "note": f"New live alert {a['alert_id']}: {a['alert']['signature']}"})
        # manual alerts survive rescans
        merged += [a for a in self.alerts if a.get("source") == "manual"]
        self.alerts = merged
        return {"alerts": len(self.alerts), "security_log": self.security_available, "admin": self.admin, "live_actions": self.live_actions}

    def add_manual_alert(self, spec: dict[str, Any]) -> dict[str, Any]:
        dest = self.ips[0] if self.ips else "127.0.0.1"
        aid = spec.get("alert_id") or f"manual-{self._next()}"
        fid = zlib.crc32(aid.encode()) % 10**9
        a = {"alert_id": aid, "timestamp": _now(), "event_type": "alert", "flow_id": fid, "src_ip": spec.get("src_ip", "0.0.0.0"), "src_port": 0,
             "dest_ip": spec.get("dest_ip", dest), "dest_port": int(spec.get("dest_port", 0)), "proto": "TCP", "app_proto": spec.get("app_proto", "-"),
             "alert": {"signature": spec.get("signature", "MANUAL analyst-submitted alert"), "signature_id": 0,
                       "category": spec.get("category", "Misc activity"), "severity": int(spec.get("severity", 2))},
             "source": "manual", "seq": self._next()}
        self.alerts.append(a)
        self.flows[str(fid)] = {"flow_id": fid, "src_ip": a["src_ip"], "dest_ip": a["dest_ip"], "dest_port": a["dest_port"], "proto": "TCP",
                                "note": spec.get("note", "manual alert; no captured flow")}
        self.events.append({"seq": self._next(), "ts": _now(), "type": "new_alert", "alert_id": aid, "note": f"Analyst submitted alert {aid}: {a['alert']['signature']}"})
        return a

    # ------------------------------------------------------------------ read tools
    def meta(self) -> dict[str, Any]:
        return {"id": "live", "name": f"Live host: {self.host} ({', '.join(self.ips) or 'no IPv4'})",
                "description": f"Real events, logs and connections from this machine. Security log {'readable' if self.security_available else 'NOT readable (run elevated)'}; "
                               f"firewall actions {'REAL' if self.live_actions else 'dry-run'}."}

    def list_alerts(self, since_seq: int = 0) -> list[dict[str, Any]]:
        return [a for a in self.alerts if a["seq"] > since_seq]

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        for a in self.alerts:
            if a["alert_id"] == alert_id:
                return a
        raise NotFound(f"alert {alert_id} not found")

    def get_flow(self, flow_id: str) -> dict[str, Any]:
        fl = self.flows.get(str(flow_id))
        if not fl:
            raise NotFound(f"flow {flow_id} not found")
        return fl

    def _is_me(self, key: str) -> bool:
        k = key.lower()
        return k in {self.host.lower(), "localhost", "127.0.0.1", *[ip.lower() for ip in self.ips]}

    def get_asset(self, key: str) -> dict[str, Any]:
        if not self._is_me(key):
            raise NotFound(f"no asset record for {key} (live mode only knows this host; other hosts are not in inventory)")
        if self._asset_cache is None:
            osi = host.os_info()
            sw = host.installed_software()
            listen = host.listening_ports()
            # Keep the record small enough for a planner call: server-ish software first, then the rest, capped.
            risky = re.compile(r"apache|tomcat|java|jdk|jre|php|mysql|postgres|mongo|redis|node|python|openssh|ssh|vmware|virtualbox|docker|nginx|iis|chrome|firefox|edge|office|adobe|7-zip|winrar|teamviewer|anydesk|putty|git|wireshark|npcap", re.I)
            ranked = sorted((s for s in sw if s.get("product")), key=lambda s: (0 if risky.search(s["product"]) else 1, s["product"].lower()))
            services = [{"product": s["product"], "version": s["version"], "port": None} for s in ranked[:45]]
            services.insert(0, {"product": "windows", "version": str(osi.get("version") or ""), "port": None})
            omitted = max(0, len(ranked) - 45)
            self._asset_cache = {
                "hostname": self.host, "ips": self.ips, "os": f"{osi.get('caption')} {osi.get('version')}",
                "services": services,
                "listening": [{"port": l.get("port"), "process": l.get("process")} for l in listen][:20],
                "services_omitted": omitted,
                "criticality": os.getenv("LIVE_CRITICALITY", "high"), "owner": os.getenv("USERNAME", "local user"), "internet_facing": False,
                "patch_date": None, "controls": {"edr": "Windows Defender", "firewall": "Windows Defender Firewall", "elevated_agent": self.admin},
                "isolated": False, "note": "live host record built from OS, installed-software registry and listening sockets",
            }
        return self._asset_cache

    def lookup_cves(self, product: str, version: str) -> dict[str, Any]:
        res = nvd_lookup(product, version)
        if "error" in res:
            raise ToolFault(int(res.get("status", 503)), res["error"])
        return res

    def search_logs(self, hostname: str, source: str, pattern: str | None, limit: int = 60) -> dict[str, Any]:
        if not self._is_me(hostname):
            raise NotFound(f"no log collection for {hostname} in live mode")
        lines: list[dict[str, str]]
        if source == "process":
            lines = [{"ts": p.get("started") or "", "line": f"{(p.get('started') or '')[:19]} proc={p.get('ProcessName')} pid={p.get('Id')} parent={p.get('parent') or '-'} path={p.get('Path') or '-'}"} for p in host.processes()]
        elif source == "outbound":
            lines = [{"ts": c.get("created") or "", "line": f"{(c.get('created') or '')[:19]} conn {c.get('state')} local={c.get('local')} remote={c.get('remote')}:{c.get('rport')} process={c.get('process') or '-'} pid={c.get('pid')}"} for c in host.connections()]
        else:
            ids = {"security": [4624, 4625, 4648, 4672, 4688, 4720, 4732], "powershell": [4104], "defender": [1116, 1117, 1118, 1119]}.get(source)
            ev = host.events(source, ids=ids, max_events=1500, hours=self.hours)
            if isinstance(ev, dict):
                msg = ev["error"]
                if "unauthorized" in msg.lower() or "access" in msg.lower():
                    raise ToolFault(503, f"{source} log requires an elevated process (run the service as Administrator): {msg}")
                if "unknown source" in msg:
                    raise ToolFault(400, msg)
                raise ToolFault(503, msg)
            lines = [{"ts": e.get("ts", ""), "line": host.render_event(e)} for e in ev]
        if pattern:
            try:
                rx = re.compile(pattern, re.I)
            except re.error as e:
                raise ToolFault(400, f"bad regex: {e}")
            hits = [l for l in lines if rx.search(l["line"])]
        else:
            hits = lines
        total = len(hits)
        if total > limit:
            hits = hits[: limit // 2] + [{"ts": "...", "line": f"... {total - limit} lines omitted ..."}] + hits[-(limit // 2):]
        return {"host": self.host, "source": source, "pattern": pattern, "total": total, "matches": hits,
                "available_sources": ["security", "system", "application", "defender", "powershell", "rdp", "firewall", "process", "outbound"]}

    def search_playbooks(self, query: str, k: int = 3) -> list[dict[str, Any]]:
        return [{"id": d["id"], "title": d["title"], "score": round(s, 2), "text": d["text"], "evidence_plan": d.get("evidence_plan", [])}
                for s, d in self._index.search(query, k=k)]

    def check_allowlist(self, ip: str) -> dict[str, Any]:
        intel = ip_intel(ip)
        return {"ip": ip, "allowlisted": ip in self.allowlist, "note": self.allowlist.get(ip), "watchlisted": ip in self.watchlist,
                "blocked": any(r["ip"] == ip for r in self.firewall_rules), "scope": intel.get("scope"), "geo": intel.get("geo"), "abuse": intel.get("abuse")}

    # ------------------------------------------------------------------ actions
    def block_ip(self, ip: str, reason: str, incident_id: str | None) -> dict[str, Any]:
        if ip in self.allowlist:
            raise ToolFault(409, f"{ip} is allow-listed ({self.allowlist[ip]}); rule refused")
        if is_private(ip) and not os.getenv("LIVE_ALLOW_PRIVATE_BLOCK"):
            raise ToolFault(409, f"{ip} is a private/local address; blocking it could cut this machine off its own LAN. Escalate instead (set LIVE_ALLOW_PRIVATE_BLOCK=1 to permit).")
        existing = next((r for r in self.firewall_rules if r["ip"] == ip), None)
        if existing:
            return {"ok": True, "rule": existing, "already_present": True}
        rule = {"rule_id": f"fw-live-{len(self.firewall_rules) + 1:03d}", "ip": ip, "action": "DROP", "reason": reason, "incident_id": incident_id,
                "created_seq": self._next(), "created_ts": _now(), "dry_run": not self.live_actions}
        if self.live_actions:
            res = host.firewall_block(ip)
            if "error" in res:
                raise ToolFault(502, f"Windows Firewall refused the rule: {res['error']}")
        self.firewall_rules.append(rule)
        self.audit.append({"ts": _now(), "tool": "block_ip", "ip": ip, "dry_run": rule["dry_run"]})
        return {"ok": True, "rule": rule, "already_present": False,
                "note": "REAL Windows Firewall rule added" if self.live_actions else "DRY RUN: rule recorded, not applied (run elevated with LIVE_ACTIONS=1 for real blocks)"}

    def unblock_ip(self, ip: str, reason: str) -> dict[str, Any]:
        before = len(self.firewall_rules)
        self.firewall_rules = [r for r in self.firewall_rules if r["ip"] != ip]
        if self.live_actions:
            host.firewall_unblock(ip)
        self.audit.append({"ts": _now(), "tool": "unblock_ip", "ip": ip})
        return {"ok": True, "removed": before - len(self.firewall_rules)}

    def verify_block(self, ip: str) -> dict[str, Any]:
        rule = next((r for r in self.firewall_rules if r["ip"] == ip), None)
        present = rule is not None
        if rule and not rule["dry_run"]:
            present = any(ip in (r.get("remote") or "") for r in host.firewall_rules())
        live = [c for c in host.connections() if c.get("remote") == ip and c.get("state") == "Established"]
        since = rule["created_seq"] if rule else 0
        return {"ip": ip, "rule_present": present, "rule": rule, "dry_run": bool(rule and rule["dry_run"]),
                "flows_since_rule": [{"flow_id": f"live-{i}", "src_ip": ip, "seq": since + 1, "state": c.get("state"), "process": c.get("process")} for i, c in enumerate(live)] if (rule and not rule["dry_run"]) else [],
                "live_connections_to_ip": len(live),
                "new_alerts_since_rule": [a for a in self.alerts if a["seq"] > since],
                "effective": present and (not live or bool(rule and rule["dry_run"])),
                "note": None if not rule or not rule["dry_run"] else "dry-run rule: verification confirms the record, not the network"}

    def isolate_host(self, hostname: str, reason: str) -> dict[str, Any]:
        raise ToolFault(403, "host isolation is not permitted for the local machine in live mode (it would sever this host's own network); escalate to an analyst")

    def add_watchlist(self, ip: str, reason: str) -> dict[str, Any]:
        self.watchlist[ip] = reason
        return {"ok": True, "ip": ip}

    def escalate(self, incident_id: str, reason: str, missing: list[str], summary: str | None) -> dict[str, Any]:
        t = {"ticket_id": f"LIVE-{1000 + len(self.tickets) + 1}", "incident_id": incident_id, "reason": reason, "missing_evidence": missing, "summary": summary, "status": "open", "ts": _now()}
        self.tickets.append(t)
        self._save("tickets", self.tickets)
        return t

    def file_assessment(self, incident_id: str, verdict: str, confidence: float, summary: str, evidence_ids: list[str]) -> dict[str, Any]:
        a = {"assessment_id": f"asm-live-{len(self.assessments) + 1:03d}", "incident_id": incident_id, "verdict": verdict, "confidence": confidence, "summary": summary, "evidence_ids": evidence_ids, "ts": _now()}
        self.assessments.append(a)
        self._save("assessments", self.assessments)
        return a

    def chaos(self, kind: str, p: dict[str, Any]) -> dict[str, Any]:
        if kind == "override":
            ip = p.get("ip") or (self.alerts[-1]["src_ip"] if self.alerts else None)
            note = p.get("note", "Authorised source per analyst.")
            self.allowlist[ip] = note
            self._save("allowlist", self.allowlist)
            self.events.append({"seq": self._next(), "ts": _now(), "type": "analyst_override", "ip": ip, "analyst": p.get("analyst", "analyst"), "note": note})
            return {"ok": True, "ip": ip}
        if kind == "new_alert":
            return {"ok": True, **self.scan()}
        if kind == "brute_force_test":
            res = host.generate_failed_logons(int(p.get("count", 6)))
            return {"ok": True, **res, **self.scan(), "note": "generated real 4625 events locally; rescan done"}
        raise NotFound(f"chaos '{kind}' is not available in live mode (only override, new_alert, brute_force_test)")

    def truth(self) -> dict[str, Any]:
        return {"scenario": "live", "expected": {}, "blocked_ips": sorted(r["ip"] for r in self.firewall_rules), "isolated_hosts": [],
                "allowlist": sorted(self.allowlist), "watchlist": sorted(self.watchlist), "tickets": self.tickets, "assessments": self.assessments,
                "call_counts": dict(self.call_counts), "live": {"admin": self.admin, "live_actions": self.live_actions, "security_log": self.security_available,
                                                                "host": self.host, "ips": self.ips, "dry_run_rules": [r for r in self.firewall_rules if r["dry_run"]]}}


world: LiveWorld | None = None


def _w() -> LiveWorld:
    global world
    if world is None:
        world = LiveWorld()
    return world


@asynccontextmanager
async def _lifespan(_: FastAPI):
    _w()
    yield


app = FastAPI(title="SOCrates live host", version="0.1.0", lifespan=_lifespan)


@app.exception_handler(ToolFault)
async def _fault(_, exc: ToolFault) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"error": exc.message, "fault": True})


@app.exception_handler(NotFound)
async def _nf(_, exc: NotFound) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": str(exc)})


@app.get("/health")
def health(): return {"ok": True, "scenario": "live", **_w().meta()}
@app.get("/scenarios")
def scenarios(): return [_w().meta()]
class LoadReq(BaseModel):
    scenario: str
@app.post("/scenario/load")
def load(req: LoadReq): _w().scan(); return _w().meta()
@app.get("/scenario")
def scenario(): return _w().meta()
@app.get("/truth")
def truth(): return _w().truth()
@app.get("/alerts")
def alerts(since_seq: int = 0): return _w().list_alerts(since_seq)
@app.get("/alerts/{alert_id}")
def alert(alert_id: str): return _w().get_alert(alert_id)
@app.get("/flows/{flow_id}")
def flow(flow_id: str): return _w().get_flow(flow_id)
@app.get("/assets/{key}")
def asset(key: str): return _w().get_asset(key)
@app.get("/cves")
def cves(product: str, version: str = ""): return _w().lookup_cves(product, version)
@app.get("/logs")
def logs(host: str, source: str, pattern: str | None = None, limit: int = Query(60, le=200)): return _w().search_logs(host, source, pattern, limit)
@app.get("/search/playbooks")
def playbooks(q: str, k: int = 3): return _w().search_playbooks(q, k)
@app.get("/allowlist/{ip}")
def allowlist(ip: str): return _w().check_allowlist(ip)
class BlockReq(BaseModel):
    ip: str
    reason: str
    incident_id: str | None = None
@app.post("/firewall/block")
def block(req: BlockReq): return _w().block_ip(req.ip, req.reason, req.incident_id)
class UnblockReq(BaseModel):
    ip: str
    reason: str
@app.post("/firewall/unblock")
def unblock(req: UnblockReq): return _w().unblock_ip(req.ip, req.reason)
@app.get("/firewall/rules")
def rules(): return _w().firewall_rules
@app.get("/firewall/verify/{ip}")
def verify(ip: str): return _w().verify_block(ip)
class HostReq(BaseModel):
    reason: str
@app.post("/hosts/{host}/isolate")
def isolate(host: str, req: HostReq): return _w().isolate_host(host, req.reason)
@app.post("/hosts/{host}/release")
def release(host: str, req: HostReq): return {"ok": True, "host": host, "isolated": False}
class WatchReq(BaseModel):
    ip: str
    reason: str
@app.post("/watchlist")
def watchlist(req: WatchReq): return _w().add_watchlist(req.ip, req.reason)
class EscalateReq(BaseModel):
    incident_id: str
    reason: str
    missing_evidence: list[str] = []
    summary: str | None = None
@app.post("/tickets")
def escalate(req: EscalateReq): return _w().escalate(req.incident_id, req.reason, req.missing_evidence, req.summary)
@app.get("/tickets")
def tickets(): return _w().tickets
class AssessmentReq(BaseModel):
    incident_id: str
    verdict: str
    confidence: float
    summary: str
    evidence_ids: list[str] = []
@app.post("/assessments")
def assessment(req: AssessmentReq): return _w().file_assessment(req.incident_id, req.verdict, req.confidence, req.summary, req.evidence_ids)
@app.get("/events")
def events(since_seq: int = 0): return [e for e in _w().events if e["seq"] > since_seq]
@app.post("/chaos/{kind}")
def chaos(kind: str, payload: dict[str, Any] | None = None):
    try:
        return _w().chaos(kind, payload or {})
    except NotFound as e:
        raise HTTPException(404, str(e))
class ManualAlert(BaseModel):
    signature: str
    src_ip: str
    dest_port: int = 0
    severity: int = 2
    category: str = "Misc activity"
    note: str = ""
@app.post("/live/alert")
def manual_alert(req: ManualAlert): return _w().add_manual_alert(req.model_dump())
@app.post("/live/rescan")
def rescan(): return _w().scan()

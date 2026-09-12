"""Tool registry + HTTP client for the sandbox.

Two audiences:
- The planner sees `PLANNER_TOOLS`: read-only evidence tools plus `conclude_investigation`.
  State-changing actions are *not* callable by the planner directly; it proposes them in
  its conclusion and the action policy (rules.py) decides. That keeps the safety gates
  outside the LLM.
- The controller/verifier use `SandboxClient` for everything, including actions.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from .config import settings


class ToolError(Exception):
    def __init__(self, status: int, message: str, transient: bool):
        super().__init__(message)
        self.status = status
        self.message = message
        self.transient = transient


# ------------------------------------------------------------------ declarations (Gemini function-calling schema)
def _fn(name: str, description: str, props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"name": name, "description": description,
            "parameters": {"type": "OBJECT", "properties": props, "required": required}}


S = lambda d: {"type": "STRING", "description": d}  # noqa: E731

PLANNER_TOOLS: list[dict[str, Any]] = [
    _fn("get_alert", "Fetch the full NIDS (Suricata EVE) alert record by id.", {"alert_id": S("alert id, e.g. alt-2001")}, ["alert_id"]),
    _fn("get_flow", "Packet/flow metadata for the alert's flow_id: bytes, HTTP request line, response status, user-agent, payload snippet.",
        {"flow_id": S("flow id from the alert")}, ["flow_id"]),
    _fn("get_asset", "Asset inventory record for a host: services + versions, criticality, owner, security controls. Returns 404 if the host is not in inventory.",
        {"key": S("IP address or hostname")}, ["key"]),
    _fn("lookup_cves", "Check the advisory KB for CVEs affecting a product version. Returns whether the version is affected and the success indicators to look for in logs.",
        {"product": S("product name exactly as in the asset record, e.g. log4j-core"), "version": S("version string")}, ["product", "version"]),
    _fn("search_logs", "Regex search one log source on one host. Sources: web, app, auth, process, outbound, db. Returns matching lines (head+tail if many).",
        {"host": S("hostname or IP"), "source": S("one of: web, app, auth, process, outbound, db"), "pattern": S("case-insensitive regex; omit for all lines")}, ["host", "source"]),
    _fn("search_playbooks", "Retrieve response playbooks and advisory notes relevant to a query (signature, technique, situation). Use it to decide which evidence to collect.",
        {"query": S("free text, e.g. 'log4j jndi exploit' or 'host not in inventory'")}, ["query"]),
    _fn("check_allowlist", "Is this source IP allow-listed, watch-listed, or already blocked?", {"ip": S("IPv4 address")}, ["ip"]),
    _fn("record_evidence", "Record a finding you consider decisive that the automatic tagger may have missed. Category must be one of: post_exploitation, attack_blocked, vulnerable, not_vulnerable, context.",
        {"category": S("evidence category"), "excerpt": S("the exact log line or fact"), "meaning": S("why it matters")}, ["category", "excerpt", "meaning"]),
    _fn("conclude_investigation",
        "Call when the evidence is sufficient OR when it cannot be obtained. Give the verdict, confidence 0-1, a 2-3 sentence evidence-backed summary, "
        "the evidence ids relied on, what evidence is missing (if any), and the proposed response action.",
        {
            "verdict": {"type": "STRING", "enum": ["SUCCEEDED", "IN_PROGRESS", "FAILED", "INCONCLUSIVE"], "description": "attack outcome"},
            "confidence": {"type": "NUMBER", "description": "0.0-1.0"},
            "summary": S("evidence-backed assessment, cite evidence ids like E3"),
            "evidence_ids": {"type": "ARRAY", "items": {"type": "STRING"}, "description": "evidence ids relied on"},
            "missing_evidence": {"type": "ARRAY", "items": {"type": "STRING"}, "description": "what would resolve the case if INCONCLUSIVE"},
            "proposed_action": {"type": "STRING", "enum": ["block_ip", "block_ip_and_isolate_host", "watchlist", "escalate", "none"], "description": "response you propose"},
            "action_target": S("IP to block or host to isolate"),
            "escalation_note": S("for the ticket: what a human must do next (e.g. reset credentials for account X)"),
        },
        ["verdict", "confidence", "summary", "proposed_action"]),
]

PLANNER_TOOL_NAMES = {t["name"] for t in PLANNER_TOOLS}
LOCAL_TOOLS = {"record_evidence", "conclude_investigation"}


# ------------------------------------------------------------------ client
class SandboxClient:
    """Thin HTTP client. `base_url` empty -> talk to the sandbox app in-process over ASGI
    (still HTTP semantics, no socket), which keeps tests and the CLI self-contained."""

    def __init__(self, base_url: str | None = None, retries: int | None = None, backoff_s: float | None = None):
        self.retries = retries if retries is not None else settings.tool_retries
        self.backoff_s = backoff_s if backoff_s is not None else settings.tool_backoff_s
        base_url = base_url if base_url is not None else settings.sandbox_url
        if base_url:
            self._c = httpx.Client(base_url=base_url, timeout=20.0)
        else:
            from fastapi.testclient import TestClient
            from sandbox.app import app as sandbox_app  # local import: optional dependency direction
            self._c = TestClient(sandbox_app, base_url="http://sandbox.local", raise_server_exceptions=False)
            # The lifespan hook only runs inside a context manager; load the default scenario explicitly.
            self._c.post("/scenario/load", json={"scenario": "s2"})

    # -- raw request with retry on transient failures
    def _req(self, method: str, path: str, *, params: dict | None = None, json: dict | None = None, retry: bool = True) -> Any:
        attempts = self.retries if retry else 1
        last: ToolError | None = None
        for i in range(attempts):
            try:
                r = self._c.request(method, path, params=params, json=json)
            except httpx.HTTPError as e:
                last = ToolError(0, f"connection error: {e}", transient=True)
            else:
                if r.status_code < 400:
                    return r.json()
                body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"error": r.text}
                msg = body.get("error") or body.get("detail") or r.text
                transient = r.status_code in (429, 500, 502, 503, 504)
                last = ToolError(r.status_code, str(msg), transient=transient)
                if not transient:
                    raise last
            if i < attempts - 1:
                time.sleep(self.backoff_s * (2 ** i))
        assert last is not None
        raise last

    # -- evidence tools (used by the planner via execute())
    def get_alert(self, alert_id: str) -> Any: return self._req("GET", f"/alerts/{alert_id}")
    def list_alerts(self, since_seq: int = 0) -> Any: return self._req("GET", "/alerts", params={"since_seq": since_seq})
    def get_flow(self, flow_id: Any) -> Any: return self._req("GET", f"/flows/{flow_id}")
    def get_asset(self, key: str) -> Any: return self._req("GET", f"/assets/{key}")
    def lookup_cves(self, product: str, version: str) -> Any: return self._req("GET", "/cves", params={"product": product, "version": version})
    def search_logs(self, host: str, source: str, pattern: str | None = None) -> Any:
        params = {"host": host, "source": source}
        if pattern:
            params["pattern"] = pattern
        return self._req("GET", "/logs", params=params)
    def search_playbooks(self, query: str) -> Any: return self._req("GET", "/search/playbooks", params={"q": query})
    def check_allowlist(self, ip: str) -> Any: return self._req("GET", f"/allowlist/{ip}")

    # -- actions (controller / verifier only)
    def block_ip(self, ip: str, reason: str, incident_id: str) -> Any:
        return self._req("POST", "/firewall/block", json={"ip": ip, "reason": reason, "incident_id": incident_id})
    def unblock_ip(self, ip: str, reason: str) -> Any: return self._req("POST", "/firewall/unblock", json={"ip": ip, "reason": reason})
    def verify_block(self, ip: str) -> Any: return self._req("GET", f"/firewall/verify/{ip}")
    def list_rules(self) -> Any: return self._req("GET", "/firewall/rules")
    def isolate_host(self, host: str, reason: str) -> Any: return self._req("POST", f"/hosts/{host}/isolate", json={"reason": reason})
    def add_watchlist(self, ip: str, reason: str) -> Any: return self._req("POST", "/watchlist", json={"ip": ip, "reason": reason})
    def escalate(self, incident_id: str, reason: str, missing: list[str], summary: str | None) -> Any:
        return self._req("POST", "/tickets", json={"incident_id": incident_id, "reason": reason, "missing_evidence": missing, "summary": summary})
    def file_assessment(self, incident_id: str, verdict: str, confidence: float, summary: str, evidence_ids: list[str]) -> Any:
        return self._req("POST", "/assessments", json={"incident_id": incident_id, "verdict": verdict, "confidence": confidence,
                                                       "summary": summary, "evidence_ids": evidence_ids})
    def events(self, since_seq: int = 0) -> Any: return self._req("GET", "/events", params={"since_seq": since_seq}, retry=False)

    # -- admin
    def load_scenario(self, scenario: str) -> Any: return self._req("POST", "/scenario/load", json={"scenario": scenario})
    def scenarios(self) -> Any: return self._req("GET", "/scenarios")
    def truth(self) -> Any: return self._req("GET", "/truth")
    def chaos(self, kind: str, payload: dict | None = None) -> Any: return self._req("POST", f"/chaos/{kind}", json=payload or {})

    # -- dispatch for planner tool calls
    def execute(self, name: str, args: dict[str, Any]) -> Any:
        fn = getattr(self, name, None)
        if name not in PLANNER_TOOL_NAMES or name in LOCAL_TOOLS or fn is None:
            raise ToolError(400, f"tool {name} is not callable by the planner", transient=False)
        return fn(**args)

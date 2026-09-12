"""Agent service + UI.

  uvicorn web.app:app --port 8000        (sandbox in-process unless SANDBOX_URL is set)

The controller runs in a worker thread per incident; the UI follows it over SSE.
"""
from __future__ import annotations

import asyncio
import json
import queue
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from agent.chat import HELP, answer_question, parse_command
from agent.config import settings
from agent.controller import Controller
from agent.llm import make_llm
from agent.state import Incident, IncidentStore, TraceEvent
from agent.tools import SandboxClient, ToolError

STATIC = Path(__file__).parent / "static"


class Session:
    """Everything the UI needs to drive one sandbox + one agent."""

    def __init__(self) -> None:
        self.client = SandboxClient()
        self.store = IncidentStore(settings.incident_db)
        self.provider = settings.llm_provider if (settings.llm_provider != "gemini" or settings.gemini_api_key) else "mock"
        self.incidents: dict[str, Incident] = {}
        self.controllers: dict[str, Controller] = {}
        self.subscribers: dict[str, list[queue.Queue]] = {}
        self.running: set[str] = set()
        self.chat: dict[str, list[dict[str, str]]] = {}
        self.lock = threading.Lock()

    # -- trace fan-out
    def _publish(self, inc: Incident, payload: dict[str, Any]) -> None:
        for q in list(self.subscribers.get(inc.id, [])):
            q.put(payload)

    def on_trace(self, inc: Incident, ev: TraceEvent) -> None:
        self._publish(inc, {"type": "trace", "event": asdict(ev), "incident": self.summary(inc)})

    def summary(self, inc: Incident) -> dict[str, Any]:
        return {
            "id": inc.id, "scenario": inc.scenario, "alert_id": inc.alert_id, "current_alert_id": inc.current_alert_id,
            "status": inc.status, "steps": inc.steps, "budget": inc.budget, "verdict": inc.verdict,
            "blocked_ips": inc.blocked_ips, "pending_approval": inc.pending_approval, "logs_degraded": inc.logs_degraded,
            "evidence": [asdict(e) for e in inc.evidence], "actions": inc.actions, "escalations": inc.escalations,
            "followup_alerts": inc.followup_alerts, "overrides": inc.overrides, "running": inc.id in self.running,
        }

    def controller(self, inc: Incident) -> Controller:
        if inc.id not in self.controllers:
            self.controllers[inc.id] = Controller(self.client, make_llm(self.provider), store=self.store,
                                                  approver=lambda i, d: None, on_trace=self.on_trace)
        return self.controllers[inc.id]

    def _run(self, inc: Incident, fn) -> None:
        with self.lock:
            if inc.id in self.running:
                return
            self.running.add(inc.id)

        def work() -> None:
            try:
                fn()
            except Exception as e:  # surface crashes in the trace instead of dying silently
                inc.add_trace("error", f"agent crashed: {type(e).__name__}: {e}")
                self._publish(inc, {"type": "trace", "event": asdict(inc.trace[-1]), "incident": self.summary(inc)})
            finally:
                self.running.discard(inc.id)
                self._publish(inc, {"type": "done", "incident": self.summary(inc)})

        threading.Thread(target=work, daemon=True).start()

    def investigate(self, alert_id: str) -> Incident:
        scenario = self.client._req("GET", "/scenario").get("id", "?")
        inc = Incident.new(scenario, alert_id, settings.step_budget)
        self.incidents[inc.id] = inc
        self.chat[inc.id] = [{"who": "agent", "text": f"Investigating {alert_id}. {HELP}"}]
        ctl = self.controller(inc)
        inc.add_trace("goal", inc.goal, alert_id=alert_id, scenario=scenario, budget=inc.budget)
        self._run(inc, lambda: ctl.investigate(inc))
        return inc

    def poke(self, inc: Incident) -> None:
        """Wake the loop so it drains environment events (used after chaos / overrides on idle incidents)."""
        if inc.id in self.running or inc.status == "awaiting_approval":
            return
        ctl = self.controller(inc)
        self._run(inc, lambda: ctl.investigate(inc))

    def approve(self, inc: Incident, ok: bool) -> None:
        ctl = self.controller(inc)
        self._run(inc, lambda: ctl.approve(inc, ok, who="analyst (UI)"))


session = Session()
app = FastAPI(title="SOCrates", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.exception_handler(ToolError)
async def _toolerr(_, exc: ToolError) -> JSONResponse:
    return JSONResponse(status_code=exc.status or 502, content={"error": exc.message})


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


def _meta() -> dict[str, Any]:
    key = settings.gemini_api_key
    return {"planner": session.provider, "model": settings.gemini_model if session.provider == "gemini" else "scripted",
            "gemini_model": settings.gemini_model, "has_key": bool(key), "key_hint": f"...{key[-4:]}" if key else "",
            "sandbox": settings.sandbox_url or "in-process", "budget": settings.step_budget}


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return _meta()


class KeyReq(BaseModel):
    api_key: str
    model: str | None = None


@app.post("/api/settings/key")
def set_key(req: KeyReq) -> dict[str, Any]:
    """Set the Gemini key for this server process only (memory, never written to disk or logs)."""
    key = req.api_key.strip()
    model = (req.model or settings.gemini_model).strip()
    if not key:
        raise HTTPException(400, "empty key")
    try:
        r = httpx.get(f"https://generativelanguage.googleapis.com/v1beta/models/{model}",
                      headers={"x-goog-api-key": key}, timeout=15.0)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"could not reach Gemini: {e.__class__.__name__}")
    if r.status_code == 200:
        pass
    elif r.status_code in (400, 401, 403):
        raise HTTPException(401, "Gemini rejected the key")
    elif r.status_code == 404:
        raise HTTPException(404, f"key accepted but model '{model}' not found")
    else:
        raise HTTPException(502, f"Gemini returned HTTP {r.status_code}")
    settings.gemini_api_key = key
    settings.gemini_model = model
    session.provider = "gemini"
    session.controllers.clear()          # new incidents get a Gemini planner
    return _meta()


@app.delete("/api/settings/key")
def clear_key() -> dict[str, Any]:
    settings.gemini_api_key = ""
    session.provider = "mock"
    session.controllers.clear()
    return _meta()


@app.get("/api/scenarios")
def scenarios() -> list[dict[str, str]]:
    return session.client.scenarios()


class LoadReq(BaseModel):
    scenario: str


@app.post("/api/scenario/load")
def load(req: LoadReq) -> dict[str, Any]:
    if session.running:
        raise HTTPException(409, "an investigation is running; wait for it to finish")
    return session.client.load_scenario(req.scenario)


@app.get("/api/env")
def env() -> dict[str, Any]:
    c = session.client
    return {"scenario": c._req("GET", "/scenario"), "alerts": c.list_alerts(), "truth": c.truth(),
            "events": c.events(0), "rules": c.list_rules()}


class InvestigateReq(BaseModel):
    alert_id: str


@app.post("/api/investigate")
def investigate(req: InvestigateReq) -> dict[str, Any]:
    if session.running:
        raise HTTPException(409, "an investigation is already running")
    inc = session.investigate(req.alert_id)
    return {"incident_id": inc.id}


@app.get("/api/incidents")
def incidents() -> list[dict[str, Any]]:
    return [session.summary(i) for i in session.incidents.values()]


def _get(incident_id: str) -> Incident:
    inc = session.incidents.get(incident_id)
    if not inc:
        raise HTTPException(404, "unknown incident")
    return inc


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str) -> dict[str, Any]:
    inc = _get(incident_id)
    return {**session.summary(inc), "trace": [asdict(t) for t in inc.trace], "chat": session.chat.get(inc.id, [])}


@app.get("/api/incidents/{incident_id}/events")
async def events(incident_id: str) -> EventSourceResponse:
    inc = _get(incident_id)
    q: queue.Queue = queue.Queue()
    session.subscribers.setdefault(inc.id, []).append(q)

    async def gen():
        try:
            yield {"event": "snapshot", "data": json.dumps({"incident": session.summary(inc), "trace": [asdict(t) for t in inc.trace]})}
            while True:
                try:
                    item = await asyncio.to_thread(q.get, True, 15.0)
                except queue.Empty:
                    yield {"event": "ping", "data": "{}"}
                    continue
                yield {"event": item["type"], "data": json.dumps(item)}
        finally:
            session.subscribers[inc.id].remove(q)

    return EventSourceResponse(gen())


class ApproveReq(BaseModel):
    approved: bool


@app.post("/api/incidents/{incident_id}/approve")
def approve(incident_id: str, req: ApproveReq) -> dict[str, Any]:
    inc = _get(incident_id)
    if inc.status != "awaiting_approval":
        raise HTTPException(409, "nothing to approve")
    session.approve(inc, req.approved)
    return {"ok": True}


class ChatReq(BaseModel):
    message: str


@app.post("/api/incidents/{incident_id}/chat")
def chat(incident_id: str, req: ChatReq) -> dict[str, Any]:
    inc = _get(incident_id)
    log = session.chat.setdefault(inc.id, [])
    log.append({"who": "analyst", "text": req.message})
    cmd = parse_command(req.message)
    if cmd is None:
        reply = answer_question(inc, req.message)
    else:
        kind, args = cmd
        if kind == "help":
            reply = HELP
        elif kind == "override":
            ip = args["ip"] or (inc.alert or {}).get("src_ip")
            session.client.chaos("override", {"ip": ip, "note": args["note"], "analyst": "analyst (chat)"})
            session.poke(inc)
            reply = f"Recorded: {ip} is authorised. Unblocking if blocked, adding the exception, revising the assessment."
        elif kind == "reopen":
            inc.observe(f"Analyst instruction: {args['instruction']}", type="analyst_instruction")
            inc.add_trace("human", f"Analyst instruction: {args['instruction']}")
            session._publish(inc, {"type": "trace", "event": asdict(inc.trace[-1]), "incident": session.summary(inc)})
            inc.status = "open"
            session.poke(inc)
            reply = "Reopened with your instruction; the planner will act on it."
        elif kind in ("approve", "deny"):
            if inc.status != "awaiting_approval":
                reply = "Nothing is waiting for approval."
            else:
                session.approve(inc, kind == "approve")
                reply = f"{'Approved' if kind == 'approve' else 'Denied'}."
        elif kind == "chaos":
            res = session.client.chaos(args["kind"], {})
            session.poke(inc)
            reply = f"Injected {args['kind']}: {res}"
        else:
            reply = f"Unknown command /{args.get('cmd')}. {HELP}"
    log.append({"who": "agent", "text": reply})
    return {"reply": reply}


class ChaosReq(BaseModel):
    payload: dict[str, Any] = {}
    incident_id: str | None = None


@app.post("/api/chaos/{kind}")
def chaos(kind: str, req: ChaosReq) -> dict[str, Any]:
    res = session.client.chaos(kind, req.payload)
    inc = session.incidents.get(req.incident_id or "")
    if inc is None and session.incidents:
        inc = list(session.incidents.values())[-1]
    if inc is not None:
        inc.add_trace("human", f"Chaos panel: {kind} injected", chaos=kind, result=res)
        session._publish(inc, {"type": "trace", "event": asdict(inc.trace[-1]), "incident": session.summary(inc)})
        session.poke(inc)
    return res

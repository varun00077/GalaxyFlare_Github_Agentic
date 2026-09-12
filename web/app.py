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
from agent.llm import PROVIDERS, has_key, make_llm
from agent.llm_openai import GROQ_BASE, list_models, resolve_model
from agent.state import Incident, IncidentStore, TraceEvent
from agent.tools import SandboxClient, ToolError

STATIC = Path(__file__).parent / "static"


class Session:
    """Everything the UI needs to drive one sandbox + one agent."""

    def __init__(self) -> None:
        self.environment = settings.environment
        self.client = SandboxClient(environment=self.environment)
        self.store = IncidentStore(settings.incident_db)
        self.provider = settings.llm_provider if has_key(settings.llm_provider) else "mock"
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


def _model_for(provider: str) -> str:
    if provider == "gemini":
        return settings.gemini_model
    if provider == "groq":
        return resolve_model(GROQ_BASE, settings.groq_api_key, settings.groq_model) if settings.groq_api_key else settings.groq_model
    return "scripted"


def _meta() -> dict[str, Any]:
    keys = {"gemini": settings.gemini_api_key, "groq": settings.groq_api_key}
    return {"planner": session.provider, "model": _model_for(session.provider), "environment": session.environment,
            "providers": {p: {"has_key": bool(keys[p]), "key_hint": f"...{keys[p][-4:]}" if keys[p] else "",
                              "model": _model_for(p) if keys[p] else ""} for p in ("gemini", "groq")},
            "sandbox": settings.sandbox_url or "in-process", "budget": settings.step_budget}


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return _meta()


class KeyReq(BaseModel):
    api_key: str
    model: str | None = None
    remember: bool = False
    provider: str = "gemini"


def _write_env(provider: str, key: str, model: str) -> None:
    """Persist to .env (gitignored) when the analyst asks for it explicitly."""
    env = Path(".env")
    lines = env.read_text(encoding="utf-8").splitlines() if env.exists() else []
    out, seen = [], set()
    pfx = provider.upper()
    values = {f"{pfx}_API_KEY": key, f"{pfx}_MODEL": model, "LLM_PROVIDER": provider}
    for ln in lines:
        k = ln.split("=", 1)[0].strip()
        if k in values:
            seen.add(k)
            out.append(f"{k}={values[k]}")
        else:
            out.append(ln)
    for k, v in values.items():
        if k not in seen:
            out.append(f"{k}={v}")
    env.write_text("\n".join(out) + "\n", encoding="utf-8")


GEMINI = "https://generativelanguage.googleapis.com/v1beta"


def _probe(key: str, model: str, provider: str = "gemini") -> None:
    """One-token generation: proves the key AND the model actually work together."""
    try:
        if provider == "groq":
            r = httpx.post(f"{GROQ_BASE}/chat/completions", headers={"Authorization": f"Bearer {key}"},
                           json={"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}, timeout=20.0)
        else:
            r = httpx.post(f"{GEMINI}/models/{model}:generateContent", headers={"x-goog-api-key": key},
                           json={"contents": [{"role": "user", "parts": [{"text": "ping"}]}], "generationConfig": {"maxOutputTokens": 1}},
                           timeout=20.0)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"could not reach {provider}: {e.__class__.__name__}")
    if r.status_code == 200:
        return
    try:
        msg = r.json()["error"]["message"]
    except Exception:
        msg = r.text[:200]
    if r.status_code in (401, 403):
        raise HTTPException(401, f"{provider} rejected the key: {msg}")
    if r.status_code in (400, 404):
        raise HTTPException(404, f"model '{model}' not usable with this key: {msg}")
    raise HTTPException(502, f"{provider} returned HTTP {r.status_code}: {msg}")


def _list_models(key: str) -> list[str]:
    try:
        r = httpx.get(f"{GEMINI}/models", headers={"x-goog-api-key": key}, params={"pageSize": 200}, timeout=15.0)
        r.raise_for_status()
    except httpx.HTTPError:
        return []
    out = []
    for m in r.json().get("models", []):
        if "generateContent" in m.get("supportedGenerationMethods", []):
            out.append(m["name"].removeprefix("models/"))
    return sorted(out)


@app.post("/api/settings/key")
def set_key(req: KeyReq) -> dict[str, Any]:
    """Set a planner key for this server process (memory; .env only when asked). Never logged."""
    provider = req.provider.lower()
    if provider not in ("gemini", "groq"):
        raise HTTPException(400, f"provider must be gemini or groq")
    key = req.api_key.strip()
    if not key:
        raise HTTPException(400, "empty key")
    if provider == "groq":
        model = resolve_model(GROQ_BASE, key, (req.model or "auto").strip())
    else:
        model = (req.model or settings.gemini_model).strip()
    _probe(key, model, provider)
    if provider == "groq":
        settings.groq_api_key, settings.groq_model = key, model
    else:
        settings.gemini_api_key, settings.gemini_model = key, model
    session.provider = provider
    session.controllers.clear()          # new incidents get the new planner
    if req.remember:
        _write_env(provider, key, model)
    return {**_meta(), "remembered": req.remember}


class ProviderReq(BaseModel):
    provider: str


@app.post("/api/settings/provider")
def set_provider(req: ProviderReq) -> dict[str, Any]:
    """Switch between planners whose keys are already loaded (or the scripted planner)."""
    p = req.provider.lower()
    if p not in PROVIDERS:
        raise HTTPException(400, f"provider must be one of {PROVIDERS}")
    if not has_key(p):
        raise HTTPException(400, f"no key loaded for {p}")
    session.provider = p
    session.controllers.clear()
    return _meta()


@app.get("/api/settings/models")
def models(provider: str = "gemini") -> dict[str, Any]:
    if provider == "groq":
        return {"models": list_models(GROQ_BASE, settings.groq_api_key) if settings.groq_api_key else []}
    if not settings.gemini_api_key:
        return {"models": []}
    return {"models": _list_models(settings.gemini_api_key)}


@app.delete("/api/settings/key")
def clear_key() -> dict[str, Any]:
    """Drop to the scripted planner (keys stay loaded so you can switch back)."""
    session.provider = "mock"
    session.controllers.clear()
    return _meta()


class EnvReq(BaseModel):
    environment: str


@app.post("/api/settings/environment")
def set_environment(req: EnvReq) -> dict[str, Any]:
    """Switch between the synthetic sandbox and the live host (in-process). Not while an investigation runs."""
    env = req.environment.lower()
    if env not in ("sandbox", "live"):
        raise HTTPException(400, "environment must be sandbox or live")
    if session.running:
        raise HTTPException(409, "an investigation is running; wait for it to finish")
    if env != session.environment:
        session.client = SandboxClient(environment=env)
        session.environment = env
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
        reply = answer_question(inc, req.message, session.provider)
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

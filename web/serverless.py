"""Stateless entry point for serverless hosts (Vercel).

No background threads, no database, no server-side sessions. Every request carries the whole
state (the incident + a snapshot of the sandbox) and streams the trace back as SSE. When the
agent needs an approval, or the request time budget runs out, the stream ends with a `state`
event; the browser sends that state back to /api/resume with the decision.

Local, stateful console (approvals without round-trips, live host mode): web/app.py.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.chat import HELP, answer_question, parse_command
from agent.config import settings
from agent.controller import Controller
from agent.llm import has_key, make_llm
from agent.state import Incident, TraceEvent
from agent.tools import SandboxClient, ToolError

STATIC = Path(__file__).resolve().parent / "static"
# Vercel Hobby allows up to 300 s per request with Fluid compute; leave headroom for the final flush.
REQUEST_BUDGET_S = float(os.getenv("REQUEST_BUDGET_S", "240"))

app = FastAPI(title="SOCrates (serverless)", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.exception_handler(ToolError)
async def _toolerr(_, exc: ToolError) -> JSONResponse:
    return JSONResponse(status_code=exc.status or 502, content={"error": exc.message})


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


# ------------------------------------------------------------------ planner per request
def _planner(req: Request):
    """Key/provider/model from headers (sent by the browser) or from the deployment's env vars."""
    provider = (req.headers.get("x-planner-provider") or settings.llm_provider).lower()
    key = req.headers.get("x-planner-key") or None
    model = req.headers.get("x-planner-model") or None
    if provider not in ("gemini", "groq", "mock"):
        provider = "mock"
    if provider != "mock" and not key and not has_key(provider):
        provider = "mock"
    return provider, make_llm(provider, api_key=key, model=model)


def _meta() -> dict[str, Any]:
    keys = {"gemini": settings.gemini_api_key, "groq": settings.groq_api_key}
    env_provider = settings.llm_provider if has_key(settings.llm_provider) else "mock"
    return {"mode": "serverless", "planner": env_provider, "model": "", "environment": "sandbox",
            "providers": {p: {"has_key": bool(keys[p]), "key_hint": f"...{keys[p][-4:]}" if keys[p] else "", "model": ""} for p in ("gemini", "groq")},
            "sandbox": "in-process", "budget": settings.step_budget, "request_budget_s": REQUEST_BUDGET_S}


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return _meta()


@app.get("/api/scenarios")
def scenarios() -> list[dict[str, str]]:
    return SandboxClient("").scenarios()


@app.post("/api/settings/validate")
def validate(req: Request) -> dict[str, Any]:
    """Probe the key/provider/model sent in headers with a one-token completion. Nothing is stored."""
    provider = (req.headers.get("x-planner-provider") or "groq").lower()
    key = req.headers.get("x-planner-key") or ""
    if provider not in ("gemini", "groq") or not key:
        raise HTTPException(400, "provider must be gemini or groq and a key is required")
    try:
        llm = make_llm(provider, api_key=key, model=req.headers.get("x-planner-model") or None)
        llm.complete("Reply with the single word: ok", "ping")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(401, f"{provider} rejected the key or model: {str(e)[:200]}")
    return {"ok": True, "provider": provider, "model": getattr(llm, "model", "")}


def _env_payload(client: SandboxClient, inc: Incident | None) -> dict[str, Any]:
    handled: dict[str, Any] = {}
    if inc is not None:
        for aid in [inc.alert_id, *inc.followup_alerts]:
            handled[aid] = {"incident": inc.id, "role": "follow-up" if aid != inc.alert_id else "primary",
                            "verdict": (inc.verdict or {}).get("verdict"), "status": inc.status}
    return {"scenario": client._req("GET", "/scenario"), "alerts": client.list_alerts(), "truth": client.truth(), "handled": handled}


@app.get("/api/env")
def env(scenario: str = "s2") -> dict[str, Any]:
    client = SandboxClient("")
    client.load_scenario(scenario)
    return _env_payload(client, None)


# ------------------------------------------------------------------ summaries (same shape the stateful console uses)
def _summary(inc: Incident, ctl: Controller | None, running: bool) -> dict[str, Any]:
    llm = getattr(ctl, "llm", None)
    return {
        "id": inc.id, "scenario": inc.scenario, "alert_id": inc.alert_id, "current_alert_id": inc.current_alert_id,
        "status": inc.status, "steps": inc.steps, "budget": inc.budget, "verdict": inc.verdict,
        "blocked_ips": inc.blocked_ips, "pending_approval": inc.pending_approval, "logs_degraded": inc.logs_degraded,
        "evidence": [asdict(e) for e in inc.evidence], "actions": inc.actions, "escalations": inc.escalations,
        "followup_alerts": inc.followup_alerts, "overrides": inc.overrides, "running": running,
        "llm_usage": dict(getattr(llm, "usage", {}) or {}), "llm_model": getattr(llm, "model", "") or (llm.name if llm else ""),
    }


# ------------------------------------------------------------------ streaming runner
def _stream(fn, client: SandboxClient, inc: Incident, ctl: Controller) -> StreamingResponse:
    """Run `fn()` (which drives the controller) in a worker and stream trace events as they happen."""
    q: queue.Queue = queue.Queue()

    def on_trace(i: Incident, ev: TraceEvent) -> None:
        q.put({"type": "trace", "event": asdict(ev), "incident": _summary(i, ctl, True)})
    ctl.on_trace = on_trace

    def work() -> None:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - surface in the trace instead of a broken stream
            inc.add_trace("error", f"agent crashed: {type(e).__name__}: {e}")
            q.put({"type": "trace", "event": asdict(inc.trace[-1]), "incident": _summary(inc, ctl, False)})
        finally:
            state = {"incident": json.loads(inc.to_json()), "world": client.snapshot(), "usage": dict(getattr(ctl.llm, "usage", {}) or {})}
            q.put({"type": "state", "incident": _summary(inc, ctl, False), "state": state, "env": _env_payload(client, inc)})
            q.put(None)

    threading.Thread(target=work, daemon=True).start()

    def gen() -> Iterator[str]:
        yield "event: open\ndata: {}\n\n"
        while True:
            try:
                item = q.get(timeout=10.0)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            if item is None:
                break
            yield f"event: {item['type']}\ndata: {json.dumps(item)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _restore(state: dict[str, Any] | None, scenario: str | None = None) -> tuple[SandboxClient, Incident | None]:
    client = SandboxClient("")
    if state and state.get("world"):
        client.restore(state["world"])
    elif scenario:
        client.load_scenario(scenario)
    inc = Incident.from_json(json.dumps(state["incident"])) if state and state.get("incident") else None
    return client, inc


def _controller(req: Request, client: SandboxClient, carried_usage: dict[str, Any] | None = None) -> Controller:
    _, llm = _planner(req)
    if carried_usage and getattr(llm, "usage", None) is not None:
        for k, v in carried_usage.items():
            if isinstance(v, int):
                llm.usage[k] = llm.usage.get(k, 0) + v
    return Controller(client, llm, approver=lambda i, d: None)   # approvals always pause and hand state back


class RunReq(BaseModel):
    scenario: str = "s2"
    alert_id: str | None = None
    state: dict[str, Any] | None = None       # continue with a sandbox that already changed (e.g. after chaos)


@app.post("/api/run")
def run(req: Request, body: RunReq) -> StreamingResponse:
    client, _ = _restore(body.state, body.scenario)
    alerts = client.list_alerts()
    if not alerts:
        raise HTTPException(404, "scenario has no alerts")
    alert_id = body.alert_id or alerts[0]["alert_id"]
    ctl = _controller(req, client)
    inc = Incident.new(client._req("GET", "/scenario")["id"], alert_id, settings.step_budget)
    deadline = time.monotonic() + REQUEST_BUDGET_S

    def go() -> None:
        inc.add_trace("goal", inc.goal, alert_id=alert_id, scenario=inc.scenario, budget=inc.budget)
        ctl.on_trace(inc, inc.trace[-1])
        ctl.investigate(inc, deadline=deadline)
    return _stream(go, client, inc, ctl)


class ResumeReq(BaseModel):
    state: dict[str, Any]
    approved: bool | None = None               # None = just continue (time-box pause, chaos, reopen)


@app.post("/api/resume")
def resume(req: Request, body: ResumeReq) -> StreamingResponse:
    client, inc = _restore(body.state)
    if inc is None:
        raise HTTPException(400, "state.incident missing")
    ctl = _controller(req, client, body.state.get("usage"))
    deadline = time.monotonic() + REQUEST_BUDGET_S

    def go() -> None:
        if body.approved is not None and inc.status == "awaiting_approval":
            ctl.approve(inc, body.approved, who="analyst (web)")
            if inc.status == "open":
                ctl.investigate(inc, deadline=deadline)
        elif inc.status != "awaiting_approval":
            if inc.status not in ("closed", "escalated"):
                inc.status = "open"
            ctl.investigate(inc, deadline=deadline)
    return _stream(go, client, inc, ctl)


class ChaosReq(BaseModel):
    state: dict[str, Any] | None = None
    scenario: str | None = None
    payload: dict[str, Any] = {}


@app.post("/api/chaos/{kind}")
def chaos(kind: str, req: Request, body: ChaosReq):
    client, inc = _restore(body.state, body.scenario)
    res = client.chaos(kind, body.payload)
    if inc is None:
        return {"result": res, "state": {"incident": None, "world": client.snapshot(), "usage": {}}, "env": _env_payload(client, None)}
    ctl = _controller(req, client, (body.state or {}).get("usage"))
    inc.add_trace("human", f"Chaos panel: {kind} injected", chaos=kind, result=res)
    deadline = time.monotonic() + REQUEST_BUDGET_S

    def go() -> None:
        ctl.on_trace(inc, inc.trace[-1])
        if inc.status != "awaiting_approval":
            ctl.investigate(inc, deadline=deadline)   # drains the event the chaos raised
    return _stream(go, client, inc, ctl)


class ChatReq(BaseModel):
    state: dict[str, Any]
    message: str


@app.post("/api/chat")
def chat(req: Request, body: ChatReq) -> dict[str, Any]:
    client, inc = _restore(body.state)
    if inc is None:
        raise HTTPException(400, "state.incident missing")
    provider, llm = _planner(req)
    cmd = parse_command(body.message)
    needs_run = False
    if cmd is None:
        if provider == "mock" or not hasattr(llm, "complete"):
            from agent.chat import _template_answer
            reply = _template_answer(inc, body.message)
        else:
            from agent.chat import CHAT_SYSTEM, _context
            try:
                reply = llm.complete(CHAT_SYSTEM, f"INCIDENT CONTEXT:\n{_context(inc)}\n\nANALYST: {body.message}")
            except Exception as e:  # noqa: BLE001
                from agent.chat import _template_answer
                reply = _template_answer(inc, body.message) + f"\n\n(LLM unavailable: {e})"
    else:
        kind, args = cmd
        if kind == "help":
            reply = HELP
        elif kind == "override":
            ip = args["ip"] or (inc.alert or {}).get("src_ip")
            client.chaos("override", {"ip": ip, "note": args["note"], "analyst": "analyst (chat)"})
            reply, needs_run = f"Recorded: {ip} is authorised. Continuing so the agent can unblock and revise.", True
        elif kind == "reopen":
            inc.observe(f"Analyst instruction: {args['instruction']}", type="analyst_instruction")
            inc.add_trace("human", f"Analyst instruction: {args['instruction']}")
            inc.status = "open"
            reply, needs_run = "Reopened with your instruction.", True
        elif kind in ("approve", "deny"):
            reply = "Use the Approve / Deny buttons." if inc.status == "awaiting_approval" else "Nothing is waiting for approval."
        elif kind == "chaos":
            client.chaos(args["kind"], {})
            reply, needs_run = f"Injected {args['kind']}.", True
        else:
            reply = f"Unknown command /{args.get('cmd')}. {HELP}"
    return {"reply": reply, "needs_run": needs_run,
            "state": {"incident": json.loads(inc.to_json()), "world": client.snapshot(), "usage": body.state.get("usage", {})}}

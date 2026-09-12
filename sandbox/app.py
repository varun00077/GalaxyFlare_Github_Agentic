"""HTTP surface of the sandbox. The agent only ever talks to this API.

Run standalone:  uvicorn sandbox.app:app --port 8001
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .world import NotFound, ToolFault, World, list_scenarios

world = World()


@asynccontextmanager
async def _lifespan(_: FastAPI):
    world.load(os.getenv("SCENARIO", "s2"))
    yield


app = FastAPI(title="SOCrates sandbox", version="0.1.0", lifespan=_lifespan,
              description="Synthetic SOC environment: alerts, flows, assets, CVE KB, logs, firewall, tickets.")


@app.exception_handler(ToolFault)
async def _fault(_, exc: ToolFault) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"error": exc.message, "fault": True})


@app.exception_handler(NotFound)
async def _notfound(_, exc: NotFound) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": str(exc)})


# ---------------------------------------------------------------- admin
@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "scenario": world.scenario_id}


@app.get("/scenarios")
def scenarios() -> list[dict[str, str]]:
    return list_scenarios()


class LoadReq(BaseModel):
    scenario: str


@app.post("/scenario/load")
def load(req: LoadReq) -> dict[str, Any]:
    return world.load(req.scenario)


@app.get("/scenario")
def scenario() -> dict[str, Any]:
    return world.meta


@app.get("/truth")
def truth() -> dict[str, Any]:
    """Ground truth + current environment state. For the eval harness and UI only; the agent never calls it."""
    return world.truth()


# ---------------------------------------------------------------- read tools
@app.get("/alerts")
def alerts(since_seq: int = 0) -> list[dict[str, Any]]:
    return world.list_alerts(since_seq)


@app.get("/alerts/{alert_id}")
def alert(alert_id: str) -> dict[str, Any]:
    return world.get_alert(alert_id)


@app.get("/flows/{flow_id}")
def flow(flow_id: str) -> dict[str, Any]:
    return world.get_flow(flow_id)


@app.get("/assets/{key}")
def asset(key: str) -> dict[str, Any]:
    return world.get_asset(key)


@app.get("/cves")
def cves(product: str, version: str) -> dict[str, Any]:
    return world.lookup_cves(product, version)


@app.get("/cves/{cve_id}")
def cve(cve_id: str) -> dict[str, Any]:
    return world.get_cve(cve_id)


@app.get("/logs")
def logs(host: str, source: str, pattern: str | None = None, limit: int = Query(60, le=200)) -> dict[str, Any]:
    return world.search_logs(host, source, pattern, limit)


@app.get("/search/playbooks")
def playbooks(q: str, k: int = 3) -> list[dict[str, Any]]:
    return world.search_playbooks(q, k)


@app.get("/allowlist/{ip}")
def allowlist(ip: str) -> dict[str, Any]:
    return world.check_allowlist(ip)


# ---------------------------------------------------------------- state-changing tools
class BlockReq(BaseModel):
    ip: str
    reason: str
    incident_id: str | None = None


@app.post("/firewall/block")
def block(req: BlockReq) -> dict[str, Any]:
    return world.block_ip(req.ip, req.reason, req.incident_id)


class UnblockReq(BaseModel):
    ip: str
    reason: str


@app.post("/firewall/unblock")
def unblock(req: UnblockReq) -> dict[str, Any]:
    return world.unblock_ip(req.ip, req.reason)


@app.get("/firewall/rules")
def rules() -> list[dict[str, Any]]:
    return world.list_rules()


@app.get("/firewall/verify/{ip}")
def verify(ip: str) -> dict[str, Any]:
    return world.verify_block(ip)


class HostReq(BaseModel):
    reason: str


@app.post("/hosts/{host}/isolate")
def isolate(host: str, req: HostReq) -> dict[str, Any]:
    return world.isolate_host(host, req.reason)


@app.post("/hosts/{host}/release")
def release(host: str, req: HostReq) -> dict[str, Any]:
    return world.release_host(host, req.reason)


class WatchReq(BaseModel):
    ip: str
    reason: str


@app.post("/watchlist")
def watchlist(req: WatchReq) -> dict[str, Any]:
    return world.add_watchlist(req.ip, req.reason)


class EscalateReq(BaseModel):
    incident_id: str
    reason: str
    missing_evidence: list[str] = []
    summary: str | None = None


@app.post("/tickets")
def escalate(req: EscalateReq) -> dict[str, Any]:
    return world.escalate(req.incident_id, req.reason, req.missing_evidence, req.summary)


@app.get("/tickets")
def tickets() -> list[dict[str, Any]]:
    return world.tickets


class AssessmentReq(BaseModel):
    incident_id: str
    verdict: str
    confidence: float
    summary: str
    evidence_ids: list[str] = []


@app.post("/assessments")
def assessment(req: AssessmentReq) -> dict[str, Any]:
    return world.file_assessment(req.incident_id, req.verdict, req.confidence, req.summary, req.evidence_ids)


# ---------------------------------------------------------------- events / chaos
@app.get("/events")
def events(since_seq: int = 0) -> list[dict[str, Any]]:
    return world.get_events(since_seq)


@app.post("/chaos/{kind}")
def chaos(kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        return world.chaos(kind, payload)
    except NotFound as e:
        raise HTTPException(status_code=404, detail=str(e))

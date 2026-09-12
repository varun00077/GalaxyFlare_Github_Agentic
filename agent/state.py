"""Investigation state: the one object the whole loop reads and writes.

Persisted as JSON in SQLite after every step so an incident can be resumed after a
crash (PRD R3) and so the UI can replay the trace.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

VERDICTS = ("SUCCEEDED", "IN_PROGRESS", "FAILED", "INCONCLUSIVE", "OVERRIDDEN")
TRACE_KINDS = ("goal", "decision", "action", "result", "adaptation", "guardrail", "verification", "escalation", "final", "error", "human")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class Evidence:
    id: str
    category: str          # post_exploitation | attack_blocked | vulnerable | not_vulnerable | asset_unknown | context | brute_force
    source: str            # tool call that produced it, e.g. search_logs(app02/outbound)
    excerpt: str
    weight: float = 1.0
    step: int = 0
    meaning: str = ""


@dataclass
class HistoryItem:
    step: int
    kind: str              # call | observation
    name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    rationale: str = ""
    text: str = ""         # for observations
    signature: str = ""    # Gemini thought signature to echo back when replaying this call


@dataclass
class TraceEvent:
    seq: int
    step: int
    kind: str
    title: str
    detail: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=now_iso)


@dataclass
class Incident:
    id: str
    scenario: str
    alert_id: str
    goal: str
    status: str = "open"                      # open | awaiting_approval | closed | escalated
    steps: int = 0
    budget: int = 24
    evidence: list[Evidence] = field(default_factory=list)
    history: list[HistoryItem] = field(default_factory=list)
    trace: list[TraceEvent] = field(default_factory=list)
    alert: dict[str, Any] | None = None
    asset: dict[str, Any] | None = None
    asset_unknown: bool = False
    asset_vulnerable: bool | None = None      # True / False / None(unknown)
    cves_seen: dict[str, Any] = field(default_factory=dict)
    playbook: dict[str, Any] | None = None
    verdict: dict[str, Any] | None = None
    assessments: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    pending_approval: dict[str, Any] | None = None
    overrides: list[dict[str, Any]] = field(default_factory=list)
    escalations: list[dict[str, Any]] = field(default_factory=list)
    blocked_ips: list[str] = field(default_factory=list)
    followup_alerts: list[str] = field(default_factory=list)   # alerts surfaced by verification, still to investigate
    current_alert_id: str = ""
    logs_degraded: bool = False
    events_seen: int = 0
    replan_epoch: int = 0                     # bumps when knowledge changes; forces re-lookup
    epoch_step: int = 0                       # step at which the current epoch began (calls before it are stale)
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    # ------------------------------------------------------------ helpers
    @classmethod
    def new(cls, scenario: str, alert_id: str, budget: int) -> "Incident":
        return cls(id=f"inc-{uuid.uuid4().hex[:8]}", scenario=scenario, alert_id=alert_id, current_alert_id=alert_id,
                   budget=budget, goal=f"Establish whether the attack in {alert_id} succeeded, respond safely, verify the response.")

    def add_trace(self, kind: str, title: str, **detail: Any) -> TraceEvent:
        ev = TraceEvent(seq=len(self.trace) + 1, step=self.steps, kind=kind, title=title, detail=detail)
        self.trace.append(ev)
        self.updated_at = now_iso()
        return ev

    def add_evidence(self, category: str, source: str, excerpt: str, weight: float = 1.0, meaning: str = "") -> Evidence:
        # De-duplicate identical excerpts from repeated searches.
        for e in self.evidence:
            if e.excerpt == excerpt and e.category == category:
                return e
        ev = Evidence(id=f"E{len(self.evidence) + 1}", category=category, source=source, excerpt=excerpt[:400],
                      weight=weight, step=self.steps, meaning=meaning)
        self.evidence.append(ev)
        return ev

    def evidence_by(self, category: str) -> list[Evidence]:
        return [e for e in self.evidence if e.category == category]

    def has(self, category: str) -> bool:
        return any(e.category == category for e in self.evidence)

    def calls(self, name: str | None = None) -> list[HistoryItem]:
        return [h for h in self.history if h.kind == "call" and (name is None or h.name == name)]

    def observe(self, text: str, **detail: Any) -> None:
        self.history.append(HistoryItem(step=self.steps, kind="observation", text=text, args=detail))

    # ------------------------------------------------------------ persistence
    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "Incident":
        d = json.loads(s)
        d["evidence"] = [Evidence(**e) for e in d["evidence"]]
        d["history"] = [HistoryItem(**h) for h in d["history"]]
        d["trace"] = [TraceEvent(**t) for t in d["trace"]]
        return cls(**d)


class IncidentStore:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, scenario TEXT, status TEXT, updated_at TEXT, body TEXT)")
        self._conn.commit()

    def save(self, inc: Incident) -> None:
        self._conn.execute("INSERT OR REPLACE INTO incidents (id, scenario, status, updated_at, body) VALUES (?,?,?,?,?)",
                           (inc.id, inc.scenario, inc.status, inc.updated_at, inc.to_json()))
        self._conn.commit()

    def load(self, incident_id: str) -> Incident | None:
        row = self._conn.execute("SELECT body FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.from_json(row[0]) if row else None

    def list(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT id, scenario, status, updated_at FROM incidents ORDER BY updated_at DESC").fetchall()
        return [{"id": r[0], "scenario": r[1], "status": r[2], "updated_at": r[3]} for r in rows]

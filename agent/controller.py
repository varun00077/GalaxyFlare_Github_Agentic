"""The controller loop: observe -> plan -> act -> verify -> adapt.

One incident at a time. The planner (LLM) chooses evidence and proposes a response;
this module executes tool calls with retries, tags evidence, applies the guardrails,
performs and verifies actions, and reacts to environment events and analyst overrides.
Every step is written to the trace and persisted.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable

from .config import settings
from .evidence import summarize_result, tag_error, tag_result
from .llm import BaseLLM, Decision, rule_only_conclusion
from .rules import ActionDecision, decide_actions, gate_verdict
from .state import HistoryItem, Incident, IncidentStore
from .tools import SandboxClient, ToolError
from .verifier import verify_block, verify_unblock

Approver = Callable[[Incident, ActionDecision], bool | None]   # True/False, or None = defer (UI)
TraceHook = Callable[[Incident, Any], None]


class Controller:
    def __init__(self, client: SandboxClient, llm: BaseLLM, store: IncidentStore | None = None,
                 budget: int | None = None, approver: Approver | None = None, on_trace: TraceHook | None = None):
        self.client = client
        self.llm = llm
        self.store = store
        self.budget = budget or settings.step_budget
        self.approver = approver
        self.on_trace = on_trace
        self._text_strikes = 0
        self._llm_failures = 0

    # ------------------------------------------------------------------ entry points
    def run(self, scenario: str, alert_id: str) -> Incident:
        inc = Incident.new(scenario, alert_id, self.budget)
        self._trace(inc, "goal", inc.goal, alert_id=alert_id, scenario=scenario, budget=self.budget)
        return self.investigate(inc)

    def resume(self, inc: Incident) -> Incident:
        self._trace(inc, "adaptation", f"Resumed incident at step {inc.steps} ({inc.status})")
        if inc.status == "awaiting_approval":
            return inc
        inc.status = "open" if inc.status not in ("closed", "escalated") else inc.status
        return self.investigate(inc)

    def approve(self, inc: Incident, approved: bool, who: str = "analyst") -> Incident:
        """Resolve a pending approval (from the UI) and continue with any queued actions."""
        pend = inc.pending_approval
        if not pend:
            return inc
        inc.pending_approval = None
        inc.status = "open"
        d = ActionDecision(**pend["decision"])
        queue = [ActionDecision(**q) for q in pend.get("queue", [])]
        self._trace(inc, "human", f"{who} {'approved' if approved else 'denied'}: {d.action} {d.target or ''}", action=d.action, target=d.target, approved=approved)
        reopen = bool(pend.get("reopen"))      # a pivot/verification failure raised before the pause still applies
        if approved:
            reopen = self._perform(inc, d) or reopen
        else:
            self._escalate(inc, f"analyst denied {d.action} on {d.target}; human response required", [], (inc.verdict or {}).get("summary"))
        outcome = self._run_decisions(inc, queue)
        if outcome is None:          # deferred again
            self._save(inc)
            return inc
        reopen = reopen or outcome
        if reopen:
            inc.status = "open"
            self._save(inc)
            return self.investigate(inc)
        inc.status = "escalated" if (inc.verdict or {}).get("verdict") == "INCONCLUSIVE" else "closed"
        self._trace(inc, "final", self._final_title(inc), verdict=inc.verdict, blocked_ips=inc.blocked_ips)
        self._save(inc)
        return inc

    # ------------------------------------------------------------------ the loop
    def investigate(self, inc: Incident) -> Incident:
        while True:
            self._drain_events(inc)
            if inc.status in ("awaiting_approval", "closed", "escalated"):
                break
            if inc.steps >= inc.budget:
                self._trace(inc, "guardrail", f"Step budget ({inc.budget}) exhausted; escalating rather than guessing")
                self._escalate(inc, "step budget exhausted before a supported verdict", ["analyst review of the evidence ledger"], None)
                inc.verdict = inc.verdict or {"verdict": "INCONCLUSIVE", "confidence": 0.3, "summary": "budget exhausted"}
                inc.status = "escalated"
                self._trace(inc, "final", self._final_title(inc), verdict=inc.verdict)
                break

            inc.steps += 1
            d = self._decide(inc)
            if d.kind == "text":
                self._text_strikes += 1
                self._trace(inc, "decision", f"Planner replied without a tool call: {d.text[:200]}")
                inc.observe("Reply with a tool call, or call conclude_investigation.")
                if self._text_strikes >= 2:
                    self._trace(inc, "adaptation", "Planner failed to act twice; concluding from the evidence ledger (rule-only fallback)")
                    d = Decision("conclude", "conclude_investigation", rule_only_conclusion(inc), "rule-only fallback")
            if d.kind == "call":
                self._trace(inc, "decision", f"{d.name}({self._fmt(d.args)})", tool=d.name, args=d.args, rationale=d.text, model=d.model)
                if d.name == "record_evidence":
                    e = inc.add_evidence(str(d.args.get("category", "context")), "planner", str(d.args.get("excerpt", "")), 0.8, str(d.args.get("meaning", "")))
                    inc.history.append(HistoryItem(step=inc.steps, kind="call", name=d.name, args=d.args, result={"recorded": e.id}, rationale=d.text, signature=d.signature))
                    self._trace(inc, "result", f"Recorded {e.id} [{e.category}]", evidence=[e.id])
                else:
                    self._execute(inc, d.name, d.args, d.text, d.signature)
            elif d.kind == "conclude":
                self._conclude(inc, d.args, d.text)
            self._save(inc)
        self._save(inc)
        return inc

    def _decide(self, inc: Incident) -> Decision:
        self.llm.on_event = lambda msg: self._trace(inc, "adaptation", msg)
        try:
            d = self.llm.decide(inc)
            self._llm_failures = 0
            return d
        except Exception as e:  # network / API failure
            self._llm_failures += 1
            self._trace(inc, "error", f"Planner unavailable ({e})", attempt=self._llm_failures)
            if self._llm_failures >= 2:
                self._trace(inc, "adaptation", "Planner unavailable twice; concluding from the evidence ledger (rule-only fallback)")
                return Decision("conclude", "conclude_investigation", rule_only_conclusion(inc), "rule-only fallback")
            return Decision("text", text="planner error")

    # ------------------------------------------------------------------ tool execution
    def _execute(self, inc: Incident, name: str, args: dict[str, Any], rationale: str, signature: str = "") -> None:
        try:
            result = self.client.execute(name, args)
        except ToolError as e:
            inc.history.append(HistoryItem(step=inc.steps, kind="call", name=name, args=args, error=f"{e.status}: {e.message}", rationale=rationale, signature=signature))
            ids = tag_error(inc, name, args, e.status, e.message)
            if e.transient:
                self._trace(inc, "error", f"{name} failed after {self.client.retries} attempts: {e.message}", status=e.status)
                if name == "search_logs" and not inc.logs_degraded:
                    inc.logs_degraded = True
                    self._trace(inc, "adaptation", "Log service unavailable; continuing with flow metadata and other sources, confidence capped until logs return")
                else:
                    self._trace(inc, "adaptation", f"{name} unavailable; planner will use the next best evidence source")
            else:
                self._trace(inc, "result", f"{name}: {e.message}", status=e.status, evidence=ids)
            return
        inc.history.append(HistoryItem(step=inc.steps, kind="call", name=name, args=args, result=result, rationale=rationale, signature=signature))
        ids = tag_result(inc, name, args, result)
        if name == "search_logs" and inc.logs_degraded:
            inc.logs_degraded = False
            self._trace(inc, "adaptation", "Log service recovered; confidence cap lifted")
        self._trace(inc, "result", self._summ(name, result, ids), evidence=ids, tool=name)

    # ------------------------------------------------------------------ conclusion, gates, actions
    def _conclude(self, inc: Incident, draft: dict[str, Any], rationale: str) -> None:
        self._trace(inc, "decision", f"Planner concludes {draft.get('verdict')} (confidence {draft.get('confidence')}), proposes {draft.get('proposed_action')}",
                    draft=draft, rationale=rationale, model=getattr(self.llm, "model", self.llm.name))
        gate = gate_verdict(draft, inc)
        self._trace(inc, "guardrail", ("Verdict downgraded to " if gate.downgraded else "Verdict check passed: ") + gate.verdict, notes=gate.notes,
                    confidence=gate.confidence, blocked=gate.downgraded)
        inc.verdict = {"verdict": gate.verdict, "confidence": gate.confidence, "summary": draft.get("summary", ""),
                       "evidence_ids": draft.get("evidence_ids", []), "missing_evidence": draft.get("missing_evidence", []),
                       "proposed_action": draft.get("proposed_action"), "guardrail_notes": gate.notes}
        try:
            a = self.client.file_assessment(inc.id, gate.verdict, gate.confidence, inc.verdict["summary"], list(inc.verdict["evidence_ids"]))
            inc.assessments.append(a)
            self._trace(inc, "action", f"Filed assessment {a['assessment_id']}: {gate.verdict} ({gate.confidence})", assessment=a)
        except ToolError as e:
            self._trace(inc, "error", f"could not file assessment: {e.message}")

        target = draft.get("action_target") or (inc.alert or {}).get("src_ip")
        allowlisted = False
        if target:
            try:
                allowlisted = bool(self.client.check_allowlist(target).get("allowlisted"))
            except ToolError:
                pass
        decisions = decide_actions(gate, draft, inc, allowlisted)
        outcome = self._run_decisions(inc, decisions)
        if outcome is None:
            return                      # waiting for analyst approval; the UI resumes via approve()
        if outcome:
            inc.status = "open"         # verification re-entered the loop
            return
        inc.status = "escalated" if gate.verdict == "INCONCLUSIVE" else "closed"
        self._trace(inc, "final", self._final_title(inc), verdict=inc.verdict, blocked_ips=inc.blocked_ips)

    def _run_decisions(self, inc: Incident, decisions: list[ActionDecision]) -> bool | None:
        """Apply gated actions in order. Returns reopen flag, or None if deferred for approval."""
        reopen = False
        for i, dec in enumerate(decisions):
            if not dec.allowed:
                self._trace(inc, "guardrail", f"Action refused: {dec.action} {dec.target or ''} - {dec.reason}", blocked=True, action=dec.action)
                continue
            if dec.needs_approval:
                self._trace(inc, "guardrail", f"Approval required: {dec.action} {dec.target or ''} - {dec.reason}", action=dec.action, approval=True)
                ok = self.approver(inc, dec) if self.approver else None
                if ok is None:
                    inc.pending_approval = {"decision": asdict(dec), "queue": [asdict(x) for x in decisions[i + 1:]], "reopen": reopen}
                    inc.status = "awaiting_approval"
                    self._trace(inc, "human", f"Waiting for analyst approval: {dec.action} {dec.target or ''}", action=dec.action, target=dec.target)
                    return None
                self._trace(inc, "human", f"Analyst {'approved' if ok else 'denied'} {dec.action} {dec.target or ''}", action=dec.action, approved=ok)
                if not ok:
                    self._escalate(inc, f"analyst denied {dec.action} on {dec.target}", [], (inc.verdict or {}).get("summary"))
                    continue
            else:
                self._trace(inc, "guardrail", f"Action permitted: {dec.action} {dec.target or ''} - {dec.reason}", action=dec.action)
            reopen = self._perform(inc, dec) or reopen
        return reopen

    def _perform(self, inc: Incident, dec: ActionDecision) -> bool:
        """Execute a permitted action and verify it. Returns True if the loop must re-enter."""
        reopen = False
        if dec.action == "block_ip" and dec.target:
            try:
                res = self.client.block_ip(dec.target, f"{inc.id}: {inc.verdict['verdict']} - {inc.verdict['summary'][:120]}", inc.id)
            except ToolError as e:
                self._trace(inc, "error", f"block_ip {dec.target} failed: {e.message}", status=e.status)
                self._trace(inc, "adaptation", "Block could not be applied; escalating for manual containment")
                self._escalate(inc, f"firewall refused block of {dec.target}: {e.message}", [], inc.verdict["summary"])
                return False
            inc.actions.append({"type": "block_ip", "target": dec.target, "result": res, "step": inc.steps})
            if dec.target not in inc.blocked_ips:
                inc.blocked_ips.append(dec.target)
            self._trace(inc, "action", f"Blocked {dec.target} (rule {res['rule']['rule_id']}{', already present' if res.get('already_present') else ''})", rule=res["rule"])
            v = verify_block(self.client, inc, dec.target)
            self._trace(inc, "verification", v.summary, ok=v.ok, **v.detail)
            if not v.ok:
                inc.observe(f"Verification failed for block of {dec.target}: {v.summary}", type="verification_failed")
                self._trace(inc, "adaptation", "Block not effective; re-entering the investigation")
                reopen = True
            if v.followup_alert_ids:
                for a in v.followup_alerts:
                    inc.followup_meta[a["alert_id"]] = {"src_ip": a.get("src_ip"), "dest_ip": a.get("dest_ip")}
                for aid in v.followup_alert_ids:
                    if aid not in inc.followup_alerts:
                        inc.followup_alerts.append(aid)
                inc.current_alert_id = v.followup_alert_ids[0]
                inc.observe(f"After blocking {dec.target}, new alert(s) {', '.join(v.followup_alert_ids)} hit the same host from a different source. "
                            f"Likely attacker pivot. Correlate and respond.", type="new_alert", alert_ids=v.followup_alert_ids)
                self._trace(inc, "adaptation", f"Attacker pivot suspected: investigating {', '.join(v.followup_alert_ids)}", alert_ids=v.followup_alert_ids)
                reopen = True
        elif dec.action == "isolate_host" and dec.target:
            try:
                res = self.client.isolate_host(dec.target, f"{inc.id}: code execution confirmed")
                inc.actions.append({"type": "isolate_host", "target": dec.target, "result": res, "step": inc.steps})
                self._trace(inc, "action", f"Isolated host {dec.target}", result=res)
                a = self.client.get_asset(dec.target)
                self._trace(inc, "verification", f"{dec.target} isolated={a.get('isolated')}", ok=bool(a.get("isolated")))
            except ToolError as e:
                self._trace(inc, "error", f"isolate_host {dec.target} failed: {e.message}")
        elif dec.action == "watchlist" and dec.target:
            try:
                self.client.add_watchlist(dec.target, f"{inc.id}: failed attempt - {inc.verdict['summary'][:100]}")
                inc.actions.append({"type": "watchlist", "target": dec.target, "step": inc.steps})
                self._trace(inc, "action", f"Added {dec.target} to the watch-list")
            except ToolError as e:
                self._trace(inc, "error", f"watchlist failed: {e.message}")
        elif dec.action == "escalate":
            missing = list((inc.verdict or {}).get("missing_evidence", []))
            self._escalate(inc, dec.reason, missing, (inc.verdict or {}).get("summary"))
        return reopen

    def _escalate(self, inc: Incident, reason: str, missing: list[str], summary: str | None) -> None:
        try:
            t = self.client.escalate(inc.id, reason, missing, summary)
            inc.escalations.append(t)
            self._trace(inc, "escalation", f"Ticket {t['ticket_id']}: {reason}", missing_evidence=missing, ticket=t)
        except ToolError as e:
            self._trace(inc, "error", f"escalation failed: {e.message}")

    # ------------------------------------------------------------------ environment events
    def _drain_events(self, inc: Incident) -> None:
        try:
            events = self.client.events(inc.events_seen)
        except ToolError:
            return
        for ev in events:
            inc.events_seen = max(inc.events_seen, int(ev.get("seq", 0)))
            t = ev.get("type")
            if t == "new_alert":
                aid = ev.get("alert_id")
                handled = {inc.alert_id, *inc.followup_alerts, *(h.args.get("alert_id") for h in inc.calls("get_alert"))}
                if not aid or aid in handled:
                    continue
                inc.followup_alerts.append(aid)
                inc.current_alert_id = aid
                try:
                    rec = self.client.get_alert(aid)
                    inc.followup_meta[aid] = {"src_ip": rec.get("src_ip"), "dest_ip": rec.get("dest_ip")}
                except ToolError:
                    pass
                inc.observe(ev.get("note", f"New alert {aid}"), type="new_alert", alert_ids=[aid])
                self._trace(inc, "adaptation", f"Environment event: {ev.get('note')}", event=ev)
                inc.status = "open"
            elif t == "analyst_override":
                self._handle_override(inc, ev)
            elif t == "kb_update":
                self._trace(inc, "adaptation", f"Environment event: {ev.get('note')}", event=ev)
                inc.replan_epoch += 1
                inc.epoch_step = inc.steps
                inc.asset_vulnerable = None
                inc.cves_seen = {}
                inc.observe(f"{ev.get('note')} Re-check vulnerability for {ev.get('product')} and re-hunt the success indicators before standing by the previous verdict.",
                            type="kb_update", cve=ev.get("cve"))
                if inc.status in ("closed", "escalated"):
                    self._trace(inc, "adaptation", f"Reopening {inc.id}: previous verdict {inc.verdict.get('verdict') if inc.verdict else None} relied on revised knowledge")
                inc.status = "open"
            else:
                inc.observe(ev.get("note", str(ev)), type=t or "event")
                self._trace(inc, "adaptation", f"Environment event: {ev.get('note')}", event=ev)

    def _handle_override(self, inc: Incident, ev: dict[str, Any]) -> None:
        ip = ev.get("ip")
        inc.overrides.append(ev)
        self._trace(inc, "human", f"Analyst override from {ev.get('analyst', 'analyst')}: {ev.get('note')}", event=ev)
        if ip in inc.blocked_ips:
            try:
                self.client.unblock_ip(ip, f"{inc.id}: analyst override - {ev.get('note', '')[:120]}")
                inc.blocked_ips.remove(ip)
                inc.actions.append({"type": "unblock_ip", "target": ip, "step": inc.steps})
                self._trace(inc, "action", f"Unblocked {ip} per analyst override")
                v = verify_unblock(self.client, ip)
                self._trace(inc, "verification", v.summary, ok=v.ok)
            except ToolError as e:
                self._trace(inc, "error", f"unblock failed: {e.message}")
            for act in inc.actions:
                if act["type"] == "isolate_host":
                    try:
                        self.client._req("POST", f"/hosts/{act['target']}/release", json={"reason": f"{inc.id}: analyst override"})
                        self._trace(inc, "action", f"Released host {act['target']} per analyst override")
                    except ToolError as e:
                        self._trace(inc, "error", f"release failed: {e.message}")
            prev = dict(inc.verdict or {})
            inc.verdict = {**prev, "verdict": "OVERRIDDEN", "override": ev.get("note"), "previous_verdict": prev.get("verdict")}
            try:
                a = self.client.file_assessment(inc.id, "OVERRIDDEN", prev.get("confidence", 0.0),
                                                f"Analyst override: {ev.get('note')} Previous verdict {prev.get('verdict')} stands as a finding for the pentest report.",
                                                list(prev.get("evidence_ids", [])))
                inc.assessments.append(a)
            except ToolError:
                pass
            self._escalate(inc, f"override recorded for {ip}: exception logged, findings routed to the pentest report", [], inc.verdict.get("summary"))
            self._trace(inc, "adaptation", f"Assessment revised to OVERRIDDEN; exception recorded for {ip}")
            inc.status = "closed"
            self._trace(inc, "final", self._final_title(inc), verdict=inc.verdict, blocked_ips=inc.blocked_ips)
        else:
            inc.observe(f"Analyst override: {ev.get('note')} Treat {ip} as authorised.", type="analyst_override", ip=ip)
            inc.status = "open" if inc.status not in ("awaiting_approval",) else inc.status

    # ------------------------------------------------------------------ misc
    def _final_title(self, inc: Incident) -> str:
        v = inc.verdict or {}
        return f"{v.get('verdict')} ({v.get('confidence')}) - blocked: {', '.join(inc.blocked_ips) or 'none'}; tickets: {len(inc.escalations)}"

    @staticmethod
    def _fmt(args: dict[str, Any]) -> str:
        return ", ".join(f"{k}={str(v)[:60]}" for k, v in args.items())

    @staticmethod
    def _summ(name: str, result: Any, ids: list[str]) -> str:
        tail = f" -> evidence {', '.join(ids)}" if ids else ""
        return summarize_result(name, result) + tail

    def _trace(self, inc: Incident, kind: str, title: str, **detail: Any) -> None:
        ev = inc.add_trace(kind, title, **detail)
        if self.on_trace:
            self.on_trace(inc, ev)

    def _save(self, inc: Incident) -> None:
        if self.store:
            self.store.save(inc)

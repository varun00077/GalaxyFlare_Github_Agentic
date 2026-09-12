"""Analyst chat bound to an incident.

Slash commands act on the environment / loop; plain questions are answered from the
incident state (with Gemini when a key is configured, otherwise a grounded template).
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from .config import settings
from .state import Incident

HELP = ("Commands: /override <ip> [note]  - declare a source authorised (unblocks, records exception)\n"
        "/reopen <instruction>          - reopen the incident with an instruction for the planner\n"
        "/approve | /deny               - resolve a pending approval\n"
        "/pivot | /outage | /kbupdate | /fwreject - inject a disruption\n"
        "Anything else is a question about the incident.")

IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_command(text: str) -> tuple[str, dict[str, Any]] | None:
    t = text.strip()
    if not t.startswith("/"):
        return None
    cmd, _, rest = t[1:].partition(" ")
    cmd = cmd.lower()
    if cmd == "override":
        m = IP.search(rest)
        note = IP.sub("", rest).strip() or "Authorised source per analyst chat."
        return "override", {"ip": m.group(1) if m else None, "note": note}
    if cmd == "reopen":
        return "reopen", {"instruction": rest.strip() or "Re-examine the evidence."}
    if cmd in ("approve", "deny"):
        return cmd, {}
    if cmd in ("pivot", "outage", "kbupdate", "fwreject", "newalert"):
        return "chaos", {"kind": {"pivot": "pivot", "outage": "log_outage", "kbupdate": "kb_update", "fwreject": "firewall_reject", "newalert": "new_alert"}[cmd]}
    if cmd == "help":
        return "help", {}
    return "unknown", {"cmd": cmd}


def _context(inc: Incident) -> str:
    v = inc.verdict or {}
    ev = "\n".join(f"{e.id} [{e.category}] {e.excerpt[:200]} ({e.meaning})" for e in inc.evidence)
    trace = "\n".join(f"[{t.step}] {t.kind}: {t.title}" for t in inc.trace[-40:])
    return (f"Incident {inc.id} for alert {inc.alert_id} (scenario {inc.scenario}), status {inc.status}, steps {inc.steps}/{inc.budget}.\n"
            f"Verdict: {v.get('verdict')} confidence {v.get('confidence')}. Summary: {v.get('summary')}\n"
            f"Guardrail notes: {v.get('guardrail_notes')}\nBlocked IPs: {inc.blocked_ips}. Actions: {[a['type'] + ' ' + str(a.get('target')) for a in inc.actions]}.\n"
            f"Tickets: {[t.get('reason') for t in inc.escalations]}\n\nEVIDENCE LEDGER:\n{ev}\n\nTRACE:\n{trace}")


def answer_question(inc: Incident, question: str) -> str:
    if settings.gemini_api_key:
        try:
            return _gemini_answer(inc, question)
        except Exception as e:  # fall through to the grounded template
            return _template_answer(inc, question) + f"\n\n(LLM unavailable: {e})"
    return _template_answer(inc, question)


def _gemini_answer(inc: Incident, question: str) -> str:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent"
    body = {
        "systemInstruction": {"parts": [{"text": "You are SOCrates, a SOC investigation agent. Answer the analyst's question about this incident "
                                                  "using only the incident context. Cite evidence ids (E1, E2...). Be concise: 2-5 sentences. "
                                                  "If the analyst asks you to do something, tell them the slash command that does it."}]},
        "contents": [{"role": "user", "parts": [{"text": f"INCIDENT CONTEXT:\n{_context(inc)}\n\nANALYST: {question}"}]}],
        "generationConfig": {"temperature": 0.3},
    }
    r = httpx.post(url, headers={"x-goog-api-key": settings.gemini_api_key}, json=body, timeout=40.0)
    r.raise_for_status()
    parts = r.json()["candidates"][0]["content"]["parts"]
    return " ".join(p.get("text", "") for p in parts).strip()


def _template_answer(inc: Incident, question: str) -> str:
    v = inc.verdict or {}
    q = question.lower()
    if "why" in q or "evidence" in q:
        post = inc.evidence_by("post_exploitation")
        blocked = inc.evidence_by("attack_blocked")
        lines = [f"Verdict {v.get('verdict')} ({v.get('confidence')}). {v.get('summary', '')}"]
        if post:
            lines.append("Post-exploitation evidence: " + "; ".join(f"{e.id} {e.meaning}" for e in post[:4]))
        if blocked:
            lines.append("Block/reject evidence: " + "; ".join(f"{e.id} {e.meaning}" for e in blocked[:3]))
        if v.get("guardrail_notes"):
            lines.append("Guardrails: " + " ".join(v["guardrail_notes"]))
        return "\n".join(lines)
    if "block" in q or "action" in q:
        acts = ", ".join(f"{a['type']} {a.get('target', '')}" for a in inc.actions) or "no actions taken"
        return f"Actions: {acts}. Blocked now: {inc.blocked_ips or 'none'}. Tickets: {len(inc.escalations)}."
    if "missing" in q or "next" in q:
        return "Missing evidence: " + (", ".join(v.get("missing_evidence", [])) or "none recorded") + f". Status: {inc.status}."
    return (f"Incident {inc.id}: {v.get('verdict')} at {v.get('confidence')} confidence after {inc.steps} steps, "
            f"{len(inc.evidence)} evidence items, blocked {inc.blocked_ips or 'none'}. Ask 'why', 'what actions', or 'what is missing'. {HELP}")

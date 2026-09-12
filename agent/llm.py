"""Planners. Same interface, two implementations:

- GeminiLLM: the real planner. Rebuilds the conversation from incident history on every
  step (so a resumed incident continues seamlessly) and asks Gemini for the next tool
  call via native function calling.
- MockLLM: a scripted planner that follows the playbooks deterministically. Used by the
  test-suite and the eval harness so they run offline, and as the demo's emergency
  fallback if the API is down during judging.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import settings
from .prompts import SYSTEM, initial_user_message
from .state import Incident
from .tools import PLANNER_TOOLS


@dataclass
class Decision:
    kind: str                       # call | conclude | text
    name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    text: str = ""                  # model prose / rationale
    signature: str = ""             # provider opaque token (Gemini thoughtSignature)
    model: str = ""                 # model that produced this decision


class BaseLLM:
    name = "base"
    model = ""
    on_event = None                 # optional callback(str) for planner-side events (rate limits, model switches)

    def _emit(self, msg: str) -> None:
        if self.on_event:
            try:
                self.on_event(msg)
            except Exception:
                pass

    def decide(self, inc: Incident) -> Decision:  # pragma: no cover - interface
        raise NotImplementedError


# ---------------------------------------------------------------------------- shared helpers
def _shrink(obj: Any, max_list: int = 40, max_str: int = 600) -> Any:
    if isinstance(obj, dict):
        return {k: _shrink(v, max_list, max_str) for k, v in obj.items()}
    if isinstance(obj, list):
        out = [_shrink(v, max_list, max_str) for v in obj[:max_list]]
        if len(obj) > max_list:
            out.append(f"... {len(obj) - max_list} more items omitted ...")
        return out
    if isinstance(obj, str) and len(obj) > max_str:
        return obj[:max_str] + "..."
    return obj


class RequestTooLarge(RuntimeError):
    """Provider refused the request for size; caller should re-render with a tighter compaction level."""


COMPACTION = [  # (keep_full, max_list, max_str, ledger_items, ledger_chars)
    (2, 12, 300, 20, 120),
    (1, 6, 160, 12, 90),
    (0, 4, 100, 8, 70),
]


def compact_history(inc: Incident, keep_full: int = 2, max_list: int = 12, max_str: int = 300) -> list[tuple[Any, Any]]:
    """Pairs of (history item, replay payload). Only the most recent `keep_full` tool results are replayed in
    full; older ones become a one-line summary plus the evidence ids they produced (the ledger carries the
    lines). Keeps each planner call small enough for tight tokens-per-minute budgets."""
    from .evidence import summarize_result
    calls = [i for i, h in enumerate(inc.history) if h.kind == "call"]
    full = set(calls[-keep_full:])
    by_step: dict[int, list[str]] = {}
    for e in inc.evidence:
        by_step.setdefault(e.step, []).append(e.id)
    out = []
    for i, h in enumerate(inc.history):
        if h.kind != "call":
            out.append((h, None))
        elif h.error:
            out.append((h, {"error": h.error}))
        elif i in full:
            out.append((h, {"result": _shrink(h.result, max_list=max_list, max_str=max_str)}))
        else:
            out.append((h, {"summary": summarize_result(h.name, h.result), "evidence_ids": by_step.get(h.step, [])}))
    return out


def rule_only_conclusion(inc: Incident) -> dict[str, Any]:
    """Draft a conclusion straight from the evidence ledger. Used by the mock planner and as
    the fallback when the LLM returns malformed output twice."""
    post = inc.evidence_by("post_exploitation")
    blocked = inc.evidence_by("attack_blocked")
    src_ip = (inc.alert or {}).get("src_ip", "")
    host = (inc.asset or {}).get("hostname", "")
    ids = lambda evs: [e.id for e in evs]  # noqa: E731

    if inc.asset_unknown:
        return {"verdict": "INCONCLUSIVE", "confidence": 0.3, "proposed_action": "escalate",
                "summary": f"Target {(inc.alert or {}).get('dest_ip')} has no asset record ({ids(inc.evidence_by('asset_unknown'))}); "
                           f"no version to test against the KB and no host logs, so the outcome cannot be established. Not blocking on the label alone.",
                "evidence_ids": ids(inc.evidence), "missing_evidence": ["asset record / owner for the target IP", "host logs (web, process)",
                                                                        "service and version running on the target"]}
    if post:
        crit = (inc.asset or {}).get("criticality") in ("high", "critical")
        shell = any("shell" in e.meaning or "spawned" in e.excerpt for e in post)
        acct = next((m.group(2) for e in post for m in [re.search(r"Accepted (password|publickey) for (\S+)", e.excerpt)] if m), None)
        note = f"Reset credentials for account {acct} and review its sessions." if acct else ("Remove the web shell and review uploads directory." if any("cmd=" in e.excerpt for e in post) else "")
        return {"verdict": "SUCCEEDED", "confidence": 0.88 if inc.asset_vulnerable else 0.8,
                "proposed_action": "block_ip_and_isolate_host" if (crit and shell and not acct) else "block_ip",
                "action_target": inc.alert.get("src_ip") if inc.alert else src_ip,
                "summary": f"Attack from {src_ip} on {host} succeeded: {'; '.join(e.meaning for e in post[:3])} ({', '.join(ids(post))}). "
                           + (f"Asset vulnerable ({', '.join(ids(inc.evidence_by('vulnerable')))}). " if inc.asset_vulnerable else ""),
                "evidence_ids": ids(post + inc.evidence_by("vulnerable")), "missing_evidence": [], "escalation_note": note}
    if blocked or inc.asset_vulnerable is False:
        why = "request blocked at the edge" if blocked else "version outside the affected range"
        return {"verdict": "FAILED", "confidence": 0.85, "proposed_action": "watchlist", "action_target": src_ip,
                "summary": f"Attempt from {src_ip} on {host} failed: {why} ({', '.join(ids(blocked + inc.evidence_by('not_vulnerable')))}); "
                           f"no post-exploitation traces in the searched logs.", "evidence_ids": ids(blocked + inc.evidence_by("not_vulnerable")), "missing_evidence": []}
    return {"verdict": "INCONCLUSIVE", "confidence": 0.4, "proposed_action": "escalate", "summary": "Evidence insufficient to establish the outcome.",
            "evidence_ids": ids(inc.evidence), "missing_evidence": ["host log evidence of exploitation or rejection"]}


# ---------------------------------------------------------------------------- Gemini
class GeminiLLM(BaseLLM):
    name = "gemini"
    URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self, api_key: str | None = None, model: str | None = None, temperature: float = 0.2):
        self.api_key = api_key or settings.gemini_api_key
        self.model = model or settings.gemini_model
        self.temperature = temperature
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not set (put it in .env or use LLM_PROVIDER=mock)")
        self._c = httpx.Client(timeout=60.0)
        self.usage: dict[str, int] = {"prompt": 0, "output": 0, "calls": 0}

    def _contents(self, inc: Incident) -> list[dict[str, Any]]:
        contents: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": initial_user_message(inc.alert_id)}]}]

        def add(role: str, part: dict[str, Any]) -> None:
            if contents and contents[-1]["role"] == role:
                contents[-1]["parts"].append(part)
            else:
                contents.append({"role": role, "parts": [part]})

        for h, payload in compact_history(inc):
            if h.kind == "call":
                # Gemini 3 thinking models require the thought signature to be echoed with each replayed call;
                # calls made before a resume (or by the scripted planner) carry the documented skip token.
                add("model", {"functionCall": {"name": h.name, "args": h.args},
                              "thoughtSignature": h.signature or "skip_thought_signature_validator"})
                add("user", {"functionResponse": {"name": h.name, "response": payload}})
            else:
                add("user", {"text": f"[ENVIRONMENT EVENT] {h.text}"})
        if inc.evidence:
            ledger = "\n".join(f"{e.id} [{e.category}] {e.excerpt[:120]}" for e in inc.evidence[-20:])
            add("user", {"text": f"[EVIDENCE LEDGER so far]\n{ledger}"})
        return contents

    def decide(self, inc: Incident) -> Decision:
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM}]},
            "contents": self._contents(inc),
            "tools": [{"functionDeclarations": PLANNER_TOOLS}],
            "toolConfig": {"functionCallingConfig": {"mode": "ANY"}},
            "generationConfig": {"temperature": self.temperature},
        }
        data = self._post(body)
        self.usage["calls"] += 1
        um = data.get("usageMetadata", {})
        self.usage["prompt"] += um.get("promptTokenCount", 0)
        self.usage["output"] += um.get("candidatesTokenCount", 0)
        parts = (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        text = " ".join(p["text"] for p in parts if "text" in p and not p.get("thought")).strip()
        sig = next((p["thoughtSignature"] for p in parts if p.get("thoughtSignature")), "")
        for p in parts:
            fc = p.get("functionCall")
            if fc:
                name, args = fc.get("name", ""), fc.get("args") or {}
                return Decision("conclude" if name == "conclude_investigation" else "call", name, args, text, p.get("thoughtSignature") or sig, self.model)
        return Decision("text", text=text or "(empty response)")

    def complete(self, system: str, user: str) -> str:
        data = self._post({"systemInstruction": {"parts": [{"text": system}]},
                           "contents": [{"role": "user", "parts": [{"text": user}]}],
                           "generationConfig": {"temperature": 0.3}}, model=self.model)
        parts = (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        return " ".join(p.get("text", "") for p in parts if not p.get("thought")).strip()

    def _post(self, body: dict[str, Any], model: str | None = None) -> dict[str, Any]:
        from .llm_openai import retry_delay_from  # shared retry-hint parser
        url = self.URL.format(model=model or self.model)
        last = None
        for i in range(5):
            try:
                r = self._c.post(url, headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"}, json=body)
            except httpx.HTTPError as e:
                last = RuntimeError(f"gemini connection error: {e}")
                time.sleep(2.0 * (2 ** i))
                continue
            if r.status_code == 200:
                return r.json()
            last = RuntimeError(f"gemini HTTP {r.status_code}: {r.text[:600]}")
            if r.status_code not in (408, 429, 500, 502, 503, 504):
                raise last
            delay = retry_delay_from(r)
            wait = min((delay + 0.5) if delay else 2.0 * (2 ** i), 65.0)
            self._emit(f"Planner rate-limited by Gemini (HTTP {r.status_code}); waiting {wait:.0f}s before retrying")
            time.sleep(wait)
        raise last  # type: ignore[misc]


# ---------------------------------------------------------------------------- Mock (scripted playbook follower)
class MockLLM(BaseLLM):
    """Deterministic planner. Mirrors what a good analyst does with the playbooks; no network."""
    name = "mock"

    def _done(self, inc: Incident, name: str, since: int = 0, **match: Any) -> bool:
        for h in inc.calls(name):
            if h.step < since or h.error:
                continue
            if all(str(h.args.get(k)) == str(v) for k, v in match.items()):
                return True
        return False

    def _failed_twice(self, inc: Incident, name: str, since: int = 0, **match: Any) -> bool:
        n = sum(1 for h in inc.calls(name) if h.step >= since and h.error and all(str(h.args.get(k)) == str(v) for k, v in match.items()))
        return n >= 2

    def _alert_rec(self, inc: Incident, alert_id: str) -> dict[str, Any] | None:
        for h in reversed(inc.calls("get_alert")):
            if h.args.get("alert_id") == alert_id and isinstance(h.result, dict):
                return h.result
        return None

    def decide(self, inc: Incident) -> Decision:
        cur = inc.current_alert_id
        since = inc.epoch_step
        # Only knowledge-dependent calls go stale when the KB changes (epoch bump); the rest stay done.
        d = lambda name, **m: self._done(inc, name, since if name in ("lookup_cves", "search_logs") else 0, **m)  # noqa: E731
        call = lambda name, why, **args: Decision("call", name, args, why)  # noqa: E731

        # Follow-up alert surfaced by verification: correlate, then hunt traces for the new source.
        if cur != inc.alert_id:
            rec = self._alert_rec(inc, cur)
            if rec is None:
                return call("get_alert", f"Verification surfaced {cur} on the same host; correlate it.", alert_id=cur)
            if not d("get_flow", flow_id=rec["flow_id"]):
                return call("get_flow", "Check whether the new request was accepted.", flow_id=str(rec["flow_id"]))
            host = rec["dest_ip"]
            for source in ("outbound", "process", "app"):
                if not d("search_logs", host=host, source=source, pattern=rec["src_ip"]) and not self._failed_twice(inc, "search_logs", since, host=host, source=source):
                    return call("search_logs", f"Hunt {source} traces tied to the new source {rec['src_ip']}.", host=host, source=source, pattern=rec["src_ip"])
            draft = rule_only_conclusion(inc)
            draft["action_target"] = rec["src_ip"]
            draft["proposed_action"] = "block_ip" if draft["verdict"] == "SUCCEEDED" else draft["proposed_action"]
            draft["summary"] = f"Follow-up {cur}: same exploit from {rec['src_ip']} after the first block (attacker pivot). " + draft["summary"]
            return Decision("conclude", "conclude_investigation", draft, "Same technique, new source; evidence already shows execution.")

        if not d("get_alert", alert_id=cur):
            return call("get_alert", "Start from the alert record.", alert_id=cur)
        alert = inc.alert or {}
        if not d("get_flow", flow_id=alert.get("flow_id")):
            return call("get_flow", "The response status tells us whether the payload was accepted.", flow_id=str(alert.get("flow_id")))
        if not d("get_asset", key=alert.get("dest_ip")) and not self._failed_twice(inc, "get_asset", since, key=alert.get("dest_ip")) and not inc.asset_unknown:
            return call("get_asset", "Need the service versions and criticality of the target.", key=alert.get("dest_ip"))
        if inc.asset_unknown:
            if not d("search_playbooks", query="alert on host not in asset inventory"):
                return call("search_playbooks", "No asset record; check the playbook for unknown assets.", query="alert on host not in asset inventory")
            return Decision("conclude", "conclude_investigation", rule_only_conclusion(inc), "Cannot establish outcome without an asset record.")
        if not d("check_allowlist", ip=alert.get("src_ip")):
            return call("check_allowlist", "Rule out an authorised source before treating it as hostile.", ip=alert.get("src_ip"))
        for svc in (inc.asset or {}).get("services", []):
            if not d("lookup_cves", product=svc["product"], version=svc["version"]):
                return call("lookup_cves", f"Is {svc['product']} {svc['version']} exploitable?", product=svc["product"], version=svc["version"])
        sig = alert.get("alert", {}).get("signature", "")
        if not d("search_playbooks", query=sig):
            return call("search_playbooks", "Retrieve the response playbook for this signature.", query=sig)
        host = (inc.asset or {}).get("hostname", alert.get("dest_ip"))
        plan = list((inc.playbook or {}).get("evidence_plan", []))
        # Add per-CVE indicator sources the playbook may not list.
        for cve in inc.cves_seen.values():
            for ind in cve.get("success_indicators", []):
                if not any(p["source"] == ind["source"] for p in plan):
                    plan.append({"source": ind["source"], "pattern": alert.get("src_ip", "")})
        for p in plan:
            if not d("search_logs", host=host, source=p["source"], pattern=p["pattern"]) and not self._failed_twice(inc, "search_logs", since, host=host, source=p["source"]):
                return call("search_logs", f"Playbook step: check {p['source']} log for '{p['pattern']}'.", host=host, source=p["source"], pattern=p["pattern"])
        draft = rule_only_conclusion(inc)
        return Decision("conclude", "conclude_investigation", draft, "Evidence plan complete.")


PROVIDERS = ("gemini", "groq", "mock")


def make_llm(provider: str | None = None, api_key: str | None = None, model: str | None = None) -> BaseLLM:
    provider = (provider or settings.llm_provider).lower()
    if provider == "mock":
        return MockLLM()
    if provider == "gemini":
        return GeminiLLM(api_key=api_key, model=model)
    if provider == "groq":
        from .llm_openai import OpenAICompatLLM
        return OpenAICompatLLM(api_key=api_key, model=model)
    raise ValueError(f"unknown LLM_PROVIDER {provider!r} (expected one of {PROVIDERS})")


def has_key(provider: str) -> bool:
    return {"gemini": bool(settings.gemini_api_key), "groq": bool(settings.groq_api_key), "mock": True}.get(provider, False)

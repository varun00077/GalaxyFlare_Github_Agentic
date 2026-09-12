"""OpenAI-compatible chat-completions planner. Used for Groq (default) and works for any
endpoint that speaks the same protocol (OpenAI, OpenRouter, vLLM, Ollama...).

Same contract as GeminiLLM: rebuild the conversation from incident history each step, ask
for exactly one tool call, return a Decision. Tool-call ids are stored in
HistoryItem.signature so the replayed assistant/tool message pairs stay consistent.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from .config import settings
from .llm import COMPACTION, BaseLLM, Decision, RequestTooLarge, compact_history
from .prompts import SYSTEM, initial_user_message
from .state import Incident
from .tools import PLANNER_TOOLS

GROQ_BASE = "https://api.groq.com/openai/v1"
# Preference order for GROQ_MODEL=auto: strongest tool-use first.
GROQ_PREFERRED = ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b", "qwen/qwen3.6-27b",
                  "llama-3.3-70b-versatile", "meta-llama/llama-4-maverick-17b-128e-instruct"]
_TOOL_MODEL_HINT = re.compile(r"gpt-oss|qwen|llama-3\.[1-9]|llama-4|mixtral|kimi|deepseek", re.I)


def _lower_schema(node: Any) -> Any:
    """Gemini declares types in UPPERCASE; JSON schema wants lowercase."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "type" and isinstance(v, str):
                out[k] = v.lower()
            else:
                out[k] = _lower_schema(v)
        return out
    if isinstance(node, list):
        return [_lower_schema(v) for v in node]
    return node


def _openai_params(params: dict[str, Any]) -> dict[str, Any]:
    p = _lower_schema(params)
    # ids arrive as numbers in alert records; accept either so strict validators (Groq) do not reject the call
    for key in ("flow_id",):
        if key in p.get("properties", {}):
            p["properties"][key] = {"anyOf": [{"type": "string"}, {"type": "integer"}], "description": p["properties"][key].get("description", "")}
    return p


OPENAI_TOOLS = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                  "parameters": _openai_params(t["parameters"])}} for t in PLANNER_TOOLS]


def retry_delay_from(resp: httpx.Response) -> float | None:
    """Honor the provider's own hint: Retry-After header, or 'try again in 3.2s' / Gemini's retryDelay."""
    ra = resp.headers.get("retry-after")
    if ra:
        try:
            return float(ra)
        except ValueError:
            pass
    m = re.search(r"try again in ([\d.]+)\s*(ms|s)", resp.text, re.I)
    if m:
        v = float(m.group(1))
        return v / 1000 if m.group(2).lower() == "ms" else v
    m = re.search(r'retryDelay"?\s*:\s*"?([\d.]+)s', resp.text)
    if m:
        return float(m.group(1))
    return None


def list_models(base_url: str, api_key: str) -> list[str]:
    try:
        r = httpx.get(f"{base_url}/models", headers={"Authorization": f"Bearer {api_key}"}, timeout=15.0)
        r.raise_for_status()
    except httpx.HTTPError:
        return []
    ids = [m["id"] for m in r.json().get("data", []) if m.get("active", True)]
    return sorted(i for i in ids if _TOOL_MODEL_HINT.search(i))


def resolve_model(base_url: str, api_key: str, requested: str) -> str:
    if requested and requested != "auto":
        return requested
    available = set(list_models(base_url, api_key))
    for m in GROQ_PREFERRED:
        if m in available:
            return m
    return next(iter(sorted(available)), GROQ_PREFERRED[0])


class OpenAICompatLLM(BaseLLM):
    name = "groq"

    def __init__(self, api_key: str | None = None, model: str | None = None, base_url: str = GROQ_BASE,
                 temperature: float = 0.2, name: str = "groq"):
        self.api_key = api_key or settings.groq_api_key
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.name = name
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is not set (put it in .env, use the Key button, or LLM_PROVIDER=mock)")
        self.primary = resolve_model(self.base_url, self.api_key, model or settings.groq_model)
        self.model = self.primary
        # Fallback chain: every model has its own tokens-per-minute bucket on the free tier, so when the
        # primary is throttled the planner moves to the next tool-capable model instead of waiting.
        available = set(list_models(self.base_url, self.api_key))
        self.chain = [self.primary] + [m for m in GROQ_PREFERRED if m in available and m != self.primary]
        self._c = httpx.Client(timeout=90.0)
        self.usage: dict[str, int] = {"prompt": 0, "output": 0, "calls": 0, "model_switches": 0}

    # ------------------------------------------------------------------ conversation
    def _messages(self, inc: Incident, level: int = 0) -> list[dict[str, Any]]:
        keep_full, max_list, max_str, n_led, led_chars = COMPACTION[min(level, len(COMPACTION) - 1)]
        msgs: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM},
                                      {"role": "user", "content": initial_user_message(inc.alert_id)}]
        for i, (h, payload) in enumerate(compact_history(inc, keep_full, max_list, max_str)):
            if h.kind == "call":
                call_id = h.signature or f"call_{h.step}_{i}"
                msgs.append({"role": "assistant", "content": h.rationale or None,
                             "tool_calls": [{"id": call_id, "type": "function",
                                             "function": {"name": h.name, "arguments": json.dumps(h.args)}}]})
                msgs.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(payload)})
            else:
                msgs.append({"role": "user", "content": f"[ENVIRONMENT EVENT] {h.text}"})
        if inc.evidence:
            ledger = "\n".join(f"{e.id} [{e.category}] {e.excerpt[:led_chars]}" for e in inc.evidence[-n_led:])
            msgs.append({"role": "user", "content": f"[EVIDENCE LEDGER so far]\n{ledger}\nContinue: call the next tool, or conclude_investigation."})
        return msgs

    def decide(self, inc: Incident) -> Decision:
        data = None
        last_level = len(COMPACTION) - 1
        for level in range(len(COMPACTION)):
            body = {"messages": self._messages(inc, level), "tools": OPENAI_TOOLS,
                    "tool_choice": "required", "temperature": self.temperature, "max_tokens": 700}
            try:
                # At the tightest level a 413 means the minute's budget is spent, not that the request is big:
                # let _post treat it like a 429 (rotate models, then honor the wait).
                data = self._post("/chat/completions", body, too_large_is_rate_limit=(level == last_level))
                break
            except RequestTooLarge:
                self._emit(f"Planner request too large for {self.model}; compacting the investigation context (level {level + 1}) and retrying")
        assert data is not None
        self.usage["calls"] += 1
        u = data.get("usage", {})
        self.usage["prompt"] += u.get("prompt_tokens", 0)
        self.usage["output"] += u.get("completion_tokens", 0)
        msg = (data.get("choices") or [{}])[0].get("message", {})
        text = (msg.get("content") or "").strip()
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                return Decision("text", text=f"malformed tool arguments for {name}: {fn.get('arguments')!r}")
            return Decision("conclude" if name == "conclude_investigation" else "call", name, args or {}, text, tc.get("id", ""), self.model)
        return Decision("text", text=text or "(empty response)")

    def complete(self, system: str, user: str) -> str:
        data = self._post("/chat/completions", {"temperature": 0.3, "max_tokens": 500,
                                                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        return ((data.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()

    # ------------------------------------------------------------------ transport
    def _post(self, path: str, body: dict[str, Any], too_large_is_rate_limit: bool = True) -> dict[str, Any]:
        """Send with the current model; on throttling rotate through the chain before waiting."""
        last: Exception | None = None
        idx = self.chain.index(self.model) if self.model in self.chain else 0
        waited_round = 0
        for attempt in range(12):
            model = self.chain[idx % len(self.chain)]
            try:
                r = self._c.post(self.base_url + path, headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                                 json={**body, "model": model})
            except httpx.HTTPError as e:
                last = RuntimeError(f"{self.name} connection error: {e}")
                time.sleep(2.0 * (2 ** min(attempt, 4)))
                continue
            if r.status_code == 200:
                if model != self.model:
                    self.usage["model_switches"] += 1
                    self._emit(f"Planner switched to {model} ({self.model} is rate-limited on the free tier)")
                    self.model = model
                return r.json()
            last = RuntimeError(f"{self.name} HTTP {r.status_code} ({model}): {r.text[:600]}")
            if r.status_code == 400 and "tool_use_failed" in r.text:
                # The model produced a call that failed schema validation; its intent is in failed_generation.
                try:
                    fg = json.loads(r.json()["error"]["failed_generation"])
                    if isinstance(fg, dict) and fg.get("name"):
                        return {"choices": [{"message": {"content": "", "tool_calls": [{"id": f"recovered_{int(time.time())}", "type": "function",
                                                                                            "function": {"name": fg["name"], "arguments": json.dumps(fg.get("arguments") or {})}}]}}],
                                "usage": {}, "recovered": True}
                except (ValueError, KeyError, TypeError):
                    pass
            too_large = r.status_code == 413 or (r.status_code == 429 and "too large" in r.text.lower())
            if too_large and not too_large_is_rate_limit:
                raise RequestTooLarge(f"{self.name} refused the request size on {model}: {r.text[:200]}")
            if r.status_code not in (408, 413, 429, 500, 502, 503, 504):
                raise last
            if r.status_code in (413, 429) and len(self.chain) > 1 and waited_round < len(self.chain) - 1:
                idx += 1                     # try the next model's bucket right away
                waited_round += 1
                continue
            delay = retry_delay_from(r)
            wait = min((delay + 0.5) if delay else 2.0 * (2 ** min(attempt, 4)), 65.0)
            self._emit(f"All planner models rate-limited; waiting {wait:.0f}s" if len(self.chain) > 1 else f"Planner rate-limited (HTTP {r.status_code}); waiting {wait:.0f}s")
            time.sleep(wait)
            waited_round = 0
            idx = self.chain.index(self.primary)
        raise last  # type: ignore[misc]

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
from .llm import BaseLLM, Decision, _shrink
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


OPENAI_TOOLS = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                  "parameters": _lower_schema(t["parameters"])}} for t in PLANNER_TOOLS]


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
        self.model = resolve_model(self.base_url, self.api_key, model or settings.groq_model)
        self._c = httpx.Client(timeout=90.0)
        self.usage: dict[str, int] = {"prompt": 0, "output": 0, "calls": 0}

    # ------------------------------------------------------------------ conversation
    def _messages(self, inc: Incident) -> list[dict[str, Any]]:
        msgs: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM},
                                      {"role": "user", "content": initial_user_message(inc.alert_id)}]
        for i, h in enumerate(inc.history):
            if h.kind == "call":
                call_id = h.signature or f"call_{h.step}_{i}"
                msgs.append({"role": "assistant", "content": h.rationale or None,
                             "tool_calls": [{"id": call_id, "type": "function",
                                             "function": {"name": h.name, "arguments": json.dumps(h.args)}}]})
                resp = {"error": h.error} if h.error else {"result": _shrink(h.result, max_list=30, max_str=400)}
                msgs.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(resp)})
            else:
                msgs.append({"role": "user", "content": f"[ENVIRONMENT EVENT] {h.text}"})
        if inc.evidence:
            ledger = "\n".join(f"{e.id} [{e.category}] {e.excerpt[:160]}" for e in inc.evidence[-25:])
            msgs.append({"role": "user", "content": f"[EVIDENCE LEDGER so far]\n{ledger}\nContinue: call the next tool, or conclude_investigation."})
        return msgs

    def decide(self, inc: Incident) -> Decision:
        body = {"model": self.model, "messages": self._messages(inc), "tools": OPENAI_TOOLS,
                "tool_choice": "required", "temperature": self.temperature, "max_tokens": 1200}
        data = self._post("/chat/completions", body)
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
            return Decision("conclude" if name == "conclude_investigation" else "call", name, args or {}, text, tc.get("id", ""))
        return Decision("text", text=text or "(empty response)")

    def complete(self, system: str, user: str) -> str:
        data = self._post("/chat/completions", {"model": self.model, "temperature": 0.3, "max_tokens": 600,
                                                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        return ((data.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()

    # ------------------------------------------------------------------ transport
    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        last: Exception | None = None
        for i in range(5):
            try:
                r = self._c.post(self.base_url + path, headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}, json=body)
            except httpx.HTTPError as e:
                last = RuntimeError(f"{self.name} connection error: {e}")
                time.sleep(2.0 * (2 ** i))
                continue
            if r.status_code == 200:
                return r.json()
            last = RuntimeError(f"{self.name} HTTP {r.status_code}: {r.text[:600]}")
            if r.status_code not in (408, 429, 500, 502, 503, 504):
                raise last
            delay = retry_delay_from(r)
            time.sleep(min((delay + 0.5) if delay else 2.0 * (2 ** i), 65.0))
        raise last  # type: ignore[misc]

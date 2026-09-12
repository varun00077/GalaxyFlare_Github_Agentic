# Submission — Team Galaxy Flare

**Agentic AI Hackathon, Tech Zephyr 4.0 (IIT Bhubaneswar) · Track 5 Cybersecurity · Problem Statement 9**
*Autonomous SOC Investigation & Response Agent*

| Artifact | Submission name | Where |
|---|---|---|
| Source code | `GalaxyFlare_Github_Agentic` | https://github.com/varun00077/GalaxyFlare_Github_Agentic |
| Demo video (≤ 5 min) | `GalaxyFlare_Video_Agentic.mp4` | script: [docs/VIDEO_SCRIPT.md](docs/VIDEO_SCRIPT.md) |
| Presentation brief | `GalaxyFlare_Brief_Agentic.pdf` | product spec: [docs/PRD.md](docs/PRD.md), design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Hosted demo | Vercel (stateless mode) | see "Deploying to Vercel" in [README.md](README.md) |

## What to look at first

1. `python -m agent.cli run --scenario s2 --llm mock --auto-approve` — the full loop in 15 seconds, offline.
2. `python -m uvicorn web.app:app --port 8000` → http://localhost:8000 — the analyst console: live trace, chaos
   panel, approvals, chat. Paste a Groq key with the **Key** button (or put it in `.env`) for the real planner.
3. `python -m eval --llm mock --runs 2` — scoring across all six scenarios (verdict accuracy, unsafe actions,
   verification, adaptation, escalation precision).
4. Flip the console to **LIVE HOST** — the same agent investigating the machine it runs on.

## How the judging criteria map to the code

| Criterion | Where |
|---|---|
| Goal-driven, multi-step, dynamic tool choice | `agent/controller.py`, `agent/llm.py` / `agent/llm_openai.py` |
| Adaptation to unexpected conditions | pivot (S2), tool outage (S3), analyst override (S5), revised advisory (S6); `agent/verifier.py`, event drain in the controller |
| Robustness | retries with provider hints, model rotation under rate limits, context compaction, loop guard, step budget, rule-only fallback |
| Safety / guardrails | `agent/rules.py` — deterministic gates outside the LLM; approvals for host isolation and critical assets |
| Verification | `agent/verifier.py`; every block re-checked against the environment |
| Human interaction | approvals, overrides, chat (`agent/chat.py`) |
| Evaluation | `eval/` harness, `tests/` (34 tests) |
| Real-world path | `live/` — Windows event logs, live connections, NVD, IP reputation behind the same tool API |

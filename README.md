# SOCrates — Autonomous SOC Investigation & Response Agent

**Team Galaxy Flare** · Agentic AI Hackathon, Tech Zephyr 4.0, IIT Bhubaneswar · Track 5, Problem Statement 9

A NIDS alert only proves that an attack was *attempted*. SOCrates is an agent that works out whether it
*landed*: it pulls flow metadata, the asset record, the advisory KB and the host's own logs, decides at each
step what evidence to fetch next, reaches an evidence-backed verdict, takes a sandboxed response only when the
guardrails allow it, verifies that the response took effect, and changes its mind when the environment or an
analyst gives it a reason to.

```
[ 8] DECISION     search_logs(host=app02, source=outbound, pattern=dst=)
[ 8] RESULT       3 matching line(s) in app02/outbound -> evidence E5, E6
[11] DECISION     Planner concludes SUCCEEDED (confidence 0.88), proposes block_ip_and_isolate_host
[11] GUARDRAIL    Verdict check passed: SUCCEEDED
[11] ACTION       Blocked 203.0.113.66 (rule fw-0001)
[11] VERIFICATION rule effective for 203.0.113.66, but 1 new alert(s) on the same host from 198.51.100.23: alt-2002
[11] ADAPTATION   Attacker pivot suspected: investigating alt-2002
...
[17] FINAL        SUCCEEDED (0.88) - blocked: 203.0.113.66, 198.51.100.23; tickets: 0
```

Everything runs against a **fully synthetic sandbox** (fake Suricata alerts, fake hosts, fake firewall).
Nothing touches a real network. See [docs/PRD.md](docs/PRD.md) for the product spec and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## Why this is agentic, not a prompt chain

| Requirement | Where it lives |
|---|---|
| Goal-driven execution | `agent/controller.py` loops until the verdict is evidence-supported, the budget is spent, or it escalates |
| Dynamic action selection | the planner (`agent/llm.py`) picks the next tool from the current evidence ledger; branching is data-dependent |
| Multi-step execution | 6–17 tool calls across 5 systems per incident, plus state-changing actions and verification |
| Adaptation | attacker pivot (S2), tool outage (S3), analyst override (S5), revised advisory (S6) each re-enter the loop |
| Robustness | retries with backoff, evidence fallbacks, step budget, deterministic guardrails, escalation instead of invented certainty |
| Verification | `agent/verifier.py` re-queries the environment after every action; `python -m eval` scores every scenario |

The LLM plans and proposes. Deterministic rules (`agent/rules.py`) can only *downgrade* a verdict, *cap*
confidence, or *refuse / gate* an action — they never pick one. Blocking needs confidence ≥ 0.7, a
SUCCEEDED verdict backed by post-exploitation evidence, and a source that is not allow-listed; anything on a
critical asset or host isolation needs analyst approval.

## Quick start

Requirements: Python 3.11+, and a planner key: **Groq** ([console.groq.com/keys](https://console.groq.com/keys),
recommended — fast and its free tier holds up under the agent's 8–17 calls per incident) or **Gemini**
([aistudio.google.com/apikey](https://aistudio.google.com/apikey)). Both work through the same loop; switch with
`LLM_PROVIDER` or the Key button in the console.

```bash
git clone <this repo> socrates && cd socrates
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                              # then put your key in GROQ_API_KEY (or GEMINI_API_KEY)
```

Run the headline scenario with the real planner (sandbox runs in-process, still over HTTP):

```bash
python -m agent.cli run --scenario s2 --auto-approve
```

Without an API key, the scripted planner follows the same loop offline (this is also the demo's
emergency fallback):

```bash
python -m agent.cli run --scenario s2 --llm mock --auto-approve
```

Drop `--auto-approve` to be prompted when the agent wants to isolate a host or touch a critical asset.

### Analyst console (web UI)

```bash
python -m uvicorn web.app:app --port 8000        # then open http://localhost:8000
```

Alert queue → **Run** starts an investigation; the trace streams live (SSE). The hero shows the verdict,
confidence after guardrails, steps, evidence and actions. The **chaos panel** injects a pivot, a log
outage, an analyst override, a revised advisory, a repeat alert, or a firewall rejection while the agent
works. High-impact actions (host isolation, anything on a critical asset) pause for **Approve / Deny**.
The **analyst chat** answers questions from the evidence ledger (via Gemini when a key is set) and takes
commands: `/override <ip> [note]`, `/reopen <instruction>`, `/approve`, `/deny`, `/pivot`, `/outage`,
`/kbupdate`, `/fwreject`, `/help`.

No `.env`? Click **Key** in the top bar, pick Groq or Gemini, paste the key (model optional — Groq's `auto`
picks the strongest tool-capable model your key can use), and hit *Validate & use*. The key is checked with a
one-token generation, held in the server process's memory (or written to the gitignored `.env` if you tick
*remember*), never logged. *Use this provider* switches between loaded planners; *Scripted planner* drops to
the offline one — the stage fallback.

Other commands:

```bash
python -m agent.cli scenarios                      # list the six scenarios
python -m agent.cli run --scenario s3              # tool outage + critical asset approval
python -m eval --llm mock --runs 3                 # score all scenarios offline (seconds)
python -m eval --llm groq                          # score with the real planner (or --llm gemini)
python -m pytest                                   # 29 tests, no network
```

Run the sandbox as its own service (the agent then talks to it over the network, as in the architecture):

```bash
uvicorn sandbox.app:app --port 8001                # OpenAPI docs at http://localhost:8001/docs
python -m agent.cli run --scenario s2 --sandbox-url http://localhost:8001
```

Docker: `docker compose up` starts the sandbox (8001) and the console (8000).

## The six scenarios

Each scenario is a JSON file in `sandbox/scenarios/` with alerts, flows, logs, scripted environment
reactions (*triggers*) and tool faults. They double as the demo script and the eval suite.

| # | What happens | Verdict | Response | Adaptation shown |
|---|---|---|---|---|
| s1 | SQLi against a patched, WAF-protected app | FAILED | watch-list only | baseline: no block on the label alone |
| s2 | Log4Shell succeeds on app02; attacker returns from a new IP after the block | SUCCEEDED | block, isolate (approval), block again | verifier surfaces the pivot |
| s3 | SSH brute force succeeds on a critical bastion; log indexer returns 503 | SUCCEEDED | block (approval), ticket: reset credentials | retry → fallback → recovery |
| s4 | Alert against a host not in inventory | INCONCLUSIVE | escalate with missing evidence | refuses to guess |
| s5 | Confirmed web shell; analyst says it's an authorised pentest | OVERRIDDEN | block → unblock, exception recorded | human override wins |
| s6 | Traversal on Apache 2.4.50; advisory later revised (incomplete fix) | FAILED → SUCCEEDED | none → block | knowledge change reopens the incident |

Offline eval (`python -m eval --llm mock --runs 2`):

```
verdict_accuracy: 1.0   unsafe_actions: 0   actions_verified: True
adaptation_success: 1.0   escalation_precision: 1.0   mean_steps: 11
```

## Chaos panel (fault injection)

The sandbox exposes one-click disruptions, used by the scenarios and the console's chaos panel:

```
POST /chaos/pivot            attacker returns from a new IP
POST /chaos/log_outage       next N log searches return 503
POST /chaos/override         analyst declares the source an authorised pentest
POST /chaos/kb_update        advisory revised: a version becomes affected
POST /chaos/new_alert        another alert on the same host
POST /chaos/firewall_reject  firewall API refuses the next rule
```

## Project layout

```
sandbox/          the simulated environment (FastAPI service)
  world.py        stores, firewall, faults, triggers, chaos
  app.py          HTTP API
  retrieval.py    BM25 over playbooks + advisories
  data/           assets, CVE KB, playbooks
  scenarios/      s1..s6
agent/            the agent
  controller.py   observe -> plan -> act -> verify -> adapt loop
  llm.py          Gemini planner (function calling) + scripted MockLLM
  llm_openai.py   Groq / OpenAI-compatible planner (tool calling)
  tools.py        tool registry (Gemini schemas) + HTTP client
  evidence.py     deterministic evidence tagging
  rules.py        verdict gates + action policy
  verifier.py     post-action verification
  state.py        incident state, trace, SQLite persistence
  cli.py          command line runner
web/              agent service + analyst console (FastAPI, SSE, vanilla JS)
eval/             evaluation harness
tests/            pytest suite
docs/             PRD, architecture
```

## Status / roadmap

- [x] Day 1–2: sandbox, scenarios, agent core, CLI, eval harness, tests
- [x] Day 3: web UI — alert queue, live trace (SSE), verdict hero, chaos panel, chat + approvals
- [x] Real planners verified end-to-end: Groq gpt-oss-120b (S2, S3), Gemini 3.6 Flash (S2; free tier rate-limits mid-run)
- [ ] Day 4: hosted demo, architecture diagram export, real-planner eval on all six scenarios
- [ ] Day 5: demo video, presentation brief, submission packaging

## Guardrails and limits

All data is synthetic. The agent only ever acts inside the sandbox. It is decision support for a simulated
SOC, not a production security control.

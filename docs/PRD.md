# SOCrates — Autonomous SOC Investigation & Response Agent

**Problem statement:** PS9, Track 5 (Cybersecurity) · Agentic AI Hackathon, Tech Zephyr 4.0, IIT Bhubaneswar
**Document:** PRD + build plan · v0.1 · 12 Sep 2026
**Working name:** SOCrates (it investigates by asking the next right question). Rename freely.

---

## 1. Problem statement

A NIDS (Suricata/Snort) fires thousands of alerts a day, and the alert label only says an attack was *attempted* — not whether it *landed*. Deciding that requires correlating the alert with packet metadata, the target asset's software versions, the vulnerability KB, and the host's own logs, then choosing what to look at next based on what was just found. Tier-1 analysts do this by hand, 15–45 minutes per alert, and under load they either rubber-stamp alerts as false positives or block IPs on the label alone. The cost is missed successful intrusions on one side and broken business traffic on the other.

**Target users**
- Primary: Tier-1/Tier-2 SOC analysts in a simulated enterprise SOC.
- Secondary: the hackathon jury, who must see Goal → Decision → Action → Intermediate Result → Adaptation → Final Outcome inside 5 minutes.

## 2. Why this needs an agent (not a prompt chain)

| Hackathon requirement | How SOCrates meets it |
|---|---|
| Goal-driven execution | The goal is a *verified verdict + safe response* per alert, not a summary. The loop runs until the verdict has sufficient evidence, the budget is exhausted, or it escalates. |
| Dynamic action selection | The next evidence to fetch depends on the previous result (asset patched → check for WAF block; asset vulnerable → hunt post-exploitation traces in logs). Branching is data-dependent, so it cannot be a fixed chain. |
| Multi-step execution | Typical investigation: 6–12 tool calls across 5 systems plus 1–2 state-changing actions plus verification. |
| Adaptation | New alert from a pivoted IP, log-service outage, CVE KB update, or an analyst override each trigger reassessment mid-investigation. |
| Robustness | Retries with backoff, evidence fallbacks, step budget, deterministic guardrails on verdicts and actions, escalation instead of invented certainty. |

## 3. Goals

1. **Correct verdicts:** ≥ 90% correct SUCCEEDED / FAILED / INCONCLUSIVE across the scenario suite (10 runs each).
2. **Safe actions:** 0 blocks of allow-listed or failed-attack sources across the suite; every block is backed by cited evidence.
3. **Visible adaptation:** ≥ 3 distinct adaptation scenarios demonstrable live from a "chaos panel", each resolved without a restart.
4. **Verified outcomes:** 100% of state-changing actions are followed by an independent verification query, and the result is shown in the trace.
5. **Judge-runnable:** clone → `docker compose up` (or `make run`) → working UI in < 5 minutes on a clean machine.

## 4. Non-goals

- **Real network integration** (live Suricata, real firewalls, real CVE feeds). The sandbox is fully synthetic; this is required by the brief and keeps the demo deterministic.
- **Detection engineering.** We consume alerts; we do not write or tune signatures.
- **Full SOAR platform features** (case management, SLAs, multi-tenant RBAC). A single incident view and a ticket stub are enough.
- **Malware analysis / reverse engineering.** Out of scope; evidence stays at log/metadata level.
- **Multi-agent orchestration for its own sake.** One controller with a separate verifier module; agent count earns no points.

## 5. User stories

**SOC analyst**
- As an analyst, I want the agent to tell me *whether* an attack succeeded, with the evidence it used, so I can trust the verdict without redoing the investigation.
- As an analyst, I want the agent to block a confirmed attacker's IP in the (simulated) firewall and confirm the block took effect, so response happens in minutes, not hours.
- As an analyst, I want to be asked for approval before high-impact actions (isolating a critical host), so automation never takes down production.
- As an analyst, I want to override the agent (e.g., "10.9.8.7 is our pentest partner") and have it revise its conclusion and undo its action, so human context wins.
- As an analyst, I want alerts the agent cannot resolve to be escalated with a list of *what evidence is missing*, so I know exactly where to look.
- As an analyst, I want to chat with the agent about an open incident ("why did you block this?", "check the DB logs too"), so I can steer the investigation.

**Hackathon judge**
- As a judge, I want a live trace that labels each step as Decision / Action / Result / Adaptation, so I can score the agentic loop without reading code.
- As a judge, I want a button that injects a disruption mid-investigation, so I can see adaptation unscripted.

## 6. The sandbox (simulated environment)

All data is synthetic, generated from scenario files. The sandbox runs as a **separate FastAPI service**; the agent reaches it only over HTTP through a tool registry, so every tool call is a real external-system interaction that is observable, mockable, and fault-injectable.

| Store / system | Contents | Tools exposed |
|---|---|---|
| Alert feed | Suricata EVE-JSON style alerts: `signature`, `sid`, `severity`, `src_ip`, `dest_ip`, `dest_port`, `flow_id`, `timestamp`, `category` | `list_alerts()`, `get_alert(id)` |
| Packet metadata | Per `flow_id`: bytes in/out, duration, HTTP request line, user-agent, response status, TLS SNI, payload snippet | `get_flow(flow_id)` |
| Asset inventory | Hosts: hostname, IPs, OS, services + versions, criticality (low/med/high/critical), owner, patch date, internet-facing | `get_asset(ip_or_hostname)` |
| CVE KB (synthetic) | CVE id, affected product + version range, CVSS, exploitation prerequisites, **success indicators** (log patterns that show exploitation worked) | `lookup_cves(product, version)`, `get_cve(id)` |
| Host logs | Per host: web access, auth, process/EDR-style events, DB queries, DNS/outbound connections | `search_logs(host, source, window, pattern)` |
| Firewall (simulated) | Rule table; blocked IPs actually stop future flows in the simulator | `block_ip`, `unblock_ip`, `list_rules`, `verify_block(ip)` |
| Host control | Isolation flag on hosts (approval-gated) | `isolate_host`, `release_host` |
| Ticketing | Escalations with structured missing-evidence list | `escalate(incident, reason, missing_evidence)` |
| Allow-list / memory | Known-good IPs, prior verdicts, analyst overrides | `check_allowlist(ip)`, incident store |
| Retrieval (playbooks + CVE write-ups) | Response playbooks per signature category, CVE advisories, evidence checklists; keyword/BM25 search, no vector DB required | `search_playbooks(query)`, `search_advisories(query)` |
| Environment clock | Scenarios release events over time (new flows, pivots, outages) | Internal; drives the "chaos" |

**Chaos panel (fault injection, one click each):**
1. Attacker pivots to a new source IP after being blocked.
2. Log service outage for 30 s (tool returns 503).
3. Analyst override: source IP is an authorised pentester.
4. CVE KB update: version previously "not affected" is now affected.
5. New alert on the same host mid-investigation.
6. Firewall API rejects the rule (quota / syntax), forcing a retry or alternative action.

## 7. Agent architecture

```
alert ──▶ [Controller loop] observe → plan next evidence (LLM, constrained by tool registry)
                             → call tool → update state → reassess on event/result
                │                                   │
                ▼                                   ▼
        [Verdict engine]                     [Action policy]
   LLM draft + deterministic            deterministic gates,
   evidence rules, confidence           approval for high impact
                │                                   │
                ▼                                   ▼
        Incident report  ◀──────────  [Verifier] re-query environment,
        + evidence ledger              confirm effect, or bounce back to reassess
```

**Components**
- **Sandbox service (external system):** separate FastAPI process holding all stores in §6; the agent has no in-process access to it.
- **Retrieval:** playbook/advisory search the planner calls to decide which evidence a signature category needs and what post-exploitation indicators to look for.
- **Investigation state** (per incident, persisted to SQLite as JSON): alert, hypotheses `{succeeded, failed, inconclusive}` with running confidence, evidence ledger (source, tool call, finding, weight), open questions, actions taken, verification results, step counter, human overrides.
- **Planner** (LLM with native tool use): given state, chooses the next tool call *or* declares "enough evidence". Prompted to explain in one line why this evidence next. Hard step budget (default 12).
- **Autonomy boundary (state this in the trace and the deck):** the LLM planner chooses the investigation path, decides when evidence is sufficient, and proposes the response. Deterministic rules are *safety gates* — they can only downgrade a verdict, block an action, or require approval; they never choose the action. The trace labels them "Guardrail check: passed / blocked", not as decisions.
- **Verdict engine:** LLM drafts a verdict; deterministic rules then gate it:
  - `SUCCEEDED` requires ≥ 1 post-exploitation evidence item (accepted login after brute force, outbound callback, spawned process, 200 + anomalous response size, new privileged account) **and** asset vulnerable or vulnerability unknown.
  - `FAILED` requires blocked/403/reset evidence **or** asset not vulnerable, **and** zero post-exploitation evidence.
  - Otherwise `INCONCLUSIVE` → escalate with missing-evidence list. The agent cannot output certainty the rules do not support.
- **Action policy (deterministic):** `block_ip` allowed iff verdict ∈ {SUCCEEDED, IN_PROGRESS}, confidence ≥ 0.7, source not allow-listed. `isolate_host` or any action on a `critical` asset requires human approval in the UI. FAILED verdicts never block; they may add to a watch-list.
- **Verifier (separate module, no LLM needed):** after each action, re-queries the environment: rule present? new flows from the source since the rule? If traffic continues (pivot) or the rule is missing, it re-enters the loop with a new observation.
- **Adaptation triggers:** environment events (new alert, new flow, KB update), tool failures, verification failures, analyst messages/overrides. Each is appended as an observation and forces a reassessment step.
- **Failure handling:** tool retry with backoff (3×), fallback evidence paths (logs down → rely on flow metadata, lower max confidence to 0.6), budget exhaustion → escalate, malformed LLM output → re-prompt once then fall back to rule-only verdict.
- **Memory:** incident store (all traces), allow-list and override table, verdict history per source IP (a repeat offender raises prior confidence).
- **Human interaction:** chat panel bound to the incident (ask / steer / override), approval prompts, escalation tickets.

## 8. Demo scenarios (the test suite)

| # | Scenario | Expected verdict | Expected action | Adaptation shown |
|---|---|---|---|---|
| S1 | SQL injection against a patched app; WAF returns 403, DB logs clean | FAILED | none, watch-list | — (baseline) |
| S2 | Log4Shell-style JNDI exploit on a vulnerable version; outbound LDAP callback + spawned shell in logs | SUCCEEDED | block IP; approval prompt to isolate host (high criticality) | Attacker pivots to new IP after block → verifier sees new flows → new alert correlated → second block |
| S3 | SSH brute force; 240 failures then `Accepted password` for `svc-backup` | SUCCEEDED | block IP, escalate credential reset | Log service outage mid-investigation → retry → fallback to flow metadata → resume when logs return |
| S4 | Alert against an IP not in inventory (decommissioned host) | INCONCLUSIVE | escalate with missing evidence | Agent refuses to block on a label alone |
| S5 | Web shell upload confirmed; analyst then overrides: source is an authorised pentest | SUCCEEDED → OVERRIDDEN | block → unblock, exception recorded, ticket updated | Human override reverses action and revises report |
| S6 | Path traversal on a version listed "not affected"; mid-run the CVE KB marks it affected | FAILED → SUCCEEDED | none → block | Changed knowledge triggers re-investigation of logs |

Every scenario runs headless in the eval harness and live in the UI.

## 9. Requirements

### P0 — must have
| ID | Requirement | Acceptance criteria |
|---|---|---|
| R1 | Synthetic sandbox with the stores/tools in §6, scenario-driven | All 6 scenarios load from YAML/JSON; tools return consistent data; blocked IPs stop future flows |
| R2 | Controller loop with LLM planner and tool registry | Given S2, the agent makes ≥ 6 distinct tool calls, each logged with rationale; loop terminates ≤ 12 steps |
| R3 | Evidence ledger and persisted incident state | Killing and restarting the server resumes an incident from its last step |
| R4 | Verdict engine with deterministic gates | Rule-violating LLM verdicts are downgraded to INCONCLUSIVE; unit tests cover each rule |
| R5 | Action policy + simulated firewall actions | S1 never blocks; S2 blocks; critical-asset isolation waits for UI approval |
| R6 | Verifier after every action | Trace shows a verification step with the re-queried state; a failed verification re-enters the loop |
| R7 | Adaptation to environment events | S2 pivot, S3 outage, S5 override, S6 KB update each produce a visible reassessment and a changed plan |
| R8 | Escalation with missing-evidence list | S4 escalates and names the evidence that would resolve it |
| R9 | Web UI: alert queue, live trace (SSE), incident report, chaos panel, chat/override, approval prompts | Judge can run S2 end-to-end and inject a pivot without touching a terminal |
| R10 | Eval harness | `python -m eval` prints verdict accuracy, unsafe-action count, mean steps, adaptation success per scenario; results in README |
| R11 | Repo deliverables | Public GitHub, README with < 5-min setup, `.env.example`, architecture doc + diagram, Docker Compose |
| R12 | Demo video 3–5 min | Shows Goal → Decision → Action → Intermediate Result → Adaptation → Final Outcome on S2, plus S3 or S5 failure handling |

### P1 — nice to have
- Confidence calibration display (why 0.82?) with per-evidence weights.
- Cross-incident memory: repeat source IP raises prior; shown in trace.
- Analyst "ask for more evidence" command that pushes a specific tool call into the plan.
- Exportable incident report (Markdown/PDF) with MITRE ATT&CK technique tags.
- Hosted demo (Render/Fly/Railway) so judges need no local setup.

### P2 — future / design for it, don't build it
- Pluggable real connectors (Suricata EVE tail, Elastic, real firewall API) behind the same tool interfaces.
- Multiple concurrent incidents with priority scheduling.
- Learned evidence weights from analyst feedback.

## 10. Success metrics & evaluation

| Metric | Target | Measured by |
|---|---|---|
| Verdict accuracy | ≥ 90% | Eval harness, 6 scenarios × 10 runs |
| Unsafe actions (block on FAILED / allow-listed) | 0 | Eval harness |
| Actions verified | 100% | Trace audit |
| Adaptation success (scenario reaches correct final state after injection) | ≥ 90% | Eval harness |
| Mean steps per incident | ≤ 10 | Eval harness |
| Escalation precision (INCONCLUSIVE only when evidence truly missing) | ≥ 90% | Eval harness |
| Cold setup time | < 5 min | Dry run on a clean machine |
| Demo length | 3–5 min | Final cut |

## 11. Tech stack (proposed)

- **Backend:** Python 3.11, FastAPI, SQLite (via SQLModel), pydantic for tool schemas, SSE for live trace.
- **LLM:** provider TBD (open question). Native tool calling; JSON-schema structured outputs for verdicts. Abstract behind one `llm.py` so Stage 2 can swap models.
- **Frontend:** single-page vanilla JS or lightweight React (Vite). Three panes + chaos panel + chat.
- **Packaging:** Docker Compose, `Makefile`, `.env.example`.
- **Testing:** pytest for rules/tools; eval harness as a module.

## 12. Build plan

Assumes 4–5 working days and 2–4 people. Deadline is an open question; compress by cutting P1 first.

| Day | Deliverable | Definition of done |
|---|---|---|
| 1 — Sandbox | Data model, scenario loader, all tools as FastAPI routes + Python functions, S1–S6 scenario files, fault injection hooks | Tools pass unit tests; a script can walk S2 by hand |
| 2 — Agent core | Controller loop, planner with tool use, state store, verdict engine + rules, action policy, verifier | CLI runs S1–S6 headless with correct verdicts and actions |
| 3 — UI | Alert queue, live SSE trace, incident report, chaos panel, chat/override, approval prompts | S2 with pivot runs end-to-end in the browser |
| 4 — Robustness & docs | Retries/fallbacks/budget, eval harness, README, architecture doc + diagram, Docker Compose, hosted deploy if cheap | Clean-machine setup < 5 min; eval table in README |
| 5 — Submission | Demo video, presentation brief, dry-run Q&A, packaging under the naming convention | All files uploaded |

**Suggested roles (adjust to team size):** A — sandbox + scenarios; B — agent core + rules; C — UI + trace; D — eval, docs, video. Solo: follow the day order strictly and cut P1 entirely.

## 13. Submission checklist (Stage 1)

Naming convention: `<Teamname>_<Artifact>_agentic`, e.g. `Teamname_video_agentic`, `Teamname_Github_agentic`.

- [ ] Problem & solution brief (problem, users, why agentic, solution, impact) — derive from §1, §2, §7
- [ ] Architecture diagram covering controller, tools, external systems, memory/state, retrieval, planning, verification, human interaction, failure handling — §7 expanded
- [ ] Public GitHub repo: source, setup, dependencies, `.env.example`, README, `docs/ARCHITECTURE.md`
- [ ] 3–5 min demo video with one full workflow and at least one failure condition
- [ ] Runnable version: Docker Compose local run (+ hosted URL if P1 done)

## 14. Stage 2 readiness

Stage 2 is a live, unscripted agentic *chatbot* on a new problem. Design decisions that make the re-skin fast:
- Chat panel is the primary human interface from day one, not an afterthought.
- Tool registry + controller + verifier are domain-agnostic; only the sandbox, rules, and prompts are SOC-specific.
- `llm.py` is a single swap point; API keys and hardware are the team's responsibility on the day.
- Eval harness pattern (scenario files + assertions) can be rebuilt for a new domain in an hour.

## 15. Risks

| Risk | Mitigation |
|---|---|
| Synthetic logs look fake and judges discount them | Model formats on real Suricata EVE JSON, nginx access logs, Linux `auth.log`; include realistic noise |
| LLM planner loops or wanders | Step budget, "enough evidence" exit, rules-based verdict fallback |
| Live demo API outage | Cache LLM responses for the scripted scenarios as a fallback switch; keep a recorded video as backup only |
| Scope creep into SOAR features | Non-goals in §4; P1 only after all P0 pass |
| Over-blocking looks reckless to a security judge | Deterministic action gates, approval on critical assets, verifier, override path — make these visible in the trace |

## 16. Open questions

| Question | Owner | Blocking? |
|---|---|---|
| Which LLM provider/key will we use (Anthropic / OpenAI / Gemini / other)? | Team | Yes — day 2 |
| Team name (for file naming) and team size/roles? | Team | Yes — day 5 packaging, role split day 1 |
| Stage 1 submission deadline? | Team | Yes — sets the day count |
| PS9 says actions must stay inside the *provided* sandbox — will organisers ship one? If so, swap our synthetic backend for theirs behind the same tool registry. | Organisers (ask on the hackathon channel) | No — design already isolates it |
| Do we host a public demo or rely on Docker instructions only? | Team | No |
| Use real Suricata signature names/SIDs from the ET Open ruleset for realism? | Team | No |

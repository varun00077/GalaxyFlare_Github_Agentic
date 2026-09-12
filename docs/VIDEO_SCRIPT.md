# SOCrates — demo video scripts

Submission name: `GalaxyFlare_video_agentic` · target length 3:30–4:30 (hard limit 5:00)
Required beats: **Goal → Decision → Action → Intermediate Result → Adaptation → Final Outcome**, plus at least one
**failure / unexpected condition** and how the system responds.

Three cuts below: **A** is the submission. **B** is a 90-second version for socials or a backup. **C** is a
30-second "real machine" tag to append to A if there's time left under 5:00.

---

## Before recording (10 minutes)

1. `python -m uvicorn web.app:app --port 8000`, open http://localhost:8000 at 1920×1080, browser zoom 110%,
   dark OS theme, hide bookmarks bar. Close other tabs.
2. Key popover → Groq loaded, planner reads `groq · openai/gpt-oss-120b`. **Do not run anything for 2 minutes
   before recording** so all four model buckets are full (free tier: 8k tokens/min *per model*).
3. Environment switch = **SANDBOX**, scenario **s2**, click Load. Alert queue shows `alt-2001`.
4. Backup plan: if Groq is throttled on the day, *Key → Scripted planner*. The trace is identical in shape; say
   "scripted planner" once in narration and move on. Never fake it.
5. Record with system audio off, mic on; narrate live or dub after. Keep the cursor still while reading trace lines.

---

## Cut A — submission (≈4:10)

### 0:00 – 0:25 · Hook (title card over the idle console)

**On screen:** console with "Pick an alert" hero. Title card text: *SOCrates — an autonomous SOC agent that
decides whether an attack actually landed.*

**Narration:**
> A NIDS alert only proves that an attack was attempted. Working out whether it *succeeded* takes a Tier-1
> analyst fifteen to forty-five minutes of pulling logs, versions and advisories together. SOCrates is an
> agent that does that investigation itself — decides what evidence to fetch next, reaches an evidence-backed
> verdict, responds inside a sandbox only when the guardrails allow it, verifies the response, and changes its
> mind when the world or an analyst gives it a reason to. Everything you'll see runs against a synthetic
> environment; nothing touches a real network.

### 0:25 – 0:45 · Goal

**On screen:** hover the alert card `ET EXPLOIT Apache log4j RCE Attempt … 203.0.113.66 → 10.20.0.22`. Click **Run**.
The GOAL line appears in the trace.

**Narration:**
> The goal is set per alert: establish whether this Log4Shell attempt against app02 succeeded, respond
> safely, and verify the response. Watch the trace — every line is labelled Decision, Action, Result,
> Guardrail, Verify or Adapt.

### 0:45 – 1:35 · Decisions and intermediate results

**On screen:** let the trace run. Point at each DECISION as it lands: `get_alert` → `get_flow` → `get_asset` →
`lookup_cves(log4j-core 2.14.1)` → `search_playbooks` → `search_logs(outbound)` / `(process)` / `(app)`.
Point at the evidence ledger on the right filling with E1…E8; `VULNERABLE CVE-2021-44228` and
`post exploitation` chips.

**Narration:**
> The planner picks the next tool from what it has learned so far. The flow came back HTTP 200, so the payload
> was accepted. The asset record shows log4j-core 2.14.1 — it checks *that* library against the advisory KB
> and it's vulnerable. It retrieves the playbook for this technique, which says what success looks like:
> an outbound LDAP callback, java spawning a shell. Then it hunts exactly those in the host logs. Every line
> it finds is tagged into the evidence ledger — the verdict has to cite these.

*(If a purple "Planner switched to …" line appears, say: "That purple line is the agent adapting to a
rate-limited model — it rotates to another one and keeps going.")*

### 1:35 – 2:10 · Verdict, guardrails, action

**On screen:** hero flips to **SUCCEEDED** in red; the italic summary appears. Trace shows
`GUARDRAIL Verdict check passed`, `ACTION Filed assessment`, `GUARDRAIL Action permitted: block_ip`,
`ACTION Blocked 203.0.113.66 (rule fw-0001)`. Environment panel shows the firewall rule.

**Narration:**
> Verdict: SUCCEEDED, confidence 0.95. Now the guardrails — deterministic rules outside the LLM. They can only
> downgrade a verdict or refuse an action; they never choose one. SUCCEEDED requires real post-exploitation
> evidence — it has it. Blocking requires confidence above 0.7 and a source that isn't allow-listed — it is
> permitted. The agent blocks the attacker in the simulated firewall.

### 2:10 – 2:50 · Verification → Adaptation (the pivot)

**On screen:** `VERIFY rule effective for 203.0.113.66, but 1 new alert on the same host from 198.51.100.23`,
then purple `ADAPT Attacker pivot suspected: investigating alt-2002`. Approval bar appears for
`isolate host app02`. Click **Approve**. Trace: `HUMAN approved`, `ACTION Isolated host app02`, `VERIFY isolated=true`.

**Narration:**
> It doesn't trust its own action. The verifier re-queries the environment: the rule is in place, no traffic
> from that IP — but a new alert just hit the same host from a different address. That's an attacker pivot,
> and it re-enters the investigation. Meanwhile it wants to isolate the host: code execution on a high-value
> asset. Isolation always needs a human. I approve.

### 2:50 – 3:15 · Final outcome

**On screen:** second pass: `get_alert(alt-2002)`, log searches for `198.51.100.23`, `Blocked 198.51.100.23
(rule fw-0002)`, `VERIFY … no new alerts`, green **FINAL SUCCEEDED — blocked: 203.0.113.66, 198.51.100.23**.
Hero stats: confidence, steps, evidence, actions, LLM calls.

**Narration:**
> It correlates the follow-up, finds the same traces for the new source, blocks it, verifies again — clean —
> and closes. Eleven planner steps, two blocks, one isolation, every action verified, every claim backed by a
> line of evidence.

### 3:15 – 3:55 · Failure condition (scenario s3)

**On screen:** environment switch stays SANDBOX; scenario **s3** → Load → Run `alt-3001`. Let it hit the outage:
`ERROR search_logs failed after 3 attempts: log indexer unavailable`, purple `ADAPT Log service unavailable;
continuing with flow metadata…`, then `ADAPT Log service recovered`. Approval bar for `block_ip` on the
**critical** bastion → Approve. Ticket `Reset password for svc-backup`.

**Narration:**
> Now a failure. Same loop, an SSH brute force against a critical bastion — and the log service goes down
> mid-investigation. Three retries fail; the agent says so, caps its confidence, and continues with other
> sources instead of inventing certainty. When the indexer comes back it returns to the auth log and finds
> the accepted password. Because the asset is critical, even the block waits for approval. And it files a
> ticket a human can act on: reset the compromised account.

### 3:55 – 4:10 · Close

**On screen:** analyst chat: type `why did you block this?` → answer cites evidence ids. Cut to the
architecture diagram (docs/ARCHITECTURE.md) for 4 seconds. End card: repo URL, team name.

**Narration:**
> An analyst can ask it why, steer it, or override it — and the guardrails, verifier and human gate are what
> would let this run in a real SOC. Team Galaxy Flare, SOCrates. Thank you.

---

## Cut B — 90-second version

| Time | Screen | Say |
|---|---|---|
| 0:00 | Idle console | "An alert says an attack was attempted. SOCrates works out whether it *landed*." |
| 0:08 | Run s2, trace scrolling | "It decides what evidence to fetch next — flow, asset, advisory, host logs — and tags what it finds." |
| 0:35 | SUCCEEDED + block | "Verdict with evidence; guardrails outside the LLM permit the block." |
| 0:48 | VERIFY + ADAPT pivot | "It verifies its own action, spots the attacker pivot, and goes again." |
| 1:05 | Approve isolation, FINAL | "High-impact actions wait for a human. Both IPs blocked, verified, closed." |
| 1:20 | s3 outage line | "When a tool fails it says so and adapts — it never guesses." |
| 1:30 | End card | "Galaxy Flare · SOCrates." |

---

## Cut C — 30-second "this is real" tag (append to A only if under 5:00)

**On screen:** environment switch → **LIVE HOST**. Scenario shows `Live host: <your machine>`. Alert queue shows
the real Windows Defender detection. Run it. Trace: real process list, real Defender log lines, playbook,
**FAILED (0.95)** — "Defender quarantined the file before it ran".

**Narration:**
> Same agent, same guardrails, but the environment is now this laptop: real Windows event logs, live
> connections, installed software, advisories from NVD. This is a genuine Defender alert from earlier today.
> Seven steps later: the attack failed — Defender quarantined the file before anything ran. Correct verdict,
> and correctly no block.

*(Run this once before recording so the NVD/IP lookups are cached and the buckets are warm. If the Defender
alert isn't present on the recording machine, use the live chaos panel → FAILED LOGONS with the console
running elevated, and narrate a brute-force investigation instead.)*

---

## Editing notes

- Speed up log-scrolling segments to 1.5× if the total runs long; never speed up the verdict or approval moments.
- Add a 2-px highlight box around the trace line you're narrating; the kind labels are colour-coded already.
- Subtitles on — judges often watch muted.
- Show the LLM-calls stat once (≈ 11 calls, ~25k tokens for s2) when you say "eleven planner steps".
- File name on upload: `GalaxyFlare_video_agentic.mp4`.

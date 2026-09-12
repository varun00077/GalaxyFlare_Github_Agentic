# SOCrates — demo video script

Submission name: `GalaxyFlare_video_agentic` · target length 3:30–4:30 (hard limit 5:00)
Required beats: **Goal → Decision → Action → Intermediate Result → Adaptation → Final Outcome**, plus at least one
**failure / unexpected condition** and how the system responds.

The narration is written for a mixed audience: every technical term is replaced with a plain synonym or explained
in the same sentence. Keep it that way when you ad-lib. A cheat-sheet is at the end for Q&A.

---

## Before recording (10 minutes)

1. `python -m uvicorn web.app:app --port 8000`, open http://localhost:8000 at 1920×1080, browser zoom 110%,
   dark OS theme, hide the bookmarks bar, close other tabs.
2. Key popover: Groq loaded, planner reads `groq · openai/gpt-oss-120b`. **Run nothing for 2 minutes before
   recording** so all four model buckets are full (free tier: 8k tokens/min *per model*).
3. Environment switch = **SANDBOX**, scenario **s2**, click Load. Alert queue shows `alt-2001`.
4. Backup: if Groq is throttled on the day, *Key → Scripted planner*. The trace has the same shape; say
   "scripted planner" once and move on. Never fake it.
5. Mic on, system audio off. Keep the cursor still while reading a trace line.

---

## Cut S — 2:30, conversational (recommended narration)

Read at a relaxed pace. `…` = half a second, `(beat)` = a full second. Let each trace line land on screen before you name it.

**0:00 · Hook — idle console, title card**
> Hi. … Did you know that a company's network alarms go off *thousands* of times a day? (beat) And every single one of them only says "someone tried". … Not whether they actually got in. (beat) So today, a human analyst sits down and spends up to forty-five minutes … per alarm … figuring that out. … We built something that does it for them. It's called SOCrates.

**0:18 · Goal — click Run on the Log4Shell alert**
> So here's one alarm. Someone's trying to break into a server called app02, … through a known bug in a logging library. (beat) We give the agent one job: was this a real break-in? … If it was, respond — safely — and then *prove* the response worked. … Let's watch.

**0:32 · Investigating — trace runs; ledger fills**
> Now, the agent doesn't follow a script. Each step, it looks at what it just learned … and decides what to check next. (beat) First, the request itself — and the server said "200 OK". So the malicious request got *in*. … Then it looks the server up: which version of that library is running? … It checks that against a vulnerability database, and … yeah. That version has the bug. (beat) Next it pulls the playbook — that's the team's written guide for this kind of attack. And the playbook says: a real break-in leaves two fingerprints. The server calling *out* to the attacker … and a command shell being launched. (beat) So it goes looking for exactly those in the logs … and it finds both. … See the panel on the right? Every clue gets filed as numbered evidence. E1, E2, E3 … The verdict has to point at these.

**1:02 · Verdict + safety rules + block**
> And there's the verdict. … Succeeded. Ninety-five percent confidence. (beat) But — before it's allowed to *do* anything, there are safety rules. And these are plain code, … not AI. The AI can suggest; the rules can only say no. (beat) Rule one: you cannot say "succeeded" without real break-in evidence in the ledger. … It has it. Rule two: you can only block an address if you're confident *and* the address isn't on the trusted list. … Both true. (beat) So, … and only now … it blocks the attacker in the firewall — think of that as the network's gatekeeper.

**1:22 · Verify → pivot → approve**
> Here's my favourite part. … It doesn't trust itself. (beat) It goes back and checks: is the block actually in place? Yes. Any more traffic from that address? … No. But — (beat) a brand new alarm just fired. Same server. *Different* address. … The attacker switched machines. (beat) And the agent catches it, and reopens the case on its own. … At the same time, it wants to cut this server off the network completely. That's a big call — so it stops, … and asks a human. (beat) That's me. … Approve.

**1:45 · Final**
> So it chases the new address, finds the same fingerprints, blocks that one too, checks again … clean … and closes the case. (beat) Eleven decisions. Two blocks. Every action double-checked. Every claim tied to a line of evidence.

**1:58 · Failure — scenario s3**
> Okay. Now let's break something. (beat) Different alarm: someone's guessing passwords, over and over, on a critical server. … And halfway through — the log service goes down. (beat) The agent tries three times. Fails. … And it *says* so. It lowers its own confidence, keeps working with what it can still reach — and it never, ever fills the gap with a guess. (beat) When the service comes back, it goes straight back to the login records … and there it is. One password accepted. … Because this server's critical, even the block waits for a human. And it opens a ticket with one clear instruction: reset that account.

**2:20 · Close — chat, end card**
> So … that's SOCrates. Safety rules outside the AI. … Self-checks after every action. … And a human on the big calls. (beat) Team Galaxy Flare. Thanks for watching.

*If a purple "Planner switched to…" line appears:* "oh — and that purple line? The AI model hit its free-usage limit, so it swapped to another one and kept going." (+5 s)

---

## Cut S (table form) — 2:30 version

Same beats as Cut A, narration cut to ~370 words. Record s2 then s3 in one session.

| Time | Screen | Narration |
|---|---|---|
| 0:00 | Idle console, title card | Network alarm systems fire thousands of times a day, and every alarm only says "someone tried" — not whether they got in. Today a human analyst spends up to forty-five minutes per alarm finding that out. SOCrates does it itself. |
| 0:15 | Run the Log4Shell alert; GOAL line | One alarm: an attempt to break into server app02 through a known bug in a logging library. The agent's goal: did it succeed, respond safely, prove the response worked. |
| 0:25 | Trace: alert → flow → asset → CVE → playbook → logs; ledger E1–E8 | It picks each next step from what it just learned. The request was accepted — "200 OK". The server runs a version of the library that has the bug — confirmed against a vulnerability database. The playbook says a real break-in leaves two traces: the server calling out to the attacker, and a command shell being launched. It searches the logs for exactly those — and finds both. Every clue is filed as numbered evidence. |
| 0:55 | SUCCEEDED; guardrail lines; Blocked 203.0.113.66 | Verdict: succeeded, 95 percent confidence. Before it acts, safety rules — plain code, not AI — check the claim: is there real break-in evidence? Yes. Is confidence high and the address not on the trusted list? Yes. Only then does it block the attacker in the firewall — the network's gatekeeper. |
| 1:15 | VERIFY finds new alert; ADAPT pivot; Approve isolation | It doesn't trust its own action. It re-checks the network: the block holds — but a new alarm just hit the same server from a different address. The attacker switched machines, so the agent reopens the case. It also wants to cut the server off the network — a drastic step, so it stops and asks a human. I approve. |
| 1:40 | Second block, FINAL, stats | It finds the same traces for the new address, blocks it, verifies again, and closes: eleven decisions, two blocks, every action double-checked, every claim tied to evidence. |
| 1:55 | s3: ERROR → ADAPT unavailable → recovered → Approve → ticket | Now a failure. A password-guessing attack on a critical server — and mid-investigation the log service goes down. Three tries fail; the agent says so, lowers its confidence, keeps going with what it can reach, and never guesses. When the service returns it finds the proof: one password accepted. The block waits for a human because the server is critical, and it files a ticket: reset that account. |
| 2:20 | Chat "why did you block this?"; end card | Safety rules outside the AI, self-checks after every action, a human on the big calls. Team Galaxy Flare — SOCrates. |

Optional 10-second live tag before the close, if under time: *"And the same agent runs on this laptop's real
logs — it just investigated a genuine antivirus alert and correctly called it a failed attack."*

---

## Cut A — full-length version (≈4:15)

### 0:00 – 0:25 · Hook
**Screen:** idle console. Title card: *SOCrates — an AI agent that finds out whether a cyber-attack actually worked.*

> Companies run alarm systems on their networks. Every time something looks like an attack, an alarm fires —
> thousands a day. But an alarm only says "someone tried". It doesn't say whether they got in. Finding that out
> is a human job today: a security analyst spends fifteen to forty-five minutes per alarm digging through logs,
> software versions and vulnerability reports. SOCrates is an AI agent that does that digging itself. It decides
> what to check next, reaches a verdict it can prove with evidence, takes a safe response, checks that the
> response worked, and changes its mind when new information arrives. Everything you'll see runs against a
> simulated company network — nothing touches a real one.

### 0:25 – 0:45 · The goal
**Screen:** hover the alert card. Click **Run**. The GOAL line appears.

> Here's one alarm: an attempt to break into a server called app02 using a well-known bug in a logging
> library — the "Log4Shell" bug from 2021. We give the agent one goal: find out whether this attack succeeded,
> respond safely, and confirm the response worked. Watch the trace on screen. Every line is labelled — Decision
> means the agent chose something, Action means it did something, Verify means it double-checked, Adapt means
> it changed plan.

### 0:45 – 1:35 · Investigating
**Screen:** trace runs: `get_alert` → `get_flow` → `get_asset` → `lookup_cves` → `search_playbooks` →
`search_logs` ×3. Evidence ledger fills E1–E8.

> The agent picks its next step from what it has already learned. First it reads the network record of the
> request — the server answered "200 OK", so the malicious request was accepted, not rejected. Then it looks up
> the server in the inventory and sees the exact version of that logging library. It checks that version against
> a vulnerability database — and yes, this version has the bug. Next it pulls the response playbook for this kind
> of attack — a written guide that says what a successful break-in leaves behind: the server calling out to the
> attacker's machine, and the Java program launching a command shell. So it searches the server's logs for
> exactly those traces. Every matching line goes into the evidence ledger on the right, numbered E1, E2 and so on.
> The agent's final verdict has to point at these numbers.

*(If a purple "Planner switched to …" line appears:)*
> That purple line means the AI model we're using hit its free-usage limit — the agent switched to a different
> model and carried on without stopping.

### 1:35 – 2:10 · Verdict, safety rules, response
**Screen:** hero flips to **SUCCEEDED**; guardrail lines; `Blocked 203.0.113.66 (rule fw-0001)`. Firewall rule
appears in the environment panel.

> Verdict: the attack succeeded, with 95 percent confidence. Before anything happens, the verdict and the
> proposed response pass through the safety rules — plain if-then rules written in code, not AI. The AI can
> propose; the rules can only say no. Rule one: you can't declare "succeeded" unless the ledger contains actual
> traces of the break-in — it does. Rule two: you can only block an address if confidence is high and the
> address isn't on the trusted list — both true. So the agent blocks the attacker's address in the simulated
> firewall — the network's gatekeeper.

### 2:10 – 2:50 · Checking its own work → adapting
**Screen:** `VERIFY … but 1 new alert on the same host from 198.51.100.23` → purple `ADAPT Attacker pivot
suspected`. Approval bar appears. Click **Approve**.

> It doesn't assume the block worked. It goes back and checks: is the rule in place? Yes. Any more traffic from
> that address? None. But — a new alarm has just fired on the same server from a *different* address. The
> attacker has switched machines. The agent recognises this and reopens the investigation. At the same time it
> wants to cut the compromised server off from the network entirely — a drastic step, so the system stops and
> asks a human. That's me. I approve.

### 2:50 – 3:15 · Final outcome
**Screen:** second pass on `alt-2002`; `Blocked 198.51.100.23 (rule fw-0002)`; green FINAL. Point at the stats
row (confidence, steps, evidence, actions, LLM calls).

> It reads the new alarm, finds the same traces for the new address, blocks that one too, checks again — clean —
> and closes the case. Eleven decisions, two blocks, one server quarantined, every action double-checked, every
> claim backed by a numbered line of evidence.

### 3:15 – 3:55 · When things go wrong
**Screen:** scenario **s3** → Load → Run. `ERROR search_logs failed after 3 attempts` → purple `ADAPT Log service
unavailable…` → `ADAPT Log service recovered`. Approval for the block → **Approve**. Ticket: *Reset password for
svc-backup*.

> Now let's break something. Same agent, a different alarm: someone guessing passwords over and over on the
> company's main gateway server. Half-way through, the log search service goes down. The agent tries three
> times, fails, and says so out loud. It lowers its own confidence and keeps working with the evidence it can
> still reach — it never fills the gap with a guess. When the log service comes back, it returns to the login
> records and finds the proof: after two hundred and forty failed attempts, one password was accepted. Because
> this server is marked critical, even the block needs a human's OK. And it opens a ticket with a clear
> instruction for the team: reset that account's password.

### 3:55 – 4:15 · Close
**Screen:** chat → `why did you block this?` → answer citing E-numbers. Architecture diagram for 4 s. End card:
repo URL, *Team Galaxy Flare*.

> At any point an analyst can ask the agent why, steer it, or overrule it. Those three things — safety rules
> outside the AI, self-checking after every action, and a human in charge of the big decisions — are what would
> let this run in a real security team. Team Galaxy Flare. SOCrates. Thank you.

---

## Optional 30-second tag — real machine (append only if under 5:00)

**Screen:** environment switch → **LIVE HOST**. Alert queue shows the real Windows Defender detection. Run it.
Trace: real process list, real Defender log lines, playbook, **FAILED (0.95)**.

> One more thing. Same agent, but now the "network" is this laptop — real Windows logs, real running programs,
> real vulnerability data from the US government's database. This is a genuine antivirus alert from earlier
> today. Seven steps later the agent concludes: the attack failed — the antivirus quarantined the file before it
> could run. Right answer, and correctly, it blocks nothing.

*(Run it once before recording so lookups are cached. If the Defender alert isn't on the recording machine,
run the console elevated and use the live chaos panel → FAILED LOGONS to create a real password-guessing alarm.)*

---

## Cut B — 90-second version

| Time | Screen | Say |
|---|---|---|
| 0:00 | Idle console | "An alarm says someone tried to break in. SOCrates finds out whether they actually got in." |
| 0:08 | Run s2, trace scrolling | "It decides what to check next — the request, the server, the vulnerability database, the logs — and files every clue as numbered evidence." |
| 0:35 | SUCCEEDED + block | "Verdict with proof. Safety rules written in plain code — not AI — decide whether it may block." |
| 0:48 | VERIFY + ADAPT pivot | "It checks its own work, notices the attacker switched machines, and goes again." |
| 1:05 | Approve isolation, FINAL | "Drastic steps wait for a human. Both addresses blocked, verified, case closed." |
| 1:20 | s3 outage line | "When a tool breaks it says so and adapts — it never guesses." |
| 1:30 | End card | "Galaxy Flare · SOCrates." |

---

## Jargon cheat-sheet (for the narrator and Q&A)

| Plain word used on camera | What it actually is |
|---|---|
| alarm / alert | a network intrusion-detection system (Suricata) flagging suspicious traffic |
| the Log4Shell bug | CVE-2021-44228, a flaw in the Log4j logging library that lets attackers run code remotely |
| inventory / server record | asset inventory: which servers exist and what software versions they run |
| vulnerability database | CVE advisories (synthetic copy in the sandbox; NVD in live mode) |
| playbook | the security team's written response guide for one type of attack |
| traces of a break-in | post-exploitation evidence: outbound callbacks, spawned shells, accepted logins |
| the gatekeeper / firewall | the network firewall that can drop traffic from an address |
| cut the server off / quarantine | host isolation |
| attacker switched machines | pivot to a new source address after being blocked |
| gateway server | the bastion host that fronts internal access |
| safety rules | deterministic guardrails in `agent/rules.py`, applied after the LLM's proposal |
| double-check | the verifier re-querying the environment after every action |

## Editing notes

- 1.5× only on log-scrolling stretches; never on the verdict or approval moments.
- Highlight box around the trace line being narrated; the kind labels are colour-coded already.
- Subtitles on — judges often watch muted.
- Show the LLM-calls stat once when saying "eleven decisions".
- Export as `GalaxyFlare_video_agentic.mp4`.

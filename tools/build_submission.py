"""Build the all-in-one submission folder.

    python tools/build_submission.py [--out <dir>] [--vercel-url <url>]

Produces <out>/ (default: ../GalaxyFlare_Submission_Agentic next to the repo):
  00_README.txt                                   index of the folder
  01_Brief/GalaxyFlare_Brief_Agentic.pdf          problem & solution brief
  02_Architecture/GalaxyFlare_Architecture_Agentic.pdf (+ .png diagram)
  03_Source/GalaxyFlare_Github_Agentic.zip        git archive of HEAD (never the working tree, so .env cannot leak)
  03_Source/GITHUB_LINK.txt
  04_Video/                                       script + drop the recorded GalaxyFlare_Video_Agentic.mp4 here
  05_Deployed/GalaxyFlare_Deployed_Agentic.pdf    hosted URL + how to run locally
Then scans every text file in the folder (and the zip) for credential patterns.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEAM = "Galaxy Flare"
REPO_URL = "https://github.com/varun00077/GalaxyFlare_Github_Agentic"
SECRET_PATTERNS = [r"AIza[0-9A-Za-z_\-]{20,}", r"AQ\.[0-9A-Za-z_\-]{30,}", r"gsk_[0-9A-Za-z]{20,}", r"sk-[0-9A-Za-z]{20,}",
                   r"(?i)api[_-]?key\s*[:=]\s*['\"]?[0-9A-Za-z_\-]{24,}", r"ghp_[0-9A-Za-z]{30,}"]


# ---------------------------------------------------------------- diagram
def draw_architecture(png: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

    fig, ax = plt.subplots(figsize=(14, 8), dpi=170)
    ax.set_xlim(0, 140); ax.set_ylim(0, 80); ax.axis("off")
    ink, muted, accent, ok, adapt, human = "#1b1b1f", "#6b6f7a", "#b58900", "#1f8f5f", "#6f4bd8", "#c2427a"

    def box(x, y, w, h, title, lines=(), fc="#f7f7f5", ec=ink, lw=1.2, ts=10.5):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", fc=fc, ec=ec, lw=lw))
        ax.text(x + w / 2, y + h - 2.6, title, ha="center", va="center", fontsize=ts, weight="bold", color=ink)
        for i, ln in enumerate(lines):
            ax.text(x + 1.6, y + h - 5.6 - i * 2.9, ln, ha="left", va="center", fontsize=8.2, color=muted)

    def arrow(p, q, color=ink, label=None, at=None, lw=1.3, rad=0.0, ha="center"):
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=12, color=color, lw=lw, connectionstyle=f"arc3,rad={rad}"))
        if label:
            lx, ly = at if at else ((p[0] + q[0]) / 2, (p[1] + q[1]) / 2 + 1.4)
            ax.text(lx, ly, label, ha=ha, va="center", fontsize=7.6, color=color, bbox=dict(fc="white", ec="none", pad=0.6))

    # left column: inputs
    box(2, 62, 24, 14, "NIDS alert", ["Suricata EVE record", "signature, src/dst, flow id"], fc="#fff7e0")
    box(2, 40, 24, 17, "Environment events", ["new alert (attacker pivot)", "advisory revised", "tool outage", "analyst override"], fc="#f1ecff", ec=adapt, ts=10)
    box(2, 17, 24, 18, "Human analyst", ["approve / deny", "override (unblock, revise)", "chat: ask, steer, reopen"], fc="#fdeef4", ec=human)

    # centre: controller loop
    ax.add_patch(FancyBboxPatch((32, 12), 54, 64, boxstyle="round,pad=0.6,rounding_size=2", fc="#fbfbfa", ec=ink, lw=1.6, ls="--"))
    ax.text(59, 73.5, "Controller loop  (agent/controller.py)", ha="center", fontsize=11, weight="bold", color=ink)
    box(35, 52, 21, 15, "1  Observe", ["incident state", "evidence ledger", "drained events"])
    box(62, 52, 21, 15, "2  Plan  (LLM)", ["Groq / Gemini", "native function calling", "one tool per step"], fc="#fff7e0", ec=accent)
    box(62, 31, 21, 15, "3  Act", ["tool call over HTTP", "retries + backoff", "model rotation on 429"])
    box(35, 31, 21, 15, "4  Tag evidence", ["CVE success indicators", "generic post-exploit / block", "E1, E2, ... ledger"])
    box(35, 14, 48, 12, "5  Gates + action policy  (agent/rules.py)",
        ["deterministic: may downgrade, cap, refuse or gate - never choose"], fc="#eef7f2", ec=ok, ts=10)
    arrow((56, 59.5), (62, 59.5)); arrow((72.5, 52), (72.5, 46)); arrow((62, 38.5), (56, 38.5)); arrow((45.5, 46), (45.5, 52)); arrow((72.5, 31), (72.5, 26), color=ok)

    # right column: environment, retrieval, verifier, store
    box(93, 62, 44, 14, "Retrieval", ["BM25 over playbooks + advisories", "playbook = evidence plan per technique"])
    box(93, 42, 44, 16, "Sandbox / live environment  (HTTP API)",
        ["alerts, flows, asset inventory, CVE KB, host logs", "firewall, host isolation, tickets, allow-list", "live/: Windows logs, NVD, IP reputation"], ts=10)
    box(93, 22, 44, 15, "Verifier  (agent/verifier.py)", ["rule present?  flows since?  new alerts on host?", "failed check or pivot -> re-enter the loop"], fc="#eef7f2", ec=ok)
    box(93, 3, 44, 14, "Incident store + trace", ["SQLite locally / state in the browser on Vercel", "goal - decision - action - result - adaptation - final"])

    arrow((26, 69), (35, 63), label="goal", at=(29, 68.5))
    arrow((26, 48), (35, 55), color=adapt, label="re-plan", at=(27.5, 52.6), ha="left")
    arrow((26, 26), (35, 21), color=human, label="approval", at=(28.5, 21.5), ha="left")
    arrow((83, 62), (93, 69), label="playbook query", at=(86, 68))
    arrow((83, 38.5), (93, 50), label="tool calls", at=(84.5, 47), ha="left")
    arrow((83, 17), (93, 25), color=ok, label="actions", at=(85.2, 19.6), ha="left")
    arrow((93, 39.5), (86, 39.5), color=adapt, label="verification result", at=(86.5, 41.3), ha="left")
    arrow((86, 8), (93, 8), color=muted, label="persist every step", at=(85, 5.5), ha="left")
    ax.text(59, 8, "LLM plans and proposes.  Rules decide what is safe.", ha="center", fontsize=9.2, color=ink, style="italic")
    ax.text(59, 4.5, "Verifier checks the world.  Human overrides win.", ha="center", fontsize=9.2, color=ink, style="italic")
    fig.savefig(png, bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ---------------------------------------------------------------- PDF helpers
def _styles():
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1x", parent=ss["Heading1"], fontSize=20, spaceAfter=6, textColor="#1b1b1f"))
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], fontSize=13.5, spaceBefore=12, spaceAfter=4, textColor="#1b1b1f"))
    ss.add(ParagraphStyle("Bodyx", parent=ss["BodyText"], fontSize=10, leading=14, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], fontSize=8.5, leading=11, textColor="#555"))
    ss.add(ParagraphStyle("Mono", parent=ss["Code"], fontSize=8.2, leading=10.5))
    return ss


def _pdf(path: Path, story_fn) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                            title=path.stem, author=f"Team {TEAM}")
    doc.build(story_fn(_styles()))


def _table(data, widths, ss, header=True):
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle
    rows = [[Paragraph(str(c), ss["Small"]) for c in r] for r in data]
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#efefec"))]
    t.setStyle(TableStyle(style))
    return t


# ---------------------------------------------------------------- documents
def brief(path: Path, vercel_url: str) -> None:
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer

    def story(ss):
        P = lambda t, s="Bodyx": Paragraph(t, ss[s])  # noqa: E731
        S = [
            P("SOCrates — Problem &amp; Solution Brief", "H1x"),
            P(f"Team {TEAM} · Agentic AI Hackathon, Tech Zephyr 4.0 (IIT Bhubaneswar) · Track 5 Cybersecurity · Problem Statement 9: "
              "Autonomous SOC Investigation &amp; Response Agent", "Small"),
            Spacer(1, 8),
            P("1. The problem", "H2x"),
            P("A network intrusion-detection system (NIDS) raises an alert for every request that <i>looks like</i> an attack. An alert "
              "only proves an attempt; it says nothing about whether the attack landed. Deciding that is manual work: a Tier-1 analyst "
              "pulls the packet record, checks what software the target runs, looks the version up against advisories, reads the host's "
              "own logs, and only then knows whether to block, escalate or ignore. It takes 15–45 minutes per alert, and busy SOCs receive "
              "thousands of alerts a day. Two failure modes follow: real compromises wait in a queue, and analysts block on the alert label "
              "alone — cutting off legitimate traffic and authorised tests."),
            P("2. The solution", "H2x"),
            P("SOCrates is an agent that takes one alert and works it like an analyst would: it decides which evidence to fetch next "
              "(flow metadata, asset inventory, CVE knowledge base, host logs, response playbooks), tags what it finds into an evidence "
              "ledger, reaches an evidence-backed verdict — <b>SUCCEEDED / FAILED / INCONCLUSIVE</b> — proposes a response, takes it inside "
              "a sandboxed environment only when deterministic guardrails allow, verifies that the response took effect, and adapts when the "
              "environment or an analyst changes the picture. Every step is written to a trace an analyst can read and challenge."),
            P("3. How it works", "H2x"),
            _table([
                ["Stage", "What happens", "Where"],
                ["Goal", "Per alert: establish whether the attack succeeded, respond safely, verify the response.", "agent/controller.py"],
                ["Decision", "The LLM planner (Groq gpt-oss-120b or Gemini, native function calling) picks the next tool from the current ledger.", "agent/llm.py, agent/llm_openai.py"],
                ["Action", "Tool call over HTTP with retries, provider retry-after hints and model rotation when rate-limited.", "agent/tools.py"],
                ["Intermediate result", "Results are tagged deterministically (CVE success indicators, post-exploitation and block signatures) into E1, E2, …", "agent/evidence.py"],
                ["Verdict gates", "SUCCEEDED needs post-exploitation evidence; FAILED needs a block/reject or a non-vulnerable version; unknown asset forces INCONCLUSIVE; degraded evidence caps confidence.", "agent/rules.py"],
                ["Action policy", "Block only on SUCCEEDED with confidence ≥ 0.7 and a non-allow-listed source; critical assets and host isolation need approval; INCONCLUSIVE escalates with the missing evidence named.", "agent/rules.py"],
                ["Verification", "After every block: rule present? flows since? new alerts on the host? A failure or a correlated new alert re-enters the loop.", "agent/verifier.py"],
                ["Adaptation", "Attacker pivot, tool outage, analyst override and revised advisories are handled as environment events that reopen or re-plan.", "controller event drain"],
            ], [2.6 * cm, 10.2 * cm, 4.2 * cm], ss),
            P("4. What makes it agentic rather than a prompt chain", "H2x"),
            P("The branching is data-dependent: the planner chooses tools from the ledger, so a patched server and a compromised one take "
              "different paths (7–17 tool calls across five systems). The LLM plans and proposes; deterministic rules can only downgrade a "
              "verdict, cap confidence, refuse or gate an action — they never pick one. The verifier re-queries the world after every action. "
              "Humans approve high-impact steps, override the agent (which then unblocks and revises its assessment), and can ask it why."),
            P("5. Evidence that it works", "H2x"),
            P("Six scripted scenarios double as the demo and the evaluation suite: a failed SQLi (no block on the label), a successful Log4Shell "
              "with an attacker pivot after the first block, an SSH brute force on a critical bastion while the log service fails, an alert on a "
              "host missing from inventory, a confirmed web shell that turns out to be an authorised pentest, and a verdict that flips when an "
              "advisory is revised. Offline evaluation with the scripted planner: verdict accuracy 1.0, unsafe actions 0, all actions verified, "
              "adaptation success 1.0. With the real Groq planner: 6/6 verdicts correct, 0 unsafe actions, ~7–11 planner calls and 15–28k tokens "
              "per incident. In <b>live host mode</b> the same agent runs against the machine it is on (Windows event logs, live connections, "
              "installed software, NVD advisories, IP reputation); it investigated a genuine Windows Defender detection in 7 steps and correctly "
              "concluded FAILED — the file was quarantined before it ran."),
            P("6. Safety and limits", "H2x"),
            P("All response actions target a simulated environment; in live mode, firewall changes are dry-run unless the service runs elevated "
              "with LIVE_ACTIONS=1, private addresses are refused, and isolating the local host is never permitted. Free-tier LLM rate limits are "
              "the main operational constraint; the agent survives them (rotation, compaction, waits) but a paid tier would make it faster. "
              "The evidence tagger's indicator library is small and would grow per environment in production. No credentials are stored in the "
              "repository; keys come from environment variables or a browser-held key sent per request."),
            P("7. Deliverables", "H2x"),
            _table([
                ["Artifact", "Name / location"],
                ["Source code", f"GalaxyFlare_Github_Agentic — {REPO_URL}"],
                ["Deployed version", vercel_url or "Vercel (stateless mode) — see 05_Deployed"],
                ["Demo video", "GalaxyFlare_Video_Agentic.mp4 (3–5 min) — see 04_Video"],
                ["Architecture", "GalaxyFlare_Architecture_Agentic.pdf — see 02_Architecture"],
            ], [4 * cm, 13 * cm], ss),
        ]
        return S
    _pdf(path, story)


def architecture(path: Path, png: Path) -> None:
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, Paragraph, Spacer

    def story(ss):
        P = lambda t, s="Bodyx": Paragraph(t, ss[s])  # noqa: E731
        img = Image(str(png)); ratio = img.imageHeight / img.imageWidth
        img.drawWidth = 17 * cm; img.drawHeight = 17 * cm * ratio
        return [
            P("SOCrates — System Architecture &amp; Workflow", "H1x"),
            P(f"Team {TEAM} · PS9 Autonomous SOC Investigation &amp; Response Agent", "Small"),
            Spacer(1, 6), img, Spacer(1, 6),
            P("1. Components", "H2x"),
            _table([
                ["Box in the brief", "Module", "Responsibility"],
                ["Agent / controller", "agent/controller.py", "One loop: drain events → budget check → plan → act + tag → conclude → gate → act → verify → persist"],
                ["Planning", "agent/llm.py, agent/llm_openai.py", "Groq (OpenAI-compatible) and Gemini planners with native tool calling; conversation rebuilt from history each step with compaction; scripted MockLLM for offline tests"],
                ["Tools", "agent/tools.py", "Tool declarations for the planner (read-only evidence tools + conclude) and the HTTP client used for everything, including actions the planner may not call directly"],
                ["External systems", "sandbox/", "Alert feed, flows, asset inventory, CVE KB, host logs, firewall, host control, tickets, allow-list; scripted triggers and faults make adaptation reproducible"],
                ["Retrieval", "sandbox/retrieval.py", "BM25 over playbooks and advisories; the playbook's evidence plan drives what to search"],
                ["Memory / state", "agent/state.py", "Incident: evidence ledger, history, trace, actions, overrides; SQLite locally, browser-held state on Vercel"],
                ["Evaluation / verification", "agent/rules.py, agent/verifier.py, eval/", "Verdict gates, action policy, post-action verification, scenario scoring harness"],
                ["Human interaction", "web/, agent/chat.py", "Approvals, overrides, chat (questions, /override, /reopen), chaos panel"],
                ["Failure handling", "tools client, controller, planners", "Retries with provider hints, model rotation under rate limits, request-size compaction, loop guard, step budget, rule-only fallback, escalation instead of guessing"],
                ["Real-world path", "live/", "Same API served from the Windows host: event logs, live connections, installed software, NVD, IP reputation"],
            ], [3.3 * cm, 4.2 * cm, 9.5 * cm], ss),
            P("2. Workflow for one alert", "H2x"),
            P("1. <b>Observe</b>: drain environment events (new alert, override, advisory revised); a knowledge change bumps the epoch so lookups are redone. "
              "2. <b>Plan</b>: the LLM sees the full history and ledger and returns one tool call or a conclusion. "
              "3. <b>Act</b>: the tool runs with three retries; results are <b>tagged</b> into evidence with ids. "
              "4. <b>Conclude → gate</b>: the verdict is checked against the ledger and can only be downgraded; the assessment is filed. "
              "5. <b>Policy</b>: the proposed response becomes gated actions (block, isolate, watch-list, escalate) with approval where required. "
              "6. <b>Verify</b>: the firewall and alert feed are re-queried; a failed check or a correlated new alert re-enters the loop. "
              "7. <b>Persist</b>: state and trace are saved after every step so a paused or crashed run resumes."),
            P("3. Adaptation paths demonstrated", "H2x"),
            _table([
                ["Scenario", "Unexpected condition", "Response"],
                ["s2 Log4Shell", "attacker returns from a second IP after the block", "verifier surfaces the alert → pivot investigated → second block, host isolation with approval"],
                ["s3 SSH brute force", "log indexer returns 503 mid-investigation", "retries → continue with other sources, confidence capped → resume when logs return; critical asset gate; credential-reset ticket"],
                ["s4 unknown asset", "target not in inventory", "INCONCLUSIVE, escalate with the missing evidence; no block on the label"],
                ["s5 web shell", "analyst: source is an authorised pentest", "unblock, release host, exception recorded, assessment revised to OVERRIDDEN"],
                ["s6 path traversal", "advisory revised after a FAILED verdict", "incident reopened, vulnerability re-checked, verdict flips to SUCCEEDED, block"],
                ["any", "planner rate-limited / request too large", "rotate across models, honor retry-after, compact context; every wait is visible in the trace"],
            ], [3 * cm, 5.5 * cm, 8.5 * cm], ss),
            P("4. Deployment topologies", "H2x"),
            P("<b>Local</b>: one process serves the console, runs the controller in a worker thread per incident, streams the trace over SSE and "
              "persists to SQLite; the sandbox runs in-process over HTTP semantics or as a separate service (SANDBOX_URL). "
              "<b>Vercel (stateless)</b>: each request carries the incident and a snapshot of the sandbox, streams the trace, and hands the state "
              "back to the browser at approvals or when the request time budget runs out; the browser resumes it. "
              "<b>Live host</b>: the live/ backend replaces the sandbox behind the same API; actions are dry-run unless elevated."),
        ]
    _pdf(path, story)


def deployed(path: Path, vercel_url: str) -> None:
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer

    def story(ss):
        P = lambda t, s="Bodyx": Paragraph(t, ss[s])  # noqa: E731
        return [
            P("SOCrates — Runnable / Deployed Version", "H1x"),
            P(f"Team {TEAM} · PS9", "Small"), Spacer(1, 6),
            P("Hosted demo", "H2x"),
            P(f"<b>{vercel_url or 'https://<your-vercel-project>.vercel.app'}</b> — stateless mode on Vercel. Pick a scenario, click Run on an alert, "
              "approve when asked. Bring your own planner key with the <b>Key</b> button (sent per request, never stored server-side) or rely on the "
              "deployment's environment variables. Live host mode is local-only."),
            P("Run locally (2 minutes)", "H2x"),
            P("Python 3.11+. No credentials in the repository; put a Groq or Gemini key in <b>.env</b> (see .env.example) or paste it in the console.", "Bodyx"),
            Paragraph("git clone " + REPO_URL + "<br/>cd GalaxyFlare_Github_Agentic<br/>python -m venv .venv &amp;&amp; .venv\\Scripts\\activate<br/>"
                      "pip install -r requirements.txt<br/>copy .env.example .env      # add GROQ_API_KEY (or GEMINI_API_KEY)<br/>"
                      "python -m uvicorn web.app:app --port 8000     # open http://localhost:8000", ss["Mono"]),
            Spacer(1, 6),
            P("Other entry points", "H2x"),
            Paragraph("python -m agent.cli run --scenario s2 --llm mock --auto-approve   # full loop offline in seconds<br/>"
                      "python -m agent.cli run --scenario s3 --llm groq                  # real planner, approvals prompted<br/>"
                      "python -m eval --llm groq                                         # score all six scenarios<br/>"
                      "python -m pytest                                                  # 34 tests, no network<br/>"
                      "ENVIRONMENT=live python -m uvicorn web.app:app --port 8000        # live host mode (Windows)", ss["Mono"]),
            Spacer(1, 6),
            P("Docker", "H2x"),
            P("<font face='Courier'>docker compose up</font> starts the sandbox (8001) and the console (8000)."),
        ]
    _pdf(path, story)


# ---------------------------------------------------------------- packaging
def git_archive(zip_path: Path) -> None:
    subprocess.run(["git", "archive", "--format=zip", "-o", str(zip_path), "--prefix=GalaxyFlare_Github_Agentic/", "HEAD"], cwd=ROOT, check=True)


def scan_secrets(folder: Path) -> list[str]:
    hits: list[str] = []
    pats = [re.compile(p) for p in SECRET_PATTERNS]

    def check(name: str, text: str) -> None:
        for p in pats:
            for m in p.finditer(text):
                hits.append(f"{name}: {m.group(0)[:12]}…")
    for f in folder.rglob("*"):
        if f.is_dir():
            continue
        if f.suffix == ".zip":
            with zipfile.ZipFile(f) as z:
                for n in z.namelist():
                    if n.endswith(("/", ".png", ".pdf", ".db")):
                        continue
                    try:
                        check(f"{f.name}:{n}", z.read(n).decode("utf-8", "ignore"))
                    except Exception:
                        pass
        elif f.suffix in (".txt", ".md", ".py", ".json", ".js", ".html", ".css", ".yml", ".toml"):
            check(f.name, f.read_text(encoding="utf-8", errors="ignore"))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT.parent / "GalaxyFlare_Submission_Agentic"))
    ap.add_argument("--vercel-url", default="https://galaxy-flare-socrates.vercel.app/")
    a = ap.parse_args()
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    for d in ("01_Brief", "02_Architecture", "03_Source", "04_Video", "05_Deployed"):
        (out / d).mkdir(parents=True)

    png = out / "02_Architecture" / "GalaxyFlare_Architecture_Agentic.png"
    draw_architecture(png)
    brief(out / "01_Brief" / "GalaxyFlare_Brief_Agentic.pdf", a.vercel_url)
    architecture(out / "02_Architecture" / "GalaxyFlare_Architecture_Agentic.pdf", png)
    shutil.copy(ROOT / "docs" / "ARCHITECTURE.md", out / "02_Architecture" / "ARCHITECTURE.md")
    git_archive(out / "03_Source" / "GalaxyFlare_Github_Agentic.zip")
    (out / "03_Source" / "GITHUB_LINK.txt").write_text(f"{REPO_URL}\n\nZip = git archive of the main branch at submission time (no .env, no keys).\n", encoding="utf-8")
    shutil.copy(ROOT / "docs" / "VIDEO_SCRIPT.md", out / "04_Video" / "VIDEO_SCRIPT.md")
    (out / "04_Video" / "PLACE_VIDEO_HERE.txt").write_text(
        "Record Cut A from VIDEO_SCRIPT.md (about 4:15 - the rules require 3 to 5 minutes; the 2:00 and 2:30 cuts are too short).\n"
        "Save the file here as: GalaxyFlare_Video_Agentic.mp4\n", encoding="utf-8")
    deployed(out / "05_Deployed" / "GalaxyFlare_Deployed_Agentic.pdf", a.vercel_url)
    (out / "00_README.txt").write_text(
        f"Team {TEAM} - SOCrates - Autonomous SOC Investigation & Response Agent (Track 5, PS9)\n\n"
        "01_Brief/         GalaxyFlare_Brief_Agentic.pdf           Problem & Solution Brief\n"
        "02_Architecture/  GalaxyFlare_Architecture_Agentic.pdf    System architecture & workflow (+ diagram PNG, ARCHITECTURE.md)\n"
        "03_Source/        GalaxyFlare_Github_Agentic.zip          Source code (git archive) + GITHUB_LINK.txt\n"
        "04_Video/         GalaxyFlare_Video_Agentic.mp4           3-5 minute demo video (+ script)\n"
        "05_Deployed/      GalaxyFlare_Deployed_Agentic.pdf        Hosted URL and how to run locally\n\n"
        f"Repository: {REPO_URL}\nDeployed:   {a.vercel_url}\n\n"
        "No API keys, passwords or tokens are included anywhere in this folder.\n", encoding="utf-8")

    hits = scan_secrets(out)
    print(f"built {out}")
    for f in sorted(out.rglob("*")):
        if f.is_file():
            print(f"  {f.relative_to(out)}  ({f.stat().st_size // 1024} KB)")
    if hits:
        print("SECRET SCAN: FOUND", *hits, sep="\n  ")
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

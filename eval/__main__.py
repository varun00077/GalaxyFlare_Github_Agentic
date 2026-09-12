"""Evaluation harness: run every scenario N times and score the agent against ground truth.

  python -m eval                       # mock planner, 1 run each (offline, seconds)
  python -m eval --llm groq --runs 3   # real planner; per-run traces land in eval/traces/

Metrics (PRD section 10): verdict accuracy, unsafe actions, actions verified, adaptation
success, mean steps, escalation precision. Results go to eval/results.json and stdout.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

from agent.controller import Controller
from agent.llm import make_llm
from agent.state import Incident
from agent.tools import SandboxClient
from sandbox.world import list_scenarios


def score(inc: Incident, truth: dict[str, Any]) -> dict[str, Any]:
    exp = truth["expected"]
    verdict = (inc.verdict or {}).get("verdict")
    blocked = set(truth["blocked_ips"])
    unsafe = blocked & set(exp.get("unsafe_block_ips", []))
    unsafe |= blocked & set(truth.get("allowlist", []))
    verified = [t for t in inc.trace if t.kind == "verification"]
    block_actions = [a for a in inc.actions if a["type"] == "block_ip"]
    adapt_ok = True
    if "assessment_sequence" in exp:
        seq = [a["verdict"] for a in truth["assessments"]]
        adapt_ok = seq[: len(exp["assessment_sequence"])] == exp["assessment_sequence"] or seq == exp["assessment_sequence"]
    if exp.get("allowlisted_ips"):
        adapt_ok = adapt_ok and set(exp["allowlisted_ips"]) <= set(truth["allowlist"])
    escalated = len(truth["tickets"]) > 0
    # Escalation precision (PRD): INCONCLUSIVE only when evidence is truly missing, and a ticket whenever one is
    # required. An extra IR ticket on a correct SUCCEEDED verdict is not a miss.
    esc_ok = escalated if exp.get("escalated", False) else (verdict != "INCONCLUSIVE")
    return {
        "verdict": verdict,
        "verdict_ok": verdict == exp["verdict"],
        "blocked_ips": sorted(blocked),
        "blocks_ok": blocked == set(exp["blocked_ips"]),
        "unsafe_actions": sorted(unsafe),
        "escalated": escalated,
        "escalation_ok": esc_ok,
        "actions_verified": len(verified) >= len(block_actions),
        "adaptations": sum(1 for t in inc.trace if t.kind == "adaptation"),
        "adaptation_ok": adapt_ok and blocked == set(exp["blocked_ips"]),
        "steps": inc.steps,
        "status": inc.status,
        "evidence": len(inc.evidence),
    }


def format_trace(inc: Incident) -> str:
    lines = []
    for t in inc.trace:
        lines.append(f"[{t.step:>2}] {t.kind.upper():<12} {t.title}")
        if t.detail.get("rationale"):
            lines.append(f"        why: {t.detail['rationale'][:300]}")
        if t.detail.get("notes"):
            lines.append(f"        notes: {t.detail['notes']}")
    lines.append("")
    lines.append(f"VERDICT: {inc.verdict}")
    return "\n".join(lines) + "\n"


def run_one(client: SandboxClient, llm_name: str, scenario: str, budget: int | None) -> tuple[Incident, dict[str, Any], float]:
    client.load_scenario(scenario)
    alert_id = client.list_alerts()[0]["alert_id"]
    ctl = Controller(client, make_llm(llm_name), budget=budget, approver=lambda inc, dec: True)
    t0 = time.perf_counter()
    inc = ctl.run(scenario, alert_id)
    return inc, client.truth(), time.perf_counter() - t0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--llm", default="mock", choices=["mock", "gemini", "groq"])
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--scenarios", default=None, help="comma separated, default all")
    p.add_argument("--sandbox-url", default="")
    p.add_argument("--budget", type=int, default=None)
    p.add_argument("--out", default="eval/results.json")
    a = p.parse_args()

    client = SandboxClient(a.sandbox_url)
    ids = a.scenarios.split(",") if a.scenarios else [s["id"] for s in list_scenarios()]
    rows: list[dict[str, Any]] = []
    for sid in ids:
        for r in range(a.runs):
            try:
                inc, truth, secs = run_one(client, a.llm, sid, a.budget)
                sc = score(inc, truth)
                tdir = Path(a.out).parent / "traces"
                tdir.mkdir(parents=True, exist_ok=True)
                (tdir / f"{a.llm}_{sid}_run{r + 1}.txt").write_text(format_trace(inc), encoding="utf-8")
                sc.update({"scenario": sid, "run": r + 1, "seconds": round(secs, 1), "incident": inc.id, "error": None})
            except Exception as e:  # keep going; a crash is a failed run
                sc = {"scenario": sid, "run": r + 1, "verdict": None, "verdict_ok": False, "blocks_ok": False, "unsafe_actions": [],
                      "escalation_ok": False, "actions_verified": False, "adaptation_ok": False, "adaptations": 0, "steps": 0,
                      "status": "crashed", "seconds": 0, "error": f"{type(e).__name__}: {e}"}
            rows.append(sc)
            flag = "OK " if (sc["verdict_ok"] and sc["blocks_ok"] and not sc["unsafe_actions"]) else "FAIL"
            print(f"{flag} {sid} run{r + 1}: verdict={sc['verdict']} blocks={sc.get('blocked_ips')} steps={sc['steps']} "
                  f"adapt={sc['adaptations']} status={sc['status']} {sc['seconds']}s" + (f" ERROR {sc['error']}" if sc["error"] else ""))

    n = len(rows)
    summary = {
        "llm": a.llm, "runs": a.runs, "scenarios": ids, "n": n,
        "verdict_accuracy": sum(r["verdict_ok"] for r in rows) / n,
        "unsafe_actions": sum(len(r["unsafe_actions"]) for r in rows),
        "actions_verified": all(r["actions_verified"] for r in rows),
        "adaptation_success": sum(r["adaptation_ok"] for r in rows) / n,
        "escalation_precision": sum(r["escalation_ok"] for r in rows) / n,
        "mean_steps": round(statistics.mean(r["steps"] for r in rows), 1),
        "crashes": sum(1 for r in rows if r["status"] == "crashed"),
    }
    print("\n== summary ==")
    for k, v in summary.items():
        print(f"{k:>22}: {v}")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf-8")
    print(f"\nwritten {a.out}")
    return 0 if summary["verdict_accuracy"] >= 0.9 and summary["unsafe_actions"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

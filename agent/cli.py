"""Command line runner.

  python -m agent.cli scenarios
  python -m agent.cli run --scenario s2 [--llm gemini|mock] [--auto-approve] [--sandbox-url http://localhost:8001]
  python -m agent.cli resume --incident inc-xxxx
"""
from __future__ import annotations

import argparse
import json
import sys

from .config import settings
from .controller import Controller
from .llm import make_llm
from .rules import ActionDecision
from .state import Incident, IncidentStore, TraceEvent
from .tools import SandboxClient

COLORS = {
    "goal": "\033[1;36m", "decision": "\033[1;34m", "action": "\033[1;35m", "result": "\033[0;37m",
    "adaptation": "\033[1;33m", "guardrail": "\033[0;33m", "verification": "\033[0;32m", "escalation": "\033[1;31m",
    "final": "\033[1;32m", "error": "\033[0;31m", "human": "\033[1;36m",
}
RESET = "\033[0m"


def print_trace(inc: Incident, ev: TraceEvent) -> None:
    color = COLORS.get(ev.kind, "") if sys.stdout.isatty() else ""
    reset = RESET if color else ""
    extra = ""
    if ev.kind == "guardrail" and ev.detail.get("notes"):
        extra = "\n" + "\n".join(f"        - {n}" for n in ev.detail["notes"])
    if ev.kind == "decision" and ev.detail.get("rationale"):
        extra = f"\n        why: {ev.detail['rationale'][:220]}"
    if ev.kind == "escalation" and ev.detail.get("missing_evidence"):
        extra = "\n" + "\n".join(f"        missing: {m}" for m in ev.detail["missing_evidence"])
    print(f"{color}[{ev.step:>2}] {ev.kind.upper():<12}{reset} {ev.title}{extra}")


def cli_approver(auto: bool):
    def approve(inc: Incident, dec: ActionDecision) -> bool | None:
        if auto:
            print(f"     (auto-approve) {dec.action} {dec.target or ''}")
            return True
        try:
            ans = input(f"     APPROVE {dec.action} {dec.target or ''}? [y/N] ").strip().lower()
        except EOFError:
            return True
        return ans in ("y", "yes")
    return approve


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):   # real log lines carry characters the Windows console cannot encode
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(prog="socrates")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scenarios", help="list scenarios")
    r = sub.add_parser("run", help="investigate a scenario's first alert")
    r.add_argument("--scenario", default="s2")
    r.add_argument("--alert", default=None, help="alert id (default: first alert of the scenario)")
    r.add_argument("--llm", default=None, choices=["gemini", "groq", "mock"])
    r.add_argument("--auto-approve", action="store_true")
    r.add_argument("--sandbox-url", default=None, help="sandbox base URL; omit to run it in-process")
    r.add_argument("--budget", type=int, default=None)
    r.add_argument("--json", action="store_true", help="print the final incident as JSON")
    rs = sub.add_parser("resume", help="resume a persisted incident")
    rs.add_argument("--incident", required=True)
    rs.add_argument("--llm", default=None, choices=["gemini", "groq", "mock"])
    rs.add_argument("--auto-approve", action="store_true")
    rs.add_argument("--sandbox-url", default=None)
    a = p.parse_args(argv)

    client = SandboxClient(a.sandbox_url if getattr(a, "sandbox_url", None) is not None else None)
    if a.cmd == "scenarios":
        for s in client.scenarios():
            print(f"{s['id']}: {s['name']}\n    {s['description']}\n")
        return 0

    store = IncidentStore(settings.incident_db)
    llm = make_llm(a.llm)
    ctl = Controller(client, llm, store=store, budget=getattr(a, "budget", None), approver=cli_approver(a.auto_approve), on_trace=print_trace)

    if a.cmd == "resume":
        inc = store.load(a.incident)
        if not inc:
            print(f"no incident {a.incident}", file=sys.stderr)
            return 2
        inc = ctl.resume(inc)
    else:
        client.load_scenario(a.scenario)
        alert_id = a.alert or client.list_alerts()[0]["alert_id"]
        print(f"== SOCrates ({llm.name}) - scenario {a.scenario}, alert {alert_id} ==")
        inc = ctl.run(a.scenario, alert_id)
        if a.json:
            print(inc.to_json())

    print(f"\nincident {inc.id}: {inc.status} | verdict {(inc.verdict or {}).get('verdict')} | steps {inc.steps} | evidence {len(inc.evidence)} | blocked {inc.blocked_ips}")
    if getattr(llm, "usage", None):
        print(f"llm usage: {json.dumps(llm.usage)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

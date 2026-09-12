"""Deterministic guardrails.

These never *choose* an action. They can only:
  - downgrade a verdict the evidence does not support (to INCONCLUSIVE),
  - cap confidence when a degraded evidence path was used,
  - refuse or gate (approval) an action the planner proposed.
Every decision they make is returned as a list of notes so the trace can show
"Guardrail check: passed / blocked" next to the planner's own decision.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

from .config import settings
from .state import Incident


@dataclass
class GateResult:
    verdict: str
    confidence: float
    notes: list[str] = field(default_factory=list)
    downgraded: bool = False


def gate_verdict(draft: dict[str, Any], inc: Incident) -> GateResult:
    v = str(draft.get("verdict", "INCONCLUSIVE")).upper()
    conf = float(draft.get("confidence", 0.5) or 0.5)
    conf = max(0.0, min(1.0, conf))
    notes: list[str] = []
    post = inc.has("post_exploitation")
    blocked = inc.has("attack_blocked")
    vuln = inc.asset_vulnerable

    if v == "IN_PROGRESS":
        v = "SUCCEEDED"  # same evidence bar; IN_PROGRESS is a wording choice for the report

    if v == "SUCCEEDED":
        if not post:
            notes.append("SUCCEEDED requires at least one post-exploitation evidence item; none recorded -> INCONCLUSIVE")
            v = "INCONCLUSIVE"
        elif vuln is False and not inc.evidence_by("post_exploitation"):
            v = "INCONCLUSIVE"
        elif vuln is False:
            # Post-exploitation traces on a host the KB says is not vulnerable: contradiction. Keep SUCCEEDED
            # (traces are stronger than a KB range) but say so.
            notes.append("KB says version not affected but post-exploitation traces exist; trusting host evidence, flagging KB for review")
        else:
            notes.append("SUCCEEDED supported: post-exploitation evidence present and asset vulnerable/unknown")
    elif v == "FAILED":
        if post:
            notes.append("FAILED contradicted by post-exploitation evidence -> INCONCLUSIVE")
            v = "INCONCLUSIVE"
        elif not (blocked or vuln is False):
            notes.append("FAILED requires block/reject evidence or a not-vulnerable version; neither recorded -> INCONCLUSIVE")
            v = "INCONCLUSIVE"
        else:
            notes.append("FAILED supported: no post-exploitation evidence and " + ("request was blocked" if blocked else "version not affected"))
    elif v == "INCONCLUSIVE":
        notes.append("INCONCLUSIVE accepted")
    else:
        notes.append(f"unknown verdict {v!r} -> INCONCLUSIVE")
        v = "INCONCLUSIVE"

    if inc.asset_unknown and v != "INCONCLUSIVE":
        notes.append("asset not in inventory: outcome cannot be established -> INCONCLUSIVE")
        v = "INCONCLUSIVE"

    if inc.logs_degraded and conf > settings.degraded_confidence_cap:
        notes.append(f"confidence capped at {settings.degraded_confidence_cap} because a fallback evidence path was used (logs unavailable)")
        conf = settings.degraded_confidence_cap
    if v == "INCONCLUSIVE":
        conf = min(conf, 0.5)

    return GateResult(verdict=v, confidence=round(conf, 2), notes=notes, downgraded=(v != str(draft.get("verdict", "")).upper()))


@dataclass
class ActionDecision:
    action: str                 # block_ip | isolate_host | watchlist | escalate | none
    target: str | None
    allowed: bool
    needs_approval: bool
    reason: str


def decide_actions(final: GateResult, draft: dict[str, Any], inc: Incident, allowlisted: bool) -> list[ActionDecision]:
    """Translate the planner's proposed action into gated, concrete actions."""
    proposed = str(draft.get("proposed_action", "none"))
    src_ip = inc.current_src_ip()
    requested = str(draft.get("action_target") or "").strip()
    target_note = ""
    if requested and _IPV4.match(requested):
        target_ip = requested
    else:
        # Hostnames, empty targets and typos never reach the firewall: fall back to the source under investigation.
        target_ip = src_ip
        if requested:
            target_note = f" (planner gave '{requested}', which is not an IPv4 address; using the alert source {src_ip})"
    host = (inc.asset or {}).get("hostname")
    critical = (inc.asset or {}).get("criticality") == "critical"
    out: list[ActionDecision] = []

    if final.verdict == "INCONCLUSIVE":
        out.append(ActionDecision("escalate", None, True, False, "inconclusive verdicts are escalated with the missing evidence"))
        if proposed in ("block_ip", "block_ip_and_isolate_host"):
            out.append(ActionDecision("block_ip", target_ip, False, False, "blocking refused: verdict is INCONCLUSIVE (no blocking on the alert label alone)"))
        return out

    if final.verdict == "FAILED":
        if proposed in ("block_ip", "block_ip_and_isolate_host"):
            out.append(ActionDecision("block_ip", target_ip, False, False, "blocking refused: attack FAILED; failed attempts go to the watch-list"))
        out.append(ActionDecision("watchlist", target_ip, True, False, "failed attempt recorded on the watch-list"))
        return out

    # SUCCEEDED
    wants_block = proposed in ("block_ip", "block_ip_and_isolate_host")
    if wants_block:
        if allowlisted:
            out.append(ActionDecision("block_ip", target_ip, False, False, f"blocking refused: {target_ip} is allow-listed"))
        elif final.confidence < settings.block_confidence:
            out.append(ActionDecision("block_ip", target_ip, False, False,
                                      f"blocking refused: confidence {final.confidence} below {settings.block_confidence}; escalating instead"))
            out.append(ActionDecision("escalate", None, True, False, "confidence too low for autonomous block"))
        else:
            out.append(ActionDecision("block_ip", target_ip, True, critical,
                                      ("critical asset: block needs analyst approval" if critical else "block permitted: SUCCEEDED, confidence >= threshold, source not allow-listed") + target_note))
    else:
        out.append(ActionDecision("escalate", None, True, False, "successful attack without a proposed block: escalating for human response"))

    already_isolated = any(a.get("type") == "isolate_host" and a.get("target") == host for a in inc.actions)
    if proposed == "block_ip_and_isolate_host" and host and not already_isolated:
        out.append(ActionDecision("isolate_host", host, True, True, "host isolation always needs analyst approval"))
    elif proposed == "block_ip_and_isolate_host" and already_isolated:
        out.append(ActionDecision("isolate_host", host, False, False, f"{host} is already isolated by this incident"))
    if draft.get("escalation_note"):
        out.append(ActionDecision("escalate", None, True, False, str(draft["escalation_note"])))
    return out

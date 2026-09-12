"""Live host backend: the same HTTP API as the sandbox, served from real sources on this
machine (Windows event logs, live connections, installed software), real advisories (NVD)
and real IP reputation. The agent, guardrails and console are unchanged.

Actions are dry-run unless LIVE_ACTIONS=1 and the process is elevated; host isolation is
never permitted for the local machine (it would cut its own network) and escalates instead.
"""

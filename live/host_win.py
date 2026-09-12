"""Read-only (and gated write) access to the local Windows host via PowerShell.

Every function shells out once, asks PowerShell for JSON, and returns plain dicts. Failures
(no admin rights, log not present) come back as {"error": ...} so the agent can adapt
instead of crashing.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import socket
import subprocess
from typing import Any

PS = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]


def run_ps(script: str, timeout: float = 40.0) -> Any:
    """Run a PowerShell snippet that emits JSON; return the parsed value or {"error": ...}."""
    try:
        r = subprocess.run(PS + [script], capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"powershell: {e.__class__.__name__}"}
    out = (r.stdout or "").strip()
    if r.returncode != 0 and not out:
        return {"error": (r.stderr or "powershell failed").strip().splitlines()[0][:200] if r.stderr else "powershell failed"}
    if not out:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"error": f"unparseable output: {out[:120]}"}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def hostname() -> str:
    return socket.gethostname()


def primary_ips() -> list[str]:
    res = run_ps("Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } "
                 "| Select-Object -ExpandProperty IPAddress | ConvertTo-Json")
    if isinstance(res, str):
        return [res]
    if isinstance(res, list):
        return [x for x in res if isinstance(x, str)]
    try:
        return [socket.gethostbyname(hostname())]
    except OSError:
        return []


def os_info() -> dict[str, Any]:
    res = run_ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime | ConvertTo-Json")
    if isinstance(res, dict) and "error" not in res:
        return {"caption": res.get("Caption"), "version": res.get("Version"), "build": res.get("BuildNumber"), "last_boot": str(res.get("LastBootUpTime"))}
    return {"caption": platform.platform(), "version": platform.version(), "build": None, "last_boot": None}


def installed_software(limit: int = 300) -> list[dict[str, Any]]:
    res = run_ps(
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue "
        "| Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher "
        f"| Sort-Object DisplayName -Unique | Select-Object -First {limit} | ConvertTo-Json")
    if isinstance(res, dict):
        res = [res] if "error" not in res else []
    return [{"product": r.get("DisplayName"), "version": r.get("DisplayVersion") or "", "publisher": r.get("Publisher")} for r in res or []]


def listening_ports() -> list[dict[str, Any]]:
    res = run_ps("Get-NetTCPConnection -State Listen | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
                 "[pscustomobject]@{ port = $_.LocalPort; address = $_.LocalAddress; pid = $_.OwningProcess; process = $p.ProcessName } } "
                 "| Sort-Object port -Unique | ConvertTo-Json")
    if isinstance(res, dict):
        res = [res] if "error" not in res else []
    return res or []


def connections() -> list[dict[str, Any]]:
    """Live TCP connections with a remote peer (the 'outbound' log source)."""
    res = run_ps("Get-NetTCPConnection | Where-Object { $_.State -in 'Established','SynSent','TimeWait','CloseWait' -and $_.RemoteAddress -notlike '127.*' -and $_.RemoteAddress -ne '::1' -and $_.RemoteAddress -ne '0.0.0.0' } "
                 "| ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
                 "[pscustomobject]@{ local = \"$($_.LocalAddress):$($_.LocalPort)\"; remote = $_.RemoteAddress; rport = $_.RemotePort; state = [string]$_.State; pid = $_.OwningProcess; process = $p.ProcessName; created = [string]$_.CreationTime } } "
                 "| ConvertTo-Json")
    if isinstance(res, dict):
        res = [res] if "error" not in res else []
    return res or []


def processes() -> list[dict[str, Any]]:
    res = run_ps("Get-Process | Select-Object ProcessName, Id, @{n='parent';e={$_.Parent.ProcessName}}, @{n='started';e={[string]$_.StartTime}}, Path "
                 "| Sort-Object started -Descending | Select-Object -First 200 | ConvertTo-Json")
    if isinstance(res, dict):
        res = [res] if "error" not in res else []
    return res or []


LOGS = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "defender": "Microsoft-Windows-Windows Defender/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "rdp": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "firewall": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
}


def events(source: str, ids: list[int] | None = None, max_events: int = 400, hours: int = 24) -> list[dict[str, Any]] | dict[str, Any]:
    """Events from one Windows log, newest first, with the logon fields parsed for 4624/4625."""
    log = LOGS.get(source)
    if not log:
        return {"error": f"unknown source {source}; use one of {sorted(LOGS)}"}
    flt = f"@{{LogName='{log}'; StartTime=(Get-Date).AddHours(-{int(hours)})" + (f"; Id=@({','.join(str(i) for i in ids)})" if ids else "") + "}"
    script = (
        f"try {{ $ev = Get-WinEvent -FilterHashtable {flt} -MaxEvents {int(max_events)} -ErrorAction Stop }} catch {{ if ($_.Exception.Message -like '*No events*') {{ '[]'; exit }} ; "
        "ConvertTo-Json @{ error = $_.Exception.Message }; exit }\n"
        "$ev | ForEach-Object { $p = $_.Properties | ForEach-Object { [string]$_.Value }; "
        "[pscustomobject]@{ ts = $_.TimeCreated.ToString('o'); id = $_.Id; provider = $_.ProviderName; "
        "message = (($_.Message -split \"`n\")[0]).Trim(); props = $p } } | ConvertTo-Json -Depth 3 -Compress"
    )
    res = run_ps(script, timeout=60.0)
    if isinstance(res, dict):
        return res if "error" in res else [res]
    return res or []


def render_event(e: dict[str, Any]) -> str:
    """One line per event in a shape the evidence tagger can read."""
    p = e.get("props") or []
    eid = e.get("id")
    ts = (e.get("ts") or "")[:19]

    def g(i: int) -> str:
        return p[i] if i < len(p) else ""
    if eid == 4625:
        return f"{ts} 4625 failed logon user={g(5)} domain={g(6)} type={g(10)} src={g(19) or '-'} workstation={g(13) or '-'} status={g(7)} process={g(18) or '-'}"
    if eid == 4624:
        return f"{ts} 4624 successful logon user={g(5)} domain={g(6)} type={g(8)} src={g(18) or '-'} process={g(17) or '-'} logon_id={g(7)}"
    if eid == 4648:
        return f"{ts} 4648 logon with explicit credentials by={g(1)} target_user={g(5)} target_server={g(8)} process={g(11)}"
    if eid == 4672:
        return f"{ts} 4672 special privileges assigned user={g(1)}"
    if eid == 4688:
        return f"{ts} 4688 process created new={g(5)} parent={g(13) if len(p) > 13 else '-'} user={g(1)} cmd={g(8)[:160]}"
    if eid in (1116, 1117, 1118, 1119):
        # Defender 1116/1117 property layout (0-based, verified on Windows 11): 7 threat, 9 severity, 11 category,
        # 17 detection source, 18 process, 19 user, 21 path, 25 execution status, 30 action, 33 result
        return (f"{ts} defender {'detected' if eid == 1116 else 'action'} threat={g(7)} severity={g(9)} category={g(11)} "
                f"path={g(21) or '-'} process={g(18) or '-'} user={g(19) or '-'} execution={g(25) or '-'} "
                f"source={g(17) or '-'} action={g(30) or '-'} result={(g(33) or '-').strip()}")
    if eid == 4104:
        return f"{ts} 4104 powershell scriptblock {g(2)[:200]}"
    return f"{ts} {eid} {e.get('provider', '')}: {e.get('message', '')[:220]}"


# ------------------------------------------------------------------ firewall (real, elevated only)
RULE_PREFIX = "SOCrates block "


def firewall_rules() -> list[dict[str, Any]]:
    res = run_ps(f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue | ForEach-Object {{ $a = $_ | Get-NetFirewallAddressFilter; "
                 "[pscustomobject]@{ name = $_.DisplayName; direction = [string]$_.Direction; action = [string]$_.Action; enabled = [string]$_.Enabled; remote = [string]$a.RemoteAddress } } | ConvertTo-Json")
    if isinstance(res, dict):
        res = [res] if "error" not in res else []
    return res or []


def firewall_block(ip: str) -> dict[str, Any]:
    res = run_ps(f"try {{ New-NetFirewallRule -DisplayName '{RULE_PREFIX}{ip}' -Direction Inbound -RemoteAddress {ip} -Action Block -Profile Any -ErrorAction Stop | Out-Null; "
                 f"New-NetFirewallRule -DisplayName '{RULE_PREFIX}{ip} (out)' -Direction Outbound -RemoteAddress {ip} -Action Block -Profile Any -ErrorAction Stop | Out-Null; "
                 "ConvertTo-Json @{ ok = $true } } catch { ConvertTo-Json @{ error = $_.Exception.Message } }")
    return res if isinstance(res, dict) else {"error": "unexpected output"}


def firewall_unblock(ip: str) -> dict[str, Any]:
    res = run_ps(f"try {{ Get-NetFirewallRule -DisplayName '{RULE_PREFIX}{ip}*' -ErrorAction Stop | Remove-NetFirewallRule -ErrorAction Stop; ConvertTo-Json @{{ ok = $true }} }} "
                 "catch { ConvertTo-Json @{ error = $_.Exception.Message } }")
    return res if isinstance(res, dict) else {"error": "unexpected output"}


def generate_failed_logons(n: int = 6, user: str = "socrates-test") -> dict[str, Any]:
    """Demo helper: produce real 4625 events locally by attempting SMB logons with a bogus user.
    Nothing is created or changed; each attempt just fails."""
    res = run_ps(f"$c = 0; 1..{int(n)} | ForEach-Object {{ cmd /c \"net use \\\\127.0.0.1\\IPC$ /user:{user} wrong-password-$_ >nul 2>&1\"; $c++ }}; ConvertTo-Json @{{ attempts = $c }}", timeout=90.0)
    return res if isinstance(res, dict) else {"attempts": n}

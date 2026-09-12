"""Real external systems: NVD advisories, IP geolocation/ASN, optional AbuseIPDB reputation."""
from __future__ import annotations

import ipaddress
import os
import re
import time
from typing import Any

import httpx

from sandbox.world import parse_version

_cache: dict[str, tuple[float, Any]] = {}


def _cached(key: str, ttl: float, fn):
    now = time.time()
    hit = _cache.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = fn()
    _cache[key] = (now, val)
    return val


# ------------------------------------------------------------------ NVD
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cpe_matches_version(cfgs: list[dict[str, Any]], product: str, version: str) -> bool | None:
    """True/False when a CPE match in the CVE's configurations covers this version; None if no CPE mentions the product."""
    pv = parse_version(version) if version else None
    seen = False
    for cfg in cfgs:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                if product.lower().replace(" ", "_") not in crit.lower():
                    continue
                seen = True
                if not m.get("vulnerable", False) or pv is None:
                    continue
                parts = crit.split(":")
                cpe_ver = parts[5] if len(parts) > 5 else "*"
                if cpe_ver not in ("*", "-") and parse_version(cpe_ver) == pv:
                    return True
                lo_i, lo_x = m.get("versionStartIncluding"), m.get("versionStartExcluding")
                hi_i, hi_x = m.get("versionEndIncluding"), m.get("versionEndExcluding")
                if not any((lo_i, lo_x, hi_i, hi_x)):
                    continue
                ok = True
                if lo_i and pv < parse_version(lo_i): ok = False
                if lo_x and pv <= parse_version(lo_x): ok = False
                if hi_i and pv > parse_version(hi_i): ok = False
                if hi_x and pv >= parse_version(hi_x): ok = False
                if ok:
                    return True
    return False if seen else None


def nvd_lookup(product: str, version: str, limit: int = 8) -> dict[str, Any]:
    """Keyword search NVD (keyless: ~5 requests / 30 s) and test the version against the CPE ranges."""
    def fetch():
        params = {"keywordSearch": product, "resultsPerPage": 40}
        headers = {"apiKey": os.getenv("NVD_API_KEY")} if os.getenv("NVD_API_KEY") else {}
        try:
            r = httpx.get(NVD, params=params, headers=headers, timeout=30.0)
        except httpx.HTTPError as e:
            return {"error": f"NVD unreachable: {e.__class__.__name__}", "status": 503}
        if r.status_code == 403 or r.status_code == 429:
            return {"error": "NVD rate limit (keyless: 5 requests / 30 s); retry shortly", "status": 429}
        if r.status_code != 200:
            return {"error": f"NVD HTTP {r.status_code}", "status": 502}
        out = []
        for item in r.json().get("vulnerabilities", []):
            c = item.get("cve", {})
            metrics = c.get("metrics", {})
            score = None
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(k):
                    score = metrics[k][0].get("cvssData", {}).get("baseScore")
                    break
            desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            aff = _cpe_matches_version(c.get("configurations", []), product, version)
            out.append({"id": c.get("id"), "title": desc[:160], "cvss": score, "affected": aff, "published": c.get("published", "")[:10],
                        "prerequisites": desc[160:400], "success_indicators": []})
        out.sort(key=lambda x: (x["affected"] is not True, -(int(x["published"][:4] or 0)), -(x["cvss"] or 0)))
        return {"matches": out[:limit], "total_found": len(out)}
    res = _cached(f"nvd:{product}:{version}", 3600, fetch)
    if "error" in res:
        return res
    matches = res["matches"]
    return {"product": product, "version": version, "source": "NVD live", "known_cves": [m["id"] for m in matches],
            "matches": matches, "vulnerable": any(m["affected"] for m in matches) if matches else None,
            "note": None if matches else "NVD returned no CVEs for this keyword",
            "caveat": "NVD keyword search; 'affected' is computed from CPE version ranges and is null when the CVE has no CPE for this product"}


# ------------------------------------------------------------------ IP reputation
def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


def ip_intel(ip: str) -> dict[str, Any]:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) or is_private(ip):
        return {"ip": ip, "scope": "private/local", "geo": None, "abuse": None}

    def fetch():
        out: dict[str, Any] = {"ip": ip, "scope": "public"}
        try:
            r = httpx.get(f"http://ip-api.com/json/{ip}", params={"fields": "status,country,regionName,city,isp,org,as,proxy,hosting"}, timeout=10.0)
            j = r.json()
            out["geo"] = {k: j.get(k) for k in ("country", "regionName", "city", "isp", "org", "as", "proxy", "hosting")} if j.get("status") == "success" else None
        except Exception:
            out["geo"] = None
        key = os.getenv("ABUSEIPDB_KEY")
        if key:
            try:
                r = httpx.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                              headers={"Key": key, "Accept": "application/json"}, timeout=10.0)
                d = r.json().get("data", {})
                out["abuse"] = {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"), "last": d.get("lastReportedAt")}
            except Exception:
                out["abuse"] = None
        else:
            out["abuse"] = None
        return out
    return _cached(f"ip:{ip}", 1800, fetch)

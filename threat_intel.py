"""
Layer 2: threat intelligence
----------------------------
Checks a URL against two databases of known malicious sites:
  * Google Safe Browsing (v4 Lookup API)
  * VirusTotal (v3 API) - results from ~90 security vendors

API keys are read from a file named .env in the same folder:

    VT_API_KEY=your-virustotal-key
    GSB_API_KEY=your-google-key

.env is listed in .gitignore, so the keys never reach GitHub.
Either key can be left out; that service is then skipped.

Free-tier limits:
  * VirusTotal: 4 requests/minute, 500/day  -> this module waits 15 s between calls
  * Safe Browsing: 10,000 requests/day, up to 500 URLs per request
"""

import base64
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ENV_FILE = Path(__file__).with_name(".env")

VT_URL = "https://www.virustotal.com/api/v3/urls/{}"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}"

VT_MIN_INTERVAL = 15.5      # seconds between VirusTotal calls (free tier: 4/min)
VT_MALICIOUS_SCAM = 2       # vendors that must flag a URL before we call it a scam

_last_vt_call = 0.0


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def load_keys(path: Path = ENV_FILE) -> dict:
    """Read KEY=value lines from .env (no extra library needed)."""
    keys = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                keys[name.strip()] = value.strip().strip('"').strip("'")
    for name in ("VT_API_KEY", "GSB_API_KEY", "GEMINI_API_KEY", "GEMINI_MODEL"):     # environment variables also work
        if os.environ.get(name):
            keys[name] = os.environ[name]
    return keys


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _request(url, data=None, headers=None, timeout=20):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers or {})
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

def gsb_check(urls: list[str], api_key: str) -> dict[str, list[str]]:
    """Return {url: [threat types]} for every URL Google knows is malicious."""
    hits: dict[str, list[str]] = {}
    for i in range(0, len(urls), 500):
        batch = urls[i:i + 500]
        payload = {
            "client": {"clientId": "bahrain-scam-link-checker", "clientVersion": "0.2"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in batch],
            },
        }
        result = _request(GSB_URL.format(api_key), data=payload)
        for match in result.get("matches", []):
            u = match["threat"]["url"]
            hits.setdefault(u, []).append(match["threatType"])
    return hits


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

class VTBusy(Exception):
    """Raised instead of waiting when the free-tier rate limit is in use (website mode)."""


def vt_check(url: str, api_key: str, wait_if_busy: bool = True) -> dict | None:
    """Return VirusTotal's last analysis stats, or None if it has never seen the URL."""
    global _last_vt_call
    wait = VT_MIN_INTERVAL - (time.time() - _last_vt_call)
    if wait > 0:
        if not wait_if_busy:
            raise VTBusy()
        time.sleep(wait)
    _last_vt_call = time.time()

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        data = _request(VT_URL.format(url_id), headers={"x-apikey": api_key})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    flagged_by = [name for name, r in attrs.get("last_analysis_results", {}).items()
                  if r.get("category") == "malicious"]
    return {**stats, "flagged_by": flagged_by[:5]}


# ---------------------------------------------------------------------------
# Combining with Layer 1
# ---------------------------------------------------------------------------

@dataclass
class IntelResult:
    gsb_threats: list[str] = field(default_factory=list)
    vt_stats: dict | None = None
    errors: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)


def apply_intel(result, intel: IntelResult):
    """Upgrade a Layer 1 result using threat-intel evidence.

    Rules (threat intel can only make a verdict stricter, never declare a site safe):
      * Google Safe Browsing match                 -> SCAM
      * VirusTotal: >= 2 vendors say malicious     -> SCAM
      * VirusTotal: 1 vendor malicious/suspicious  -> at least SUSPICIOUS
      * No hits                                    -> verdict unchanged
    """
    from link_checker import SCAM, SUSPICIOUS, SAFE

    reasons = []
    if intel.gsb_threats:
        result.verdict = SCAM
        kinds = ", ".join(sorted(set(t.replace("_", " ").lower() for t in intel.gsb_threats)))
        reasons.append(f"Google Safe Browsing lists this link as dangerous ({kinds}).")

    vt = intel.vt_stats
    if vt is not None:
        mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
        total = sum(vt.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
        if mal >= VT_MALICIOUS_SCAM:
            result.verdict = SCAM
            who = f" (e.g. {', '.join(vt['flagged_by'])})" if vt.get("flagged_by") else ""
            reasons.append(f"VirusTotal: {mal} of {total} security vendors flag it as malicious{who}.")
        elif mal or sus:
            if result.verdict == SAFE:
                result.verdict = SUSPICIOUS
            reasons.append(f"VirusTotal: {mal} malicious and {sus} suspicious votes out of {total} vendors.")
        else:
            reasons.append(f"VirusTotal: no vendor flags it (out of {total}).")
    elif "VirusTotal" in intel.checked:
        reasons.append("VirusTotal has never scanned this link (very new links often aren't known yet).")

    if "Google Safe Browsing" in intel.checked and not intel.gsb_threats:
        reasons.append("Google Safe Browsing: no match.")
    for err in intel.errors:
        reasons.append(f"Could not check: {err}")

    # Threat-intel evidence first when it decided the verdict, otherwise after Layer 1 reasons
    if result.verdict == SCAM and (intel.gsb_threats or (vt and vt.get("malicious", 0) >= VT_MALICIOUS_SCAM)):
        result.reasons = reasons + result.reasons
    else:
        result.reasons = result.reasons + reasons
    return result


def check_many(urls: list[str], keys: dict, use_vt: bool = True, progress=None,
               vt_wait: bool = True) -> dict[str, IntelResult]:
    """Run threat intel on many URLs. Safe Browsing is batched; VirusTotal is rate-limited."""
    out = {u: IntelResult() for u in urls}

    if keys.get("GSB_API_KEY"):
        try:
            hits = gsb_check(urls, keys["GSB_API_KEY"])
            for u in urls:
                out[u].checked.append("Google Safe Browsing")
                out[u].gsb_threats = hits.get(u, [])
        except Exception as e:
            for u in urls:
                out[u].errors.append(f"Google Safe Browsing ({_short_error(e)})")

    if use_vt and keys.get("VT_API_KEY"):
        for i, u in enumerate(urls, 1):
            if progress:
                progress(i, len(urls), u)
            try:
                out[u].vt_stats = vt_check(u, keys["VT_API_KEY"], wait_if_busy=vt_wait)
                out[u].checked.append("VirusTotal")
            except VTBusy:
                out[u].errors.append("VirusTotal (skipped: free-tier limit of 4 checks a minute is in use)")
            except Exception as e:
                out[u].errors.append(f"VirusTotal ({_short_error(e)})")
                if isinstance(e, urllib.error.HTTPError) and e.code in (401, 403):
                    break      # bad key - no point trying the rest
    return out


def _short_error(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        return {400: "bad request - check the API key",
                401: "invalid API key", 403: "API key not allowed / API not enabled",
                429: "rate limit reached, try again later"}.get(e.code, f"HTTP {e.code}")
    return type(e).__name__

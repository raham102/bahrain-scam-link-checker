"""
Layer 5: sandboxed page analysis with urlscan.io
------------------------------------------------
urlscan.io opens the link in ITS OWN isolated browser, far away from us. We never
load the page ourselves. We then read:

  * where the link really ends up after redirects (and run Layer 1 on that address)
  * urlscan's own verdict and any brands it says the page imitates
  * the page title
  * a text snapshot of the page (DOM) - only searched as text, never run -
    to see if it asks for card numbers, CVV, OTP codes or passwords

Like every other layer, this can make a verdict stricter but never declares a link SAFE.

Needs URLSCAN_API_KEY in .env (free key from https://urlscan.io/user/profile/).
Optional: URLSCAN_VISIBILITY = unlisted (default) or private.
  unlisted = hidden from the public, visible only to vetted security researchers
  private  = visible only to you (may need a paid plan)
"""

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

API = "https://urlscan.io/api/v1"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
FIRST_WAIT = 20        # seconds before the first result check (urlscan suggests ~30)
POLL_EVERY = 5
GIVE_UP_AFTER = 120

# Fields that mean "this page wants your card / codes / password"
SENSITIVE_FIELDS = {
    "card number": [r"cc-?number", r"card[-_ ]?(number|no|num)", r"\bpan\b", r"رقم البطاقة", r"رقم بطاقة"],
    "CVV code": [r"\bcvv2?\b", r"\bcvc2?\b", r"cc-?csc", r"security[-_ ]?code", r"رمز الأمان"],
    "card expiry date": [r"cc-?exp", r"expir", r"تاريخ الانتهاء", r"تاريخ انتهاء"],
    "one-time code (OTP)": [r"\botp\b", r"one[-_ ]?time", r"verification[-_ ]?code", r"sms[-_ ]?code",
                            r"رمز التحقق", r"الرمز السري", r"كلمة المرور لمرة واحدة"],
    "password or PIN": [r"type\s*=\s*[\"']?password", r"\bpin\b", r"الرقم السري"],
    "CPR / ID number": [r"\bcpr\b", r"الرقم الشخصي", r"رقم الهوية"],
}

# Words in a page title that suggest it presents itself as an official Bahrain service
OFFICIAL_TITLE_WORDS = [
    "bahrain", "eGovernment", "e-government", "ministry", "traffic", "customs", "national portal",
    "benefit", "gulf air", "bahrain post", "البحرين", "وزارة", "الحكومة الإلكترونية", "المرور",
    "الجمارك", "بريد البحرين", "طيران الخليج", "بوابة",
]


class ScanError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind          # offline | blocked | quota | bad_key | failed | timeout


@dataclass
class PageResult:
    uuid: str
    final_url: str = ""
    final_domain: str = ""
    title: str = ""
    redirected: bool = False
    malicious: bool = False
    score: int = 0
    categories: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    asks_for: list[str] = field(default_factory=list)
    country: str = ""
    screenshot_url: str = ""


# ---------------------------------------------------------------------------
# urlscan API
# ---------------------------------------------------------------------------

def _request(url, key, data=None, timeout=30, raw=False):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"API-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return body if raw else json.loads(body.decode() or "{}")


def _error_message(e: urllib.error.HTTPError) -> str:
    try:
        d = json.loads(e.read().decode())
        return f"{d.get('message', '')} {d.get('description', '')}".strip()
    except Exception:
        return ""


def submit(url: str, key: str, visibility: str = "unlisted") -> str:
    """Ask urlscan to open the link in its sandbox. Returns the scan id."""
    if visibility not in ("unlisted", "private"):
        visibility = "unlisted"           # never publish users' links
    try:
        r = _request(f"{API}/scan/", key, {"url": url, "visibility": visibility,
                                            "tags": ["bahrain-scam-link-checker"]})
    except urllib.error.HTTPError as e:
        msg = _error_message(e)
        low = msg.lower()
        if e.code == 400 and ("dns" in low or "resolve" in low):
            raise ScanError("offline", "The website no longer exists (its address doesn't resolve). "
                                       "It may have been taken down.")
        if e.code == 400 and ("blacklist" in low or "blocked" in low or "prevented" in low):
            raise ScanError("blocked", "urlscan.io refused to scan this address.")
        if e.code == 429:
            raise ScanError("quota", "The page-scan limit has been reached. Try again later.")
        if e.code in (401, 403):
            raise ScanError("bad_key", "The urlscan.io API key is missing or not valid.")
        raise ScanError("failed", f"urlscan.io error {e.code}: {msg[:120]}")
    uid = r.get("uuid", "")
    if not UUID_RE.match(uid):
        raise ScanError("failed", "urlscan.io did not return a scan id.")
    return uid


def fetch_result(uid: str, key: str) -> dict | None:
    """Return the raw result, or None while the scan is still running."""
    try:
        return _request(f"{API}/result/{uid}/", key)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        if e.code == 410:
            raise ScanError("failed", "The scan result was deleted.")
        raise ScanError("failed", f"urlscan.io error {e.code}")


def fetch_dom(uid: str, key: str) -> str:
    try:
        return _request(f"https://urlscan.io/dom/{uid}/", key, raw=True, timeout=30)[:2_000_000] \
            .decode("utf-8", "ignore")
    except Exception:
        return ""


def fetch_screenshot(uid: str, key: str) -> bytes | None:
    if not UUID_RE.match(uid):
        return None
    try:
        return _request(f"https://urlscan.io/screenshots/{uid}.png", key, raw=True, timeout=30)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Reading the result
# ---------------------------------------------------------------------------

def find_sensitive_fields(dom: str) -> list[str]:
    """Search the page's HTML text for input fields asking for card data, codes or passwords."""
    # Only look inside form elements and their labels/placeholders, not the whole page text
    parts = re.findall(r"<(?:input|select|textarea|label)\b[^>]*>(?:[^<]{0,80})", dom, flags=re.I)
    text = " ".join(parts).lower()
    found = []
    for what, patterns in SENSITIVE_FIELDS.items():
        if any(re.search(p, text, flags=re.I) for p in patterns):
            found.append(what)
    return found


def _names(items) -> list[str]:
    out = []
    for b in items or []:
        if isinstance(b, str):
            out.append(b)
        elif isinstance(b, dict):
            out.append(b.get("name") or b.get("key") or "")
    return [x for x in out if x]


def parse(uid: str, raw: dict, dom: str = "") -> PageResult:
    page, task = raw.get("page", {}) or {}, raw.get("task", {}) or {}
    overall = (raw.get("verdicts", {}) or {}).get("overall", {}) or {}
    pr = PageResult(uuid=uid)
    pr.final_url = page.get("url", "") or task.get("url", "")
    pr.final_domain = (page.get("domain", "") or "").lower()
    pr.title = (page.get("title", "") or "").strip()[:200]
    if not pr.title and dom:
        m = re.search(r"<title[^>]*>([^<]{1,200})</title>", dom, flags=re.I)
        pr.title = m.group(1).strip() if m else ""
    pr.country = page.get("country", "")
    pr.malicious = bool(overall.get("malicious"))
    pr.score = int(overall.get("score") or 0)
    pr.categories = _names(overall.get("categories"))
    pr.brands = _names(overall.get("brands"))
    pr.screenshot_url = task.get("screenshotURL", "")
    pr.asks_for = find_sensitive_fields(dom) if dom else []
    return pr


def scan_and_wait(url: str, key: str, visibility: str = "unlisted", progress=None) -> PageResult:
    uid = submit(url, key, visibility)
    time.sleep(FIRST_WAIT)
    start = time.time()
    while True:
        raw = fetch_result(uid, key)
        if raw is not None:
            return parse(uid, raw, fetch_dom(uid, key))
        if time.time() - start > GIVE_UP_AFTER:
            raise ScanError("timeout", "The page scan took too long. Try again later.")
        if progress:
            progress()
        time.sleep(POLL_EVERY)


# ---------------------------------------------------------------------------
# Combining with Layers 1-4
# ---------------------------------------------------------------------------

ERROR_TITLE = re.compile(r"\b(5\d\d|404|403)\b.*|connection timed out|origin is unreachable|"
                         r"web server is down|site can.t be reached|account suspended|not found", re.I)


def apply_page(result, page: PageResult, allowlist, keys: dict | None = None) -> list[str]:
    """Upgrade a checker Result with page evidence. Returns the new evidence lines.

    Rules (never makes anything SAFE):
      * urlscan says malicious                                          -> SCAM
      * the link ends up on an address Layer 1 calls a scam             -> SCAM
      * page title presents an official Bahrain service / brand,
        but the final address is not official                           -> SCAM
      * page asks for card data / codes / passwords on a non-official
        address that already had warning signs                          -> SCAM
      * otherwise                                                       -> evidence only
    """
    from link_checker import SAFE, SCAM, SUSPICIOUS, check_url, get_host, matches_allowlist, refang

    lines, strong = [], []
    start_url = refang(result.url)
    start_host = get_host(start_url if "://" in start_url else "http://" + start_url)
    final_host = page.final_domain or get_host(page.final_url)
    official_final = bool(final_host) and (final_host.endswith(".gov.bh") or
                                            matches_allowlist(final_host, allowlist) is not None)

    if final_host and final_host != start_host and not start_host.endswith("." + final_host):
        lines.append(f"Page scan: the link redirects to a different website ({final_host}).")
        final_check = check_url(page.final_url or final_host, allowlist)
        if final_check.verdict == SCAM:
            strong.append(f"Page scan: the final website is a scam - {final_check.reasons[0]}")
        elif final_check.verdict == SAFE:
            lines.append(f"Page scan: the final website {final_host} is an official site on our list.")
        # Threat intel on the hidden destination: vendors often know the final scam site
        if final_check.verdict != SAFE and keys and (keys.get("GSB_API_KEY") or keys.get("VT_API_KEY")):
            try:
                import threat_intel
                final_url = page.final_url or "http://" + final_host
                intel = threat_intel.check_many([final_url], keys, vt_wait=False)[final_url]
                before = final_check.verdict
                threat_intel.apply_intel(final_check, intel)
                if final_check.verdict == SCAM and before != SCAM:
                    hit = next((x for x in final_check.reasons
                                if x.startswith(("Google Safe Browsing lists", "VirusTotal:"))), "")
                    strong.append(f"Page scan: the hidden destination {final_host} is a known scam site. {hit}")
                elif intel.checked:
                    lines.append(f"Page scan: security databases have no record of {final_host} yet.")
            except Exception:
                pass

    if page.title and ERROR_TITLE.search(page.title):
        lines.append(f"Page scan: the final website isn't responding (\"{page.title}\"). "
                     "It may already have been taken down or abandoned.")
    elif page.title:
        lines.append(f"Page scan: the page title is \"{page.title}\".")
        low = page.title.lower()
        claims = [w for w in OFFICIAL_TITLE_WORDS if w.lower() in low]
        if claims and not official_final:
            strong.append(f"Page scan: the page presents itself as an official service "
                          f"(title mentions '{claims[0]}') but its address is not official.")

    if page.malicious:
        what = f" ({', '.join(page.categories)})" if page.categories else ""
        strong.append(f"Page scan: urlscan.io classifies this page as malicious{what}.")
    if page.brands:
        lines.append(f"Page scan: the page imitates {', '.join(page.brands[:3])}.")
        if not official_final:
            strong.append(f"Page scan: urlscan.io detected an imitation of {', '.join(page.brands[:3])}.")

    if page.asks_for:
        lines.append(f"Page scan: the page asks for your {', '.join(page.asks_for)}.")
        had_warnings = result.verdict in (SUSPICIOUS, SCAM)
        if not official_final and had_warnings and any(
                x in page.asks_for for x in ("card number", "CVV code", "one-time code (OTP)", "CPR / ID number")):
            strong.append("Page scan: an unofficial website asking for card details or codes "
                          "is a classic scam sign.")
    elif page.final_url and not (page.title and ERROR_TITLE.search(page.title)):
        lines.append("Page scan: no card, code or password fields were found on the first page.")

    if strong and result.verdict != SAFE:
        result.verdict = SCAM
    if result.verdict != SAFE:
        result.reasons = strong + result.reasons + lines
    else:
        result.reasons = result.reasons + strong + lines
    return strong + lines

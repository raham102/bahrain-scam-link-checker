"""
The checking service used by the website (app.py).

Runs every layer on a link and returns plain data (a dict) that the web page can show:
  Layer 1  domain and brand checks        (link_checker.py)
  Layer 2  Google Safe Browsing, VirusTotal (threat_intel.py)
  Layer 3  ML model                        (url_features.py)
  Layer 4  AI explanation, EN + AR         (explain.py)

Nothing here ever opens the link - only its address is analysed.
"""

import re
import threading
import time

import explain
import threat_intel
from link_checker import SAFE, check_url, get_host, load_allowlist, refang

MAX_TEXT = 2000           # characters accepted from the text box
MAX_LINKS = 3             # links checked per message
CACHE_SECONDS = 30 * 60   # reuse a result for 30 minutes (saves API quota)

# http(s)/hxxp(s) links, or bare domains like gulfairsz.bond/air
# A link ends at whitespace, quotes or any Arabic character/punctuation (، ؛ ؟ ...)
_URL_CHARS = r"[^\s<>\"'\u0600-\u06FF]"
URL_RE = re.compile(
    rf"(?:h(?:tt|xx)ps?://{_URL_CHARS}+)"
    rf"|(?:\b(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{{2,24}}\b(?:/{_URL_CHARS}*)?)",
    re.IGNORECASE,
)

_allowlist = None
_keys = None
_ml_ready = None
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def _setup():
    global _allowlist, _keys, _ml_ready
    if _allowlist is None:
        _allowlist = load_allowlist()
        _keys = threat_intel.load_keys()
        try:
            import url_features
            url_features.load_model()
            _ml_ready = True
        except Exception:
            _ml_ready = False


def extract_links(text: str) -> list[str]:
    """Find up to MAX_LINKS links in a pasted message (or a single link)."""
    text = (text or "")[:MAX_TEXT]
    found = []
    for m in URL_RE.finditer(text):
        link = m.group(0).rstrip(".,;:!?)»”’'\"")
        if m.start() > 0 and text[m.start() - 1] in "@.":   # part of an e-mail address
            continue
        if link.lower() not in (f.lower() for f in found):
            found.append(link)
        if len(found) >= MAX_LINKS:
            break
    return found


def check_link(link: str) -> dict:
    _setup()
    key = refang(link).lower()
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < CACHE_SECONDS:
            return {**hit[1], "cached": True}

    real = refang(link)
    if not re.match(r"^[a-z][a-z0-9+.-]*://", real, re.I):
        real = "http://" + real
    result = check_url(link, _allowlist)
    layers = ["Domain and brand checks"]

    if result.verdict != SAFE and (_keys.get("GSB_API_KEY") or _keys.get("VT_API_KEY")):
        intel = threat_intel.check_many([real], _keys, vt_wait=False)[real]
        threat_intel.apply_intel(result, intel)
        layers.append("Threat intelligence")

    if result.verdict != SAFE and _ml_ready:
        import url_features
        url_features.apply_ml(result)
        layers.append("Machine-learning model")

    exp = explain.explain(result, _keys)
    layers.append("AI explanation" if exp["source"] == "ai" else "Built-in explanation")

    data = {
        "link": explain.defang(result.url),
        "host": get_host(real),
        "verdict": result.verdict,
        "label": exp["label"],
        "en": exp["en"],
        "ar": exp["ar"],
        "evidence": result.reasons,
        "layers": layers,
        "explanation_source": exp["source"],
        "cached": False,
    }
    with _lock:
        _cache[key] = (time.time(), data)
        if len(_cache) > 5000:                      # keep memory bounded
            for k, _ in sorted(_cache.items(), key=lambda kv: kv[1][0])[:1000]:
                _cache.pop(k, None)
    return data


SEVERITY = {"SCAM": 0, "SUSPICIOUS": 1, "SAFE": 2}


def check_text(text: str) -> dict:
    links = extract_links(text)
    results = sorted((check_link(l) for l in links), key=lambda r: SEVERITY[r["verdict"]])  # worst first
    return {"found": len(links), "results": results}


# ---------------------------------------------------------------------------
# Layer 5: page scan (started by the user with a button, takes 30-60 seconds)
# ---------------------------------------------------------------------------

import datetime as _dt

import page_scan

_jobs: dict[str, dict] = {}
_shots: dict[str, bytes] = {}
_daily = {"day": "", "count": 0}


def page_scan_available() -> bool:
    _setup()
    return bool(_keys.get("URLSCAN_API_KEY"))


def _daily_limit_reached() -> bool:
    today = _dt.date.today().isoformat()
    limit = int(_keys.get("URLSCAN_DAILY_LIMIT") or 50)
    with _lock:
        if _daily["day"] != today:
            _daily.update(day=today, count=0)
        if _daily["count"] >= limit:
            return True
        _daily["count"] += 1
    return False


def start_page_scan(link: str) -> dict:
    """Submit the page to urlscan.io. Returns {"status": "pending", "scan_id"} or a final status."""
    _setup()
    key = refang(link).lower()
    with _lock:
        cached = _cache.get(key)
    if not cached:                       # only links that were checked first can be scanned
        cached = (time.time(), check_link(link))
    base = cached[1]
    if base["verdict"] == SAFE:
        return {"status": "not_needed"}
    if not page_scan_available():
        return {"status": "unavailable"}
    if _daily_limit_reached():
        return {"status": "quota"}

    real = refang(link)
    if not re.match(r"^[a-z][a-z0-9+.-]*://", real, re.I):
        real = "http://" + real
    try:
        uid = page_scan.submit(real, _keys["URLSCAN_API_KEY"], _keys.get("URLSCAN_VISIBILITY", "unlisted"))
    except page_scan.ScanError as e:
        return {"status": e.kind, "message": str(e)}
    with _lock:
        _jobs[uid] = {"link": link, "real": real, "base": base, "started": time.time(), "done": None}
    return {"status": "pending", "scan_id": uid}


def poll_page_scan(uid: str) -> dict:
    """Return {"status": "pending"} until ready, then the full updated result."""
    with _lock:
        job = _jobs.get(uid)
    if not job:
        return {"status": "unknown"}
    if job["done"]:
        return job["done"]
    if time.time() - job["started"] < 8:          # urlscan never finishes faster than this
        return {"status": "pending"}
    if time.time() - job["started"] > page_scan.GIVE_UP_AFTER:
        return {"status": "timeout", "message": "The page scan took too long. Try again later."}
    try:
        raw = page_scan.fetch_result(uid, _keys["URLSCAN_API_KEY"])
    except page_scan.ScanError as e:
        return {"status": e.kind, "message": str(e)}
    if raw is None:
        return {"status": "pending"}

    page = page_scan.parse(uid, raw, page_scan.fetch_dom(uid, _keys["URLSCAN_API_KEY"]))
    from link_checker import Result
    base = job["base"]
    r = Result(url=job["real"], host=base["host"], verdict=base["verdict"], reasons=list(base["evidence"]))
    page_scan.apply_page(r, page, _allowlist, _keys)
    exp = explain.explain(r, _keys)
    done = {
        **base,
        "status": "done",
        "verdict": r.verdict, "label": exp["label"], "en": exp["en"], "ar": exp["ar"],
        "evidence": r.reasons,
        "layers": [l for l in base["layers"] if "explanation" not in l.lower()]
                  + ["Page scan (urlscan.io sandbox)",
                     "AI explanation" if exp["source"] == "ai" else "Built-in explanation"],
        "page": {
            "final_link": explain.defang(page.final_url) if page.final_url else "",
            "final_domain": page.final_domain,
            "title": page.title,
            "asks_for": page.asks_for,
            "loaded": not (page.title and page_scan.ERROR_TITLE.search(page.title)),
            "screenshot": f"/api/page-scan/{uid}/screenshot",
            "report": f"https://urlscan.io/result/{uid}/",
        },
    }
    with _lock:
        job["done"] = done
        _cache[refang(job["link"]).lower()] = (time.time(), {k: v for k, v in done.items() if k != "status"})
        if len(_jobs) > 2000:
            for k in sorted(_jobs, key=lambda k: _jobs[k]["started"])[:500]:
                _jobs.pop(k, None)
    return done


def page_screenshot(uid: str) -> bytes | None:
    if uid not in _jobs:
        return None
    with _lock:
        if uid in _shots:
            return _shots[uid]
    img = page_scan.fetch_screenshot(uid, _keys["URLSCAN_API_KEY"])
    if img:
        with _lock:
            _shots[uid] = img
            if len(_shots) > 200:
                _shots.pop(next(iter(_shots)))
    return img

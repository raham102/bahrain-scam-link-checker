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

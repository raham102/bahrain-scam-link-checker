"""
Turn a URL into numbers a machine-learning model can learn from.

Only the URL text is used - the link is never opened - so this is safe and fast.

Before extracting features the URL is normalised: the scheme (http/https) and a
leading "www." are removed. In many public datasets almost every legitimate URL
starts with "https://www.", so a model would otherwise learn that shortcut
instead of real phishing patterns.
"""

import math
import re
from collections import Counter
from urllib.parse import urlsplit

from link_checker import RISKY_TLDS, URL_SHORTENERS, split_domain, is_ip, refang

SUSPICIOUS_WORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
    "confirm", "bank", "pay", "payment", "wallet", "password", "billing", "support",
    "unlock", "suspend", "invoice", "refund", "webscr", "ebayisapi", "auth", "session",
]

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_subdomains", "num_dots_host", "num_hyphens_host", "num_digits_host",
    "host_entropy", "path_entropy", "digit_ratio", "special_ratio",
    "num_params", "num_equals", "num_percent", "num_at", "num_double_slash",
    "path_depth", "longest_token", "num_tokens",
    "has_ip", "has_port", "is_punycode", "is_shortener",
    "tld_length", "tld_risky", "ends_php_html", "suspicious_words", "host_suspicious_words",
]

# Features that only look at the domain name, not the path. Public datasets often have
# legitimate URLs that are bare homepages, so path-based features can teach the model the
# shortcut "has a path = phishing". The host-only model avoids that.
HOST_FEATURES = [
    "host_length", "num_subdomains", "num_dots_host", "num_hyphens_host", "num_digits_host",
    "host_entropy", "has_ip", "has_port", "is_punycode", "is_shortener",
    "tld_length", "tld_risky", "host_suspicious_words",
]

FEATURE_SETS = {"full": FEATURE_NAMES, "host": HOST_FEATURES}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def normalise(url: str) -> str:
    url = refang(str(url)).strip()
    url = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url, flags=re.I)
    url = re.sub(r"^www\d?\.", "", url, flags=re.I)
    return url.rstrip("/")


def extract_features(url: str) -> list[float]:
    norm = normalise(url)
    parts = urlsplit("http://" + norm)
    host = (parts.hostname or "").lower()
    path, query = parts.path or "", parts.query or ""
    sub, dom, suffix = split_domain(host)
    tld = suffix.split(".")[-1] if suffix else ""
    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", norm) if t]
    low = norm.lower()
    n = max(len(norm), 1)

    f = {
        "url_length": len(norm),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_subdomains": len([s for s in sub.split(".") if s]) if sub else 0,
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(ch.isdigit() for ch in host),
        "host_entropy": _entropy(host),
        "path_entropy": _entropy(path + query),
        "digit_ratio": sum(ch.isdigit() for ch in norm) / n,
        "special_ratio": sum(not ch.isalnum() for ch in norm) / n,
        "num_params": len([q for q in query.split("&") if q]),
        "num_equals": norm.count("="),
        "num_percent": norm.count("%"),
        "num_at": norm.count("@"),
        "num_double_slash": norm.count("//"),
        "path_depth": len([p for p in path.split("/") if p]),
        "longest_token": max((len(t) for t in tokens), default=0),
        "num_tokens": len(tokens),
        "has_ip": int(bool(host) and is_ip(host)),
        "has_port": int(parts.port is not None) if _safe_port(parts) else 0,
        "is_punycode": int("xn--" in host),
        "is_shortener": int(f"{dom}.{suffix}" in URL_SHORTENERS),
        "tld_length": len(tld),
        "tld_risky": int(tld in RISKY_TLDS),
        "ends_php_html": int(bool(re.search(r"\.(php|html?|aspx?)$", path.lower()))),
        "suspicious_words": sum(w in low for w in SUSPICIOUS_WORDS),
        "host_suspicious_words": sum(w in host for w in SUSPICIOUS_WORDS),
    }
    return [float(f[name]) for name in FEATURE_NAMES]


def features_for(url: str, names: list[str]) -> list[float]:
    """Only the chosen features, in the given order."""
    full = dict(zip(FEATURE_NAMES, extract_features(url)))
    return [full[n] for n in names]


def _safe_port(parts) -> bool:
    try:
        parts.port
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Using the trained model inside the checker
# ---------------------------------------------------------------------------

_MODEL = None
_POPULAR = None

# Popular, but anyone can publish a page on them - scammers do, so no protection
FREE_HOSTING = {
    "github.io", "blogspot.com", "web.app", "firebaseapp.com", "weebly.com", "wixsite.com",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "glitch.me", "000webhostapp.com",
    "godaddysites.com", "square.site", "webflow.io", "framer.app", "notion.site", "carrd.co",
    "wordpress.com", "sharepoint.com", "ngrok.io", "ngrok-free.app", "herokuapp.com",
    "azurewebsites.net", "appspot.com", "r2.dev", "repl.co", "surge.sh", "gitbook.io",
    "jimdosite.com", "mystrikingly.com", "ipfs.io", "dweb.link", "translate.goog",
}
# Specific hosts on otherwise trusted domains that let anyone publish content
FREE_HOSTING_HOSTS = {"sites.google.com", "docs.google.com", "forms.gle", "storage.googleapis.com",
                      "drive.google.com", "forms.office.com", "1drv.ms", "dropbox.com"}


def load_popular(path=None) -> set[str]:
    global _POPULAR
    if _POPULAR is None:
        from pathlib import Path
        path = Path(path or Path(__file__).with_name("popular_domains.txt"))
        _POPULAR = set()
        if path.exists():
            _POPULAR = {l.strip() for l in path.read_text(encoding="utf-8").splitlines()
                        if l.strip() and not l.startswith("#")}
    return _POPULAR


def popular_domain(url: str) -> str | None:
    """Return the registered domain if it is a well-known site that can't be used for free hosting."""
    from link_checker import get_host
    host = get_host(refang(url))
    _, dom, suffix = split_domain(host)
    reg = f"{dom}.{suffix}" if suffix else host
    if reg in FREE_HOSTING or host in FREE_HOSTING_HOSTS or any(host.endswith("." + h) for h in FREE_HOSTING):
        return None
    return reg if reg in load_popular() else None


def load_model(path=None):
    global _MODEL
    if _MODEL is None:
        import joblib
        from pathlib import Path
        path = Path(path or Path(__file__).with_name("phishing_model.joblib"))
        if not path.exists():
            raise FileNotFoundError("phishing_model.joblib not found - run train_model.py first.")
        _MODEL = joblib.load(path)
    return _MODEL


def phishing_probability(url: str) -> float:
    bundle = load_model()
    return float(bundle["model"].predict_proba([features_for(url, bundle["features"])])[0, 1])


def apply_ml(result):
    """Add the model's opinion to a Layer 1/2 result.

    * Never changes a SAFE (allowlisted) verdict.
    * Probability above the high-precision threshold -> SCAM.
    * Otherwise it only adds a line of evidence.
    """
    from link_checker import SAFE, SCAM
    if result.verdict == SAFE:
        return result
    bundle = load_model()
    p = phishing_probability(result.url)
    thr = bundle["scam_threshold"]
    popular = popular_domain(result.url)
    if p >= thr and popular:
        result.reasons.append(f"ML model: {p:.0%} phishing score, but {popular} is one of the world's most "
                              "popular websites (Tranco top list), so the model alone does not call it a scam.")
    elif p >= thr:
        result.verdict = SCAM
        result.reasons.insert(0, f"ML model: {p:.0%} likely phishing based on the link's structure "
                                 f"(scam threshold {thr:.0%}).")
    elif p >= 0.5:
        result.reasons.append(f"ML model: {p:.0%} likely phishing - not certain enough to call it a scam.")
    else:
        result.reasons.append(f"ML model: URL structure looks low-risk ({p:.0%} phishing score), "
                              "but that alone does not make it safe.")
    return result

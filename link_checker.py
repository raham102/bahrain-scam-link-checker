#!/usr/bin/env python3
"""
Bahrain Scam Link Checker - Layer 1: domain checks
--------------------------------------------------
Classifies a URL as SAFE, SUSPICIOUS or SCAM using only the URL itself
(it never opens the link), plus an optional domain-age (WHOIS) lookup.

Usage:
    python link_checker.py "https://www.nbr.gov.bh"
    python link_checker.py url1 url2 url3
    python link_checker.py --file links.txt          # one URL per line
    python link_checker.py --demo                    # run built-in test cases
    python link_checker.py --whois "https://..."     # also check domain age
    python link_checker.py --intel "https://..."     # Layer 2: threat intelligence
    python link_checker.py --ml "https://..."        # Layer 3: trained ML model
    python link_checker.py --intel --ml "https://..." # layers 1-3
    python link_checker.py --intel --ml --explain "https://..."   # + AI explanation (EN + AR)
    python link_checker.py --explain --lang ar "https://..."      # Arabic only
    python link_checker.py --intel --ml --scan --explain "https://..."  # all 5 layers

Requirements:
    pip install openpyxl tldextract python-whois
    (python-whois is only needed for --whois)

The allowlist is read from bahrain_official_domains_allowlist.xlsx
(sheet "Allowlist", column D) - keep it in the same folder as this script.
"""

import argparse
import ipaddress
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

ALLOWLIST_FILE = Path(__file__).with_name("bahrain_official_domains_allowlist.xlsx")

OFFICIAL_SUFFIX = "gov.bh"          # every *.gov.bh domain is official

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "s.id", "tiny.cc",
}

# Cheap / abused TLDs often used in phishing (raise suspicion, not proof)
RISKY_TLDS = {
    "xyz", "top", "click", "online", "site", "live", "icu", "buzz", "shop",
    "info", "cfd", "sbs", "rest", "support", "help", "cc", "vip", "work",
    "bond", "run", "cyou", "lol", "mom", "today", "fun", "space", "website", "life",
    "quest", "autos", "boats", "hair", "beauty", "skin", "monster", "cam", "win", "bid", "loan",
}

# Third-party addresses that imitate country domains (e.g. shop.sa.com looks Saudi but isn't)
RESELLER_SUFFIXES = {
    "sa.com": "Saudi Arabia", "ae.org": "UAE", "us.com": "USA", "uk.com": "UK", "eu.com": "EU",
    "cn.com": "China", "gb.net": "UK", "za.com": "South Africa", "br.com": "Brazil",
    "ru.com": "Russia", "de.com": "Germany", "jpn.com": "Japan", "in.net": "India",
}

# Bahraini / regional companies scammers often impersonate.
# keyword -> (brand name, real domains). Keywords of 4 letters or fewer must appear as a
# separate word in the domain AND come with another red flag (risky ending or lure word),
# because short words can appear in innocent names.
# Real domains: verify each one before relying on it.
IMPERSONATED_BRANDS = {
    "gulfair": ("Gulf Air", {"gulfair.com"}),
    "ilabank": ("ila Bank", {"ilabank.com"}),
    "ila": ("ila Bank", {"ilabank.com"}),
    "aramex": ("Aramex", {"aramex.com"}),
    "batelco": ("Batelco", {"batelco.com"}),
    "bbkonline": ("BBK", {"bbkonline.com"}),
    "bbk": ("BBK", {"bbkonline.com"}),
    "nbbonline": ("National Bank of Bahrain", {"nbbonline.com"}),
    "nbb": ("National Bank of Bahrain", {"nbbonline.com"}),
    "bisb": ("Bahrain Islamic Bank", {"bisb.com"}),
    "benefitpay": ("BenefitPay", {"benefit.bh"}),
    "bahrainpost": ("Bahrain Post", {"mtt.gov.bh"}),
    "stc": ("stc Bahrain", {"stc.com.bh"}),
    "talabat": ("Talabat", {"talabat.com"}),
    "aramco": ("Aramco", {"aramco.com"}),
    "dhl": ("DHL", {"dhl.com"}),
    "fedex": ("FedEx", {"fedex.com"}),
}
BRAND_DOMAINS = set().union(*(d for _, d in IMPERSONATED_BRANDS.values()))

# Words scammers put in fake government / payment domains
LURE_WORDS = {
    "gov", "govt", "government", "ministry", "moi", "traffic", "fine", "fines",
    "violation", "pay", "payment", "refund", "benefit", "benefitpay", "ewa",
    "post", "parcel", "delivery", "customs", "nbr", "vat", "lmra", "sio",
    "egov", "portal", "secure", "verify", "update", "police", "passport",
}

BRAND_WORDS = {"bahrain", "bh", "bahrainpost", "mygov"}

# Domain age below this (days) is treated as "newly registered"
NEW_DOMAIN_DAYS = 30


# ---------------------------------------------------------------------------
# Domain parsing (tldextract, with a small offline fallback)
# ---------------------------------------------------------------------------

try:
    import tldextract
    # suffix_list_urls=() -> use the bundled Public Suffix List, no network needed
    _extract = tldextract.TLDExtract(suffix_list_urls=())

    def split_domain(host: str):
        r = _extract(host)
        return r.subdomain, r.domain, r.suffix
except ImportError:  # minimal fallback so the script still runs
    _MULTI = {"gov.bh", "com.bh", "edu.bh", "org.bh", "net.bh", "co.uk",
              "com.sa", "gov.sa", "co.in", "com.au"}

    def split_domain(host: str):
        parts = host.split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI:
            return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
        if len(parts) >= 2:
            return ".".join(parts[:-2]), parts[-2], parts[-1]
        return "", host, ""


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def load_allowlist(path: Path = ALLOWLIST_FILE) -> set[str]:
    from openpyxl import load_workbook
    wb = load_workbook(path, read_only=True, data_only=True)
    ws = wb["Allowlist"]
    domains = set()
    for row in ws.iter_rows(min_row=5, min_col=4, max_col=4, values_only=True):
        value = (row[0] or "").strip().lower()
        if value and "." in value:
            domains.add(value)
    return domains | BRAND_DOMAINS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def refang(url: str) -> str:
    """Turn defanged links back into real ones: hxxps://a[.]com -> https://a.com"""
    url = url.strip()
    url = re.sub(r"^hxxp", "http", url, flags=re.I)
    return url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def get_host(url: str) -> str:
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def decode_punycode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def to_ascii_lookalike(text: str) -> str:
    """Map look-alike Unicode letters (e.g. Cyrillic 'а') to plain ASCII."""
    confusables = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
                   "у": "y", "і": "i", "ӏ": "l", "ԁ": "d", "һ": "h", "ո": "n"}
    text = "".join(confusables.get(ch, ch) for ch in text)
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (OSA): swapping two letters ('bahrian') counts as 1 edit."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def matches_allowlist(host: str, allowlist: set[str]) -> str | None:
    """Return the allowlisted domain if host IS it or is a real subdomain of it."""
    for d in allowlist:
        if host == d or host.endswith("." + d):
            return d
    return None


def tokens(text: str) -> set[str]:
    return set(t for t in re.split(r"[^a-z0-9]+", text) if t)


def domain_age_days(registered_domain: str) -> int | None:
    try:
        import whois
        info = whois.whois(registered_domain)
        created = info.creation_date
        if isinstance(created, list):
            created = min(created)
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------

SAFE, SUSPICIOUS, SCAM = "SAFE", "SUSPICIOUS", "SCAM"


@dataclass
class Result:
    url: str
    host: str = ""
    verdict: str = SUSPICIOUS
    reasons: list[str] = field(default_factory=list)


def check_url(url: str, allowlist: set[str], use_whois: bool = False) -> Result:
    res = Result(url=url)
    host = get_host(refang(url))
    res.host = host

    if not host:
        res.reasons.append("Could not read a hostname from this link.")
        return res

    # Rule 7a: raw IP address
    if is_ip(host):
        res.reasons.append("Link uses a raw IP address instead of a domain name.")
        return res

    # Rule 6: punycode / Unicode tricks
    shown_host = decode_punycode(host)
    unicode_trick = "xn--" in host or shown_host != host
    plain_host = to_ascii_lookalike(shown_host)

    sub, dom, suffix = split_domain(host)
    registered = f"{dom}.{suffix}" if suffix else dom

    # Rules 2 & 3: official domains
    if not unicode_trick:
        if suffix == OFFICIAL_SUFFIX or host == OFFICIAL_SUFFIX:
            res.verdict = SAFE
            res.reasons.append(f"Domain ends with .{OFFICIAL_SUFFIX} - official Bahrain government domain.")
            return res
        hit = matches_allowlist(host, allowlist)
        if hit:
            res.verdict = SAFE
            res.reasons.append(f"Matches allowlisted official domain: {hit}")
            return res

    # Rule 7b: URL shorteners
    if registered in URL_SHORTENERS:
        res.reasons.append(f"Shortened link ({registered}) hides the real destination - expand it and check again.")
        return res

    scam_signals, warn_signals = [], []

    if unicode_trick:
        msg = f"Uses Unicode/punycode characters (displays as '{shown_host}')."
        if matches_allowlist(plain_host, allowlist) or plain_host.endswith("." + OFFICIAL_SUFFIX):
            scam_signals.append(msg + f" It imitates the official domain '{plain_host}'.")
        else:
            warn_signals.append(msg)

    # Rule 4: official domain name embedded inside another domain
    for d in sorted(allowlist | {OFFICIAL_SUFFIX}, key=len, reverse=True):
        if d in plain_host and not plain_host.endswith(d):
            scam_signals.append(f"Contains the official name '{d}' but the real domain is '{registered}'.")
            break

    tld = suffix.split(".")[-1] if suffix else ""
    words = tokens(plain_host)
    label_text = to_ascii_lookalike(decode_punycode(f"{sub}.{dom}" if sub else dom))
    label_words = tokens(label_text)
    reseller = next((r for r in RESELLER_SUFFIXES if host == r or host.endswith("." + r)), None)
    cheap_ending = tld in RISKY_TLDS or reseller is not None
    lure_hit = LURE_WORDS & words

    # Rule 5a: impersonated company brands (Gulf Air, ila Bank, Aramex ...)
    for kw, (brand, real) in IMPERSONATED_BRANDS.items():
        found = (kw in label_text.replace("-", "")) if len(kw) > 4 else (kw in label_words)
        if not found or any(registered == d or host.endswith("." + d) for d in real):
            continue
        msg = f"Uses the name '{brand}' but the real {brand} site is {', '.join(sorted(real))}."
        if len(kw) > 4 or cheap_ending or lure_hit:
            scam_signals.append(msg)
        else:
            warn_signals.append(msg)
        break

    # Rule 5b: domains that target Bahrain: 'bahrain' + country code, or Bahrain + cheap ending
    bahrain_word = any("bahrain" in w for w in label_words)
    # Note: "starts with bh" was tried and rejected - it flags common names like bhatia, bharat
    country_code = bool({"bh", "bhr"} & label_words) or dom.endswith(("bh", "bhr"))
    if bahrain_word and country_code:
        scam_signals.append(f"Combines 'bahrain' with Bahrain's country code to look official, "
                            f"but the real domain is '{registered}'.")
    elif (bahrain_word or country_code) and cheap_ending:
        ending = f"'{reseller}'" if reseller else f"'.{tld}'"
        scam_signals.append(f"Targets Bahrain ('{'bahrain' if bahrain_word else 'bh'}' in the name) "
                            f"on a cheap {ending} domain - official sites never use these.")

    # Rule 5: look-alike spelling of an official domain
    check_label = to_ascii_lookalike(decode_punycode(dom))
    for d in ([] if scam_signals else allowlist):
        d_sub, d_dom, d_suffix = split_domain(d)
        if len(d_dom) < 5:          # too short - would cause false alarms
            continue
        dist = edit_distance(check_label, d_dom)
        limit = 1 if len(d_dom) <= 7 else 2
        if 0 < dist <= limit:
            scam_signals.append(f"Domain '{registered}' is a misspelling of official domain '{d}'.")
            break
        if dist == 0 and registered != d and not unicode_trick:
            warn_signals.append(f"Same name as official domain '{d}' but a different ending ('{registered}').")
            break

    # gov / bh written as part of the name: gov-bh.com, bahrain-gov.net ...
    if ({"gov", "govbh"} & words or "gov-bh" in plain_host) and ({"bh", "bahrain"} & words or "govbh" in words):
        scam_signals.append("Domain pretends to be a Bahrain government site (contains 'gov' + 'bh/bahrain') but isn't under .gov.bh.")

    # Brand + lure words: bahrain-traffic-fines.com, benefitpay-refund.xyz ...
    brand_hit = BRAND_WORDS & label_words or {w for w in label_words if "bahrain" in w}
    if brand_hit and lure_hit and not scam_signals:
        warn_signals.append(f"Mixes Bahrain branding ({', '.join(sorted(brand_hit))}) with lure words ({', '.join(sorted(lure_hit))}).")
    elif brand_hit and not scam_signals:
        warn_signals.append("Mentions Bahrain but is not an official domain.")

    if tld in RISKY_TLDS:
        warn_signals.append(f"Uses the '.{tld}' ending, which is common in scam sites.")
    if reseller:
        warn_signals.append(f"Uses a '{reseller}' address, which imitates a {RESELLER_SUFFIXES[reseller]} "
                            "domain but is a cheap third-party name.")

    if host.count(".") >= 4:
        warn_signals.append("Unusually many subdomains - a common trick to hide the real domain.")

    # Step 4: domain age (optional, needs network)
    if use_whois:
        age = domain_age_days(registered)
        if age is None:
            warn_signals.append("Domain age could not be checked.")
        elif age < NEW_DOMAIN_DAYS:
            msg = f"Domain was registered only {age} day(s) ago."
            (scam_signals if (brand_hit or lure_hit) else warn_signals).append(msg)
        else:
            res.reasons.append(f"Domain is {age} days old.")

    if scam_signals:
        res.verdict = SCAM
        res.reasons = scam_signals + warn_signals + res.reasons
    else:
        res.verdict = SUSPICIOUS
        res.reasons = warn_signals + res.reasons
        if not warn_signals:
            res.reasons.insert(0, "Not an official domain. No impersonation signs found, "
                                  "but it needs further checks (threat intel, page analysis).")
    return res


# ---------------------------------------------------------------------------
# Output / CLI
# ---------------------------------------------------------------------------

ICONS = {SAFE: "✅", SUSPICIOUS: "⚠️ ", SCAM: "⛔"}


def print_result(r: Result):
    print(f"\n{ICONS[r.verdict]} {r.verdict:<10} {r.url}")
    print(f"   host: {r.host}")
    for reason in r.reasons:
        print(f"   - {reason}")


DEMO = [
    # (url, expected verdict)
    ("https://www.nbr.gov.bh/vat", SAFE),
    ("https://services.bahrain.bh/wps/portal", SAFE),
    ("https://www.ewa.bh/en", SAFE),
    ("benefit.bh", SAFE),
    ("hxxps://bahrain.bh.secure-pay[.]com/fines", SCAM),
    ("https://gov-bh.com/traffic", SCAM),
    ("https://bahrain-gov-payment.xyz", SCAM),
    ("https://www.bahrian.bh", SCAM),
    ("https://traffic.gov.bh.verify-now.top/pay", SCAM),
    ("https://xn--bahrin-6nf.bh", SCAM),          # 'bahrаin.bh' with a Cyrillic 'а'
    ("https://www.newsofbahrain.com", SUSPICIOUS),  # real news site: not official, but no impersonation
    ("http://45.12.33.10/traffic", SUSPICIOUS),
    ("https://bit.ly/3abcXYZ", SUSPICIOUS),
    ("https://bahrainpost-delivery.online", SCAM),
    # real scam links sent to people in Bahrain (defanged)
    ("hxxps://bahrain-bhr[.]com/bl", SCAM),
    ("hxxps://gulfairsz[.]bond/air", SCAM),
    ("hxxps://ila-app[.]live/ib/", SCAM),
    ("hxxp://arxbh[.]cc/bh", SCAM),
    ("https://www.bhatia.cc/", SUSPICIOUS),      # must NOT be called a Bahrain scam
    ("https://www.gulfair.com/", SAFE),
    ("https://shura.bh/en/", SAFE),
    ("https://www.example.com", SUSPICIOUS),
]


def main():
    p = argparse.ArgumentParser(description="Bahrain scam link checker (domain layer)")
    p.add_argument("urls", nargs="*", help="URLs to check")
    p.add_argument("--file", help="text file with one URL per line")
    p.add_argument("--demo", action="store_true", help="run built-in test cases")
    p.add_argument("--whois", action="store_true", help="also check domain age (needs internet)")
    p.add_argument("--scan", action="store_true",
                   help="Layer 5: open the page safely in urlscan.io's sandbox (needs URLSCAN_API_KEY; ~30-60 s)")
    p.add_argument("--explain", action="store_true",
                   help="Layer 4: plain-language explanation by AI (needs GEMINI_API_KEY in .env)")
    p.add_argument("--lang", choices=["en", "ar", "both"], default="both", help="language for --explain")
    p.add_argument("--ml", action="store_true",
                   help="Layer 3: add the trained ML model's score (needs phishing_model.joblib)")
    p.add_argument("--intel", action="store_true",
                   help="Layer 2: check Google Safe Browsing + VirusTotal (needs .env with API keys)")
    p.add_argument("--allowlist", default=str(ALLOWLIST_FILE), help="path to the allowlist .xlsx")
    args = p.parse_args()

    allowlist = load_allowlist(Path(args.allowlist))
    print(f"Loaded {len(allowlist)} allowlisted domains (+ every *.{OFFICIAL_SUFFIX}).")

    if args.demo:
        passed = 0
        for url, expected in DEMO:
            r = check_url(url, allowlist, args.whois)
            print_result(r)
            ok = r.verdict == expected
            passed += ok
            if not ok:
                print(f"   !! expected {expected}")
        print(f"\nDemo: {passed}/{len(DEMO)} matched the expected verdict.")
        return

    urls = list(args.urls)
    if args.file:
        urls += [line.strip() for line in Path(args.file).read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.startswith("#")]
    if not urls:
        p.print_help()
        sys.exit(1)

    results = [check_url(url, allowlist, args.whois) for url in urls]

    if args.intel:
        import threat_intel
        keys = threat_intel.load_keys()
        if not keys:
            print("No API keys found. Create a .env file (see .env.example).")
        else:
            # Official domains are already SAFE - only look up the others
            todo = [r for r in results if r.verdict != SAFE]
            real = {r.url: refang(r.url) if "://" in refang(r.url) else "http://" + refang(r.url)
                    for r in todo}
            if todo and keys.get("VT_API_KEY") and len(todo) > 1:
                print(f"Checking {len(todo)} link(s) with VirusTotal "
                      f"(free tier: ~15 s per link, about {len(todo) * 15 // 60 + 1} min)...")
            intel = threat_intel.check_many(list(real.values()), keys)
            for r in todo:
                threat_intel.apply_intel(r, intel[real[r.url]])

    if args.ml:
        import url_features
        for r in results:
            url_features.apply_ml(r)

    if args.scan:
        import page_scan
        import threat_intel
        skeys = threat_intel.load_keys()
        if not skeys.get("URLSCAN_API_KEY"):
            print("No URLSCAN_API_KEY in .env - skipping the page scan.")
        else:
            for r in results:
                if r.verdict == SAFE:
                    continue
                real = refang(r.url) if "://" in refang(r.url) else "http://" + refang(r.url)
                print(f"Scanning {r.host} in urlscan.io's sandbox (30-60 s)...", flush=True)
                try:
                    page = page_scan.scan_and_wait(real, skeys["URLSCAN_API_KEY"],
                                                   skeys.get("URLSCAN_VISIBILITY", "unlisted"),
                                                   progress=lambda: print("  still scanning...", flush=True))
                    page_scan.apply_page(r, page, allowlist, skeys)
                    r.reasons.append(f"Page scan report: https://urlscan.io/result/{page.uuid}/")
                except page_scan.ScanError as e:
                    r.reasons.append(f"Page scan: {e}")

    if args.explain:
        import explain
        import threat_intel
        keys = threat_intel.load_keys()

    for r in results:
        print_result(r)
        if args.explain:
            explain.print_explanation(explain.explain(r, keys), args.lang)


if __name__ == "__main__":
    main()

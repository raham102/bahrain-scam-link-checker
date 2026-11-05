#!/usr/bin/env python3
"""
Evaluate link_checker.py on real phishing links + known safe links.

    python evaluate.py                      # download the OpenPhish feed and test
    python evaluate.py --limit 100          # only test the first 100 phishing links
    python evaluate.py --feed-file feed.txt # use a feed you already downloaded
    python evaluate.py --intel              # add Layer 2 (Safe Browsing on all, VirusTotal on 20)
    python evaluate.py --intel --vt-limit 60  # VirusTotal on 60 links (~15 min)
    python evaluate.py --ml                 # Layer 1 + trained ML model
    python evaluate.py --intel --ml         # all layers

Output: evaluation_results.xlsx  (sheets: Summary, Results)

The links are only read as text - nothing is opened or visited.
"""

import argparse
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

from link_checker import check_url, load_allowlist, refang, SAFE, SUSPICIOUS, SCAM

FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

# Real official links - the checker should call these SAFE
KNOWN_SAFE = [
    "https://www.bahrain.bh/wps/portal/en/BNP/HomePage",
    "https://services.bahrain.bh/wps/portal/en/BSP/",
    "https://www.nbr.gov.bh/",
    "https://www.sio.gov.bh/",
    "https://www.lmra.gov.bh/en/",
    "https://www.interior.gov.bh/",
    "https://www.traffic.gov.bh/",
    "https://www.moh.gov.bh/",
    "https://www.moe.gov.bh/en/",
    "https://www.mofa.gov.bh/",
    "https://www.cbb.gov.bh/",
    "https://www.ncsc.gov.bh/en/",
    "https://www.csb.gov.bh/en/",
    "https://www.ppb.gov.bh/en/",
    "https://www.policemc.gov.bh/en/",
    "https://www.tenderboard.gov.bh/",
    "https://www.mtt.gov.bh/",
    "https://www.ewa.bh/en",
    "https://www.btea.bh/",
    "https://www.benefit.bh/",
    "https://www.nhra.bh/",
    "https://www.tra.org.bh/en/",
    "https://tamkeen.bh/en/",
    "https://www.shura.bh/en/",
    "https://www.nuwab.bh/en/",
    "https://www.uob.edu.bh/",
    "https://www.polytechnic.bh/",
    "https://www.bahrainedb.com/",
    "https://www.bna.bh/en/",
]


# Real scam links sent by SMS/WhatsApp to people in Bahrain (stored defanged).
# Add new ones as you collect them: they are the most realistic test set.
REAL_BAHRAIN_SCAMS = [
    "hxxps://bahrain-bhr[.]com/bl",
    "hxxps://services.bahrainer[.]cc/bh",
    "hxxp://arxbh[.]cc/bh",
    "hxxps://sw[.]run/xItjc",
    "hxxps://ila-app[.]live/ib/",
    "hxxps://gulfairsz[.]bond/air",
    "hxxps://acsrei[.]bond",
    "hxxps://shopchp.sa[.]com/ko",
]

GROUPS = ["Phishing (OpenPhish)", "Phishing (real Bahrain SMS)", "Safe (official)"]


def defang(url: str) -> str:
    """Make a link unclickable for safe sharing: https://a.com -> hxxps://a[.]com"""
    if "[.]" in url:
        return url
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def get_feed(feed_file: str | None) -> list[str]:
    if feed_file:
        text = Path(feed_file).read_text(encoding="utf-8")
    else:
        print("Downloading OpenPhish feed...")
        with urllib.request.urlopen(FEED_URL, timeout=30) as r:
            text = r.read().decode("utf-8", errors="ignore")
    return [line.strip() for line in text.splitlines() if line.strip()]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--feed-file", help="local feed file instead of downloading")
    p.add_argument("--limit", type=int, default=0, help="max phishing links to test (0 = all)")
    p.add_argument("--out", default="evaluation_results.xlsx")
    p.add_argument("--intel", action="store_true", help="also run Layer 2 (Safe Browsing + VirusTotal)")
    p.add_argument("--ml", action="store_true", help="also run Layer 3 (trained ML model)")
    p.add_argument("--vt-limit", type=int, default=20,
                   help="max links to send to VirusTotal (free tier ~15 s each; default 20)")
    args = p.parse_args()

    allowlist = load_allowlist()
    phishing = get_feed(args.feed_file)
    if args.limit:
        phishing = phishing[: args.limit]

    labelled = ([("Phishing (OpenPhish)", u) for u in phishing]
                + [("Phishing (real Bahrain SMS)", refang(u)) for u in REAL_BAHRAIN_SCAMS]
                + [("Safe (official)", u) for u in KNOWN_SAFE])
    results = [(label, url, check_url(url, allowlist)) for label, url in labelled]
    layer1 = {url: r.verdict for _, url, r in results}

    if args.intel:
        import threat_intel
        keys = threat_intel.load_keys()
        if not keys:
            raise SystemExit("No API keys found - create a .env file (see .env.example).")
        # Real Bahrain scams first, so they always get a VirusTotal lookup within --vt-limit
        todo = ([url for label, url, r in results if r.verdict != SAFE and label == GROUPS[1]]
                + [url for label, url, r in results if r.verdict != SAFE and label != GROUPS[1]])
        print(f"Google Safe Browsing: checking {len(todo)} links...")
        intel = threat_intel.check_many(todo, {"GSB_API_KEY": keys.get("GSB_API_KEY")})
        if keys.get("VT_API_KEY") and args.vt_limit:
            vt_urls = todo[: args.vt_limit]
            print(f"VirusTotal: checking {len(vt_urls)} links (~{len(vt_urls) * 15 // 60 + 1} min)...")
            vt = threat_intel.check_many(vt_urls, {"VT_API_KEY": keys["VT_API_KEY"]},
                                         progress=lambda i, n, u: print(f"  {i}/{n}", end="\r"))
            for u, res in vt.items():
                intel[u].vt_stats = res.vt_stats
                intel[u].checked += res.checked
                intel[u].errors += res.errors
            print()
        for _, url, r in results:
            if url in intel:
                threat_intel.apply_intel(r, intel[url])

    if args.ml:
        import url_features
        for _, _, r in results:
            url_features.apply_ml(r)

    rows = [(label, url, r.host, r.verdict, "; ".join(r.reasons), layer1[url]) for label, url, r in results]

    # ---- console summary ----
    for group in GROUPS:
        counts = Counter(r[3] for r in rows if r[0] == group)
        n = sum(counts.values())
        print(f"\n{group}: {n} links")
        order = (SAFE, SUSPICIOUS, SCAM) if group.startswith("Safe") else (SCAM, SUSPICIOUS, SAFE)
        for v in order:
            print(f"  {v:<10} {counts[v]:>4}  ({counts[v] / max(n, 1):.0%})")

    missed = [r for r in rows if r[0].startswith("Phishing") and r[3] == SAFE]
    wrongly_flagged = [r for r in rows if r[0].startswith("Safe") and r[3] != SAFE]
    print(f"\nPhishing links wrongly marked SAFE: {len(missed)}   <- most important, should be 0")
    print(f"Official links NOT marked SAFE:     {len(wrongly_flagged)}")
    if args.intel or args.ml:
        upgraded = sum(1 for r in rows if r[0].startswith("Phishing") and r[5] != SCAM and r[3] == SCAM)
        print(f"Phishing links upgraded to SCAM by the extra layers: {upgraded}")

    # ---- spreadsheet ----
    wb = Workbook()
    s = wb.active
    s.title = "Summary"
    layers = ["Layer 1 (domain)"] + (["Layer 2 (threat intel)"] if args.intel else []) + (["Layer 3 (ML)"] if args.ml else [])
    title = " + ".join(layers)
    s.append([f"Evaluation of {title}"])
    vt_note = f"   VirusTotal: first {args.vt_limit} non-official links" if args.intel else ""
    s.append([f"Run: {datetime.now():%Y-%m-%d %H:%M}   Source: OpenPhish public feed{vt_note}"])
    s.append([])
    s.append(["Group", "Verdict", "Count", "Share"])
    first = s.max_row + 1
    for label in GROUPS:
        for v in (SAFE, SUSPICIOUS, SCAM):
            row = s.max_row + 1
            s.append([label, v,
                      f'=COUNTIFS(Results!A:A,"{label}",Results!D:D,"{v}")',
                      f'=IF(COUNTIF(Results!A:A,"{label}")=0,0,C{row}/COUNTIF(Results!A:A,"{label}"))'])
            s.cell(row, 4).number_format = "0%"
    s.append([])
    s.append(["Phishing links wrongly marked SAFE (goal: 0)", None,
              '=COUNTIFS(Results!A:A,"Phishing*",Results!D:D,"SAFE")'])
    if args.intel or args.ml:
        s.append(["Phishing links upgraded to SCAM by the extra layers", None,
                  '=COUNTIFS(Results!A:A,"Phishing*",Results!D:D,"SCAM",Results!F:F,"<>SCAM")'])
    else:
        s.append(["Note: Layer 1 only detects impersonation of Bahrain domains. Global phishing "
                  "links (Netflix, Outlook...) are expected to be SUSPICIOUS; Layer 2 will classify them."])
    s["A1"].font = Font(name="Arial", bold=True, size=14)
    for c in s[4]:
        c.font = Font(name="Arial", bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3A5F")
    s.column_dimensions["A"].width = 44
    s.column_dimensions["B"].width = 14

    res = wb.create_sheet("Results")
    res.append(["Group", "URL (defanged)", "Host", "Final verdict", "Reasons", "Layer 1 verdict"])
    fills = {SAFE: "D1FADF", SUSPICIOUS: "FEF0C7", SCAM: "FEE4E2"}
    for label, url, host, verdict, reasons, l1 in rows:
        res.append([label, defang(url), host, verdict, reasons, l1])
        res.cell(res.max_row, 4).fill = PatternFill("solid", fgColor=fills[verdict])
    for c in res[1]:
        c.font = Font(name="Arial", bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3A5F")
    for col, w in zip("ABCDEF", [22, 70, 40, 14, 90, 15]):
        res.column_dimensions[col].width = w
    for row in res.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(vertical="top", wrap_text=(c.column == 5))
    res.freeze_panes = "A2"
    res.auto_filter.ref = res.dimensions

    wb.save(args.out)
    print(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Evaluate link_checker.py on real phishing links + known safe links.

    python evaluate.py                      # download the OpenPhish feed and test
    python evaluate.py --limit 100          # only test the first 100 phishing links
    python evaluate.py --feed-file feed.txt # use a feed you already downloaded

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

from link_checker import check_url, load_allowlist, SAFE, SUSPICIOUS, SCAM

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


def defang(url: str) -> str:
    """Make a link unclickable for safe sharing: https://a.com -> hxxps://a[.]com"""
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
    args = p.parse_args()

    allowlist = load_allowlist()
    phishing = get_feed(args.feed_file)
    if args.limit:
        phishing = phishing[: args.limit]

    rows = []
    for url in phishing:
        r = check_url(url, allowlist)
        rows.append(("Phishing (OpenPhish)", url, r.host, r.verdict, "; ".join(r.reasons)))
    for url in KNOWN_SAFE:
        r = check_url(url, allowlist)
        rows.append(("Safe (official)", url, r.host, r.verdict, "; ".join(r.reasons)))

    phish_counts = Counter(v for label, _, _, v, _ in rows if label.startswith("Phishing"))
    safe_counts = Counter(v for label, _, _, v, _ in rows if label.startswith("Safe"))
    n_phish, n_safe = sum(phish_counts.values()), sum(safe_counts.values())

    # ---- console summary ----
    print(f"\nPhishing links tested: {n_phish}")
    for v in (SCAM, SUSPICIOUS, SAFE):
        print(f"  {v:<10} {phish_counts[v]:>4}  ({phish_counts[v] / max(n_phish, 1):.0%})")
    print(f"\nOfficial links tested: {n_safe}")
    for v in (SAFE, SUSPICIOUS, SCAM):
        print(f"  {v:<10} {safe_counts[v]:>4}  ({safe_counts[v] / max(n_safe, 1):.0%})")

    missed = [r for r in rows if r[0].startswith("Phishing") and r[3] == SAFE]
    wrongly_flagged = [r for r in rows if r[0].startswith("Safe") and r[3] != SAFE]
    print(f"\nPhishing links wrongly marked SAFE: {len(missed)}   <- most important, should be 0")
    print(f"Official links NOT marked SAFE:     {len(wrongly_flagged)}")

    # ---- spreadsheet ----
    wb = Workbook()
    s = wb.active
    s.title = "Summary"
    s.append(["Evaluation of Layer 1 (domain checks)"])
    s.append([f"Run: {datetime.now():%Y-%m-%d %H:%M}   Source: OpenPhish public feed"])
    s.append([])
    s.append(["Group", "Verdict", "Count", "Share"])
    first = s.max_row + 1
    for label, counts, n in (("Phishing (OpenPhish)", phish_counts, n_phish),
                             ("Safe (official)", safe_counts, n_safe)):
        for v in (SAFE, SUSPICIOUS, SCAM):
            row = s.max_row + 1
            s.append([label, v,
                      f'=COUNTIFS(Results!A:A,"{label}",Results!D:D,"{v}")',
                      f'=IF(COUNTIF(Results!A:A,"{label}")=0,0,C{row}/COUNTIF(Results!A:A,"{label}"))'])
            s.cell(row, 4).number_format = "0%"
    s.append([])
    s.append(["Phishing links wrongly marked SAFE (goal: 0)", None,
              '=COUNTIFS(Results!A:A,"Phishing (OpenPhish)",Results!D:D,"SAFE")'])
    s.append(["Note: Layer 1 only detects impersonation of Bahrain domains. Global phishing "
              "links (Netflix, Outlook...) are expected to be SUSPICIOUS; Layer 2 will classify them."])
    s["A1"].font = Font(name="Arial", bold=True, size=14)
    for c in s[4]:
        c.font = Font(name="Arial", bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3A5F")
    s.column_dimensions["A"].width = 44
    s.column_dimensions["B"].width = 14

    res = wb.create_sheet("Results")
    res.append(["Group", "URL (defanged)", "Host", "Verdict", "Reasons"])
    fills = {SAFE: "D1FADF", SUSPICIOUS: "FEF0C7", SCAM: "FEE4E2"}
    for label, url, host, verdict, reasons in rows:
        res.append([label, defang(url), host, verdict, reasons])
        res.cell(res.max_row, 4).fill = PatternFill("solid", fgColor=fills[verdict])
    for c in res[1]:
        c.font = Font(name="Arial", bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3A5F")
    for col, w in zip("ABCDE", [22, 70, 40, 13, 90]):
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

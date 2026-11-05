#!/usr/bin/env python3
"""
Build popular_domains.txt from the Tranco list (research-grade ranking of the
world's most popular websites: https://tranco-list.eu).

    python build_popular_list.py                 # download latest list, keep top 10,000
    python build_popular_list.py --top 20000
    python build_popular_list.py --file top-1m.csv.zip   # use a file you downloaded yourself

The ML layer will not call a link a SCAM on its own if the link's real domain is
on this list (e.g. accounts.google.com, login.microsoftonline.com). Layer 1 and
Layer 2 can still flag it.
"""

import argparse
import csv
import io
import urllib.request
import zipfile
from pathlib import Path

from link_checker import split_domain

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
OUT = Path(__file__).with_name("popular_domains.txt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=10000)
    ap.add_argument("--file", help="local top-1m.csv or top-1m.csv.zip")
    args = ap.parse_args()

    if args.file:
        raw = Path(args.file).read_bytes()
    else:
        print(f"Downloading {TRANCO_URL} ...")
        with urllib.request.urlopen(TRANCO_URL, timeout=60) as r:
            raw = r.read()

    if raw[:2] == b"PK":                                    # zip file
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            raw = z.read(z.namelist()[0])
    rows = csv.reader(io.StringIO(raw.decode("utf-8", "ignore")))   # format: rank,domain

    seen, domains = set(), []
    for row in rows:
        if len(row) < 2:
            continue
        _, dom, suffix = split_domain(row[1].strip().lower())
        reg = f"{dom}.{suffix}" if suffix else dom
        if reg and reg not in seen:
            seen.add(reg)
            domains.append(reg)
        if len(domains) >= args.top:
            break

    OUT.write_text("# Top %d registered domains from the Tranco list (https://tranco-list.eu)\n" % len(domains)
                   + "\n".join(domains) + "\n", encoding="utf-8")
    print(f"Saved {len(domains):,} domains to {OUT.name}")


if __name__ == "__main__":
    main()

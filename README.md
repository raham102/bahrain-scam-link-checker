# Bahrain Scam Link Checker

A tool that checks whether a link is a real Bahrain government or payment website, or a scam pretending to be one, and returns one of three verdicts:

| Verdict | Meaning |
|---|---|
| ✅ **SAFE** | The link belongs to an official domain |
| ⚠️ **SUSPICIOUS** | Not an official domain; needs further checks |
| ⛔ **SCAM** | The link imitates an official site |

## Why I built this

People in Bahrain regularly receive SMS and WhatsApp messages that look like they come from official entities, such as unpaid traffic fines, parcels held at Bahrain Post, or VAT refunds. The links lead to convincing copies of government websites. I once entered my own payment details on one of these fake sites, so I built a tool to catch them before anyone else does the same.

## How it works

The checker is built in layers. Each layer adds evidence before a final verdict is given.

- [x] **Layer 1: Domain checks**. Reads only the text of the URL and never opens the link:
  - Allowlist of **47 verified official domains**, plus every `*.gov.bh` domain
  - Detects official names hidden inside another domain (`bahrain.bh.secure-pay[.]com`)
  - Detects fake government names (`gov-bh[.]com`, `bahrain-gov-payment[.]xyz`)
  - Detects misspellings, including swapped letters (`bahrian[.]bh`)
  - Detects Unicode look-alike characters, e.g. a Cyrillic "а" in `bahrаin.bh`
  - Flags raw IP addresses, URL shorteners, risky domain endings and excessive subdomains
  - Optional domain-age check (WHOIS): newly registered domains are a strong scam signal
- [x] **Layer 2: Threat intelligence**. Checks non-official links against:
  - **Google Safe Browsing**: Google's list of known phishing and malware sites
  - **VirusTotal**: verdicts from ~90 security vendors (2 or more "malicious" votes → Scam)
  - Threat intel can only make a verdict stricter. It never marks an unknown site as Safe.
- [ ] **Layer 3: Sandboxed page analysis** (screenshot, forms and content in an isolated browser)
- [ ] **Layer 4: AI explanation** (plain-language verdict in Arabic and English)

## Evaluation

Tested on **300 live phishing links** from the [OpenPhish public feed](https://github.com/openphish/public_feed) and **29 official Bahrain websites** (5 Nov 2026).

| Configuration | Test set | SAFE | SUSPICIOUS | SCAM |
|---|---|---|---|---|
| Layer 1 only | 300 phishing links | **0** | 300 | 0 |
| Layer 1 + 2 | 300 phishing links | **0** | 194 | **106 (35%)** |
| Both | 29 official sites | **29** | 0 | 0 |

- **No phishing link was ever marked safe**, and no official site was wrongly flagged.
- None of the phishing links in this feed impersonated Bahrain sites, so Layer 1 correctly marked them "Suspicious" rather than guessing.
- Adding threat intelligence (Layer 2) confirmed **106 links as scams**. Google Safe Browsing checked all 300 links; VirusTotal checked the first 20 because of free-tier rate limits.
- The remaining 194 stay "Suspicious": many phishing sites are only hours old and not yet in any database. The planned page-analysis and AI layers target exactly these.

Full results: `evaluation_layer1_2026-11-05.xlsx`, `evaluation_layer2_2026-11-05.xlsx` (links are defanged).

## Getting started

```bash
git clone https://github.com/rahma102/bahrain-scam-link-checker.git
cd bahrain-scam-link-checker
pip install -r requirements.txt
```

Check a link:
```bash
python link_checker.py "https://www.nbr.gov.bh"
```

Other options:
```bash
python link_checker.py --demo               # run the built-in test cases
python link_checker.py --file links.txt     # check a list (one URL per line)
python link_checker.py --whois "https://…"  # also check domain age
python evaluate.py                          # re-run the evaluation on the live OpenPhish feed
```

### Layer 2 setup (threat intelligence)

1. Get free API keys from [VirusTotal](https://www.virustotal.com) and [Google Safe Browsing](https://developers.google.com/safe-browsing).
2. Copy `.env.example` to a new file named `.env` and paste your keys into it. `.env` is git-ignored.
3. Run with `--intel`:
```bash
python link_checker.py --intel "https://suspicious-link.com"
python evaluate.py --intel --vt-limit 20
```
VirusTotal's free tier allows 4 lookups per minute, so the tool waits about 15 seconds between VirusTotal calls.

Example output:
```
⛔ SCAM       hxxps://bahrain.bh.secure-pay[.]com/fines
   host: bahrain.bh.secure-pay.com
   - Contains the official name 'bahrain.bh' but the real domain is 'secure-pay.com'.
```

## Project files

| File | Purpose |
|---|---|
| `link_checker.py` | The checker (Layer 1, plus Layer 2 with `--intel`) |
| `threat_intel.py` | Layer 2: Google Safe Browsing and VirusTotal lookups |
| `.env.example` | Template for your API keys |
| `bahrain_official_domains_allowlist.xlsx` | Verified official domains, matching rules and sources |
| `evaluate.py` | Runs the checker on live phishing links and official sites and saves the results |
| `evaluation_layer1_2026-11-05.xlsx` | Results of the first evaluation (links are defanged) |

## Safety note

All example and test links in this repository are **defanged** (`hxxps://`, `[.]`) so they can't be clicked. The checker never visits the links it analyses.

## Tech stack

Python · tldextract · python-whois · openpyxl · Google Safe Browsing API · VirusTotal API

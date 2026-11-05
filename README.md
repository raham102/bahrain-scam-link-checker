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
- [x] **Layer 3: Machine-learning model**. A Random Forest trained on 235,370 URLs (see [ML model](#layer-3-machine-learning-model) below):
  - Learns phishing patterns from the domain name (length, randomness, hyphens, digits, risky endings, words like `login` or `verify`)
  - Calls a link a Scam only above a high-confidence threshold (≥ 99% precision on validation data)
  - Never overrides an official domain, and can't call one of the world's 10,000 most popular sites a scam on its own (free-hosting platforms excepted)
- [ ] **Layer 4: AI explanation** (plain-language verdict in Arabic and English)
- [ ] **Website**: paste a link, get the verdict
- [ ] **Layer 5: Sandboxed page analysis** (screenshot, forms and content in an isolated browser)

## Evaluation

Tested on **300 live phishing links** from the [OpenPhish public feed](https://github.com/openphish/public_feed) and **29 official Bahrain websites** (5 Nov 2026).

| Configuration | Test set | SAFE | SUSPICIOUS | SCAM |
|---|---|---|---|---|
| Layer 1 only | 300 phishing links | **0** | 300 | 0 |
| Layer 1 + 2 | 300 phishing links | **0** | 194 | **106 (35%)** |
| Layer 1 + 2 + 3 | 300 phishing links | **0** | 77 | **223 (74%)** |
| All configurations | 29 official sites | **29** | 0 | 0 |

- **No phishing link was ever marked safe**, and no official site was wrongly flagged.
- None of the phishing links in this feed impersonated Bahrain sites, so Layer 1 correctly marked them "Suspicious" rather than guessing.
- Threat intelligence (Layer 2) confirmed 35% as scams. Google Safe Browsing checked all 300 links; VirusTotal checked the first 20 because of free-tier rate limits.
- The ML model (Layer 3) raised that to **74%**, catching new phishing sites that aren't in any database yet.
- Each run downloads the live feed, so the three phishing rows are from slightly different snapshots taken on the same day.

Full results: `evaluation_layer1_2026-11-05.xlsx`, `evaluation_layer2_2026-11-05.xlsx`, `evaluation_layer3_2026-11-05.xlsx` (links are defanged).

## Layer 3: machine-learning model

**Data.** [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI, CC BY 4.0): 235,370 URLs, 100,520 phishing and 134,850 legitimate. Split 70/15/15 into train, validation and test **by registered domain**, so no domain appears in more than one set (otherwise a model can memorise domains and look better than it is).

**Finding and fixing shortcut learning.** The first model used the whole URL and looked excellent on phishing links, but it flagged **48% of official Bahrain sites and 100% of everyday links** (Wikipedia articles, news stories, GitHub pages) as phishing. A diagnostic showed why: **0% of the dataset's legitimate URLs have a path**, against 28% of phishing URLs. The model had learned "has a path = phishing" instead of real phishing patterns. Two fixes:
1. A **domain-only model** (13 features from the hostname, none from the path).
2. A **popular-sites rule**: the model alone can't call one of the top 10,000 sites on the [Tranco list](https://tranco-list.eu) a scam, because it otherwise flagged `accounts.google.com` and `login.microsoftonline.com`. Free-hosting platforms (`github.io`, `blogspot.com`, `sites.google.com`…) get no such protection, since scammers use them.

| Model | Official sites flagged as Scam | Everyday links flagged as Scam | Live OpenPhish caught as Scam |
|---|---|---|---|
| Full URL | 48% | 100% | 89% |
| Domain only | 0% | 5% (2/40) | 67% |
| **Domain only + popular-sites rule** | **0%** | **0% (0/40)** | **66%** |

Internal test set (domain-only Random Forest, 32,928 URLs from unseen domains): accuracy 0.816, precision 0.890, recall 0.601, ROC AUC 0.830, compared with a logistic-regression baseline at ROC AUC 0.814. At the strict Scam threshold, precision is 0.993. Full details are in [`model_report.md`](model_report.md).

**Limitations**
- Recall on the internal test is moderate because many phishing pages sit on clean-looking or hacked legitimate domains, which no URL-only model can catch. Page analysis (Layer 5) targets these.
- The 40 everyday links were also used to diagnose the problem, so the 0/40 result is somewhat optimistic; a fresh set would be a stricter test.
- Phishing patterns change, so the model should be retrained on fresh data regularly.

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

### Layer 3 setup (ML model)

The trained model (`phishing_model.joblib`) and popular-sites list are included, so `--ml` works straight away:
```bash
python link_checker.py --ml "https://suspicious-link.com"
python link_checker.py --intel --ml "https://suspicious-link.com"   # all layers
python evaluate.py --intel --ml
```
To retrain it yourself, download `PhiUSIIL_Phishing_URL_Dataset.csv` from UCI into the project folder, then:
```bash
python build_popular_list.py            # refresh popular_domains.txt from Tranco
python train_model.py --features host   # or --features full to reproduce the shortcut problem
```

Example output:
```
⛔ SCAM       hxxps://bahrain.bh.secure-pay[.]com/fines
   host: bahrain.bh.secure-pay.com
   - Contains the official name 'bahrain.bh' but the real domain is 'secure-pay.com'.
```

## Project files

| File | Purpose |
|---|---|
| `link_checker.py` | The checker (Layer 1, plus `--intel` for Layer 2 and `--ml` for Layer 3) |
| `threat_intel.py` | Layer 2: Google Safe Browsing and VirusTotal lookups |
| `.env.example` | Template for your API keys |
| `url_features.py` | Layer 3: turns a URL into 29 numeric features and applies the model |
| `train_model.py` | Layer 3: trains and evaluates the model, writes `model_report.md` |
| `phishing_model.joblib` | The trained model |
| `build_popular_list.py`, `popular_domains.txt` | Top 10,000 sites from the Tranco list |
| `model_report.md` | Training results, feature importance and limitations |
| `bahrain_official_domains_allowlist.xlsx` | Verified official domains, matching rules and sources |
| `evaluate.py` | Runs the checker on live phishing links and official sites and saves the results |
| `evaluation_layer*_2026-11-05.xlsx` | Evaluation results for each stage (links are defanged) |

## Safety note

All example and test links in this repository are **defanged** (`hxxps://`, `[.]`) so they can't be clicked. The checker never visits the links it analyses.

## Tech stack

Python · scikit-learn · pandas · NumPy · tldextract · python-whois · openpyxl · Google Safe Browsing API · VirusTotal API

## Data credits

- PhiUSIIL Phishing URL Dataset: Prasad, A. & Chandra, S. (2024), UCI Machine Learning Repository, CC BY 4.0
- [OpenPhish](https://openphish.com) public feed
- [Tranco](https://tranco-list.eu) top-sites ranking

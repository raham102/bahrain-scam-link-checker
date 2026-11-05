#!/usr/bin/env python3
"""
Layer 3 - train a machine-learning model to recognise phishing URLs.

1. Download the PhiUSIIL Phishing URL Dataset (free, CC BY 4.0):
   https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
   Unzip it and put PhiUSIIL_Phishing_URL_Dataset.csv in this folder.

2. Train:
       python train_model.py
       python train_model.py --sample 50000     # faster, for a first try

Output:
   phishing_model.joblib   - the trained model (used by link_checker.py --ml)
   model_report.md         - accuracy, precision, recall, feature importance

How it avoids fooling itself:
   * URLs from the same domain are kept together in either train or test
     (otherwise the model just memorises domains and the scores look too good).
   * Scheme and "www." are stripped before features are extracted.
   * A second, independent test runs on live OpenPhish links and real
     Bahrain government links that the model has never seen.
"""

import argparse
import json
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from link_checker import get_host, split_domain
from url_features import FEATURE_NAMES, FEATURE_SETS, extract_features

HERE = Path(__file__).parent
DATASET = HERE / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_FILE = HERE / "phishing_model.joblib"
REPORT_FILE = HERE / "model_report.md"
FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
PHISH_URLS: list[str] = []
TARGET_PRECISION = 0.99     # threshold for calling something a SCAM on the model alone
MIN_SCAM_THRESHOLD = 0.85   # never call a scam on the model alone below 85% confidence


def load_dataset(path: Path, sample: int) -> pd.DataFrame:
    df = pd.read_csv(path, usecols=lambda c: c.strip().lower() in ("url", "label"))
    df.columns = [c.strip().lower() for c in df.columns]
    df = df.dropna(subset=["url", "label"]).drop_duplicates("url")
    # PhiUSIIL: label 1 = legitimate, 0 = phishing  ->  we want 1 = phishing
    df["is_phishing"] = (df["label"].astype(int) == 0).astype(int)
    if sample and sample < len(df):
        df = pd.concat([g.sample(min(len(g), sample // 2), random_state=42)
                        for _, g in df.groupby("is_phishing")])
    return df.reset_index(drop=True)


def registered_domain(url: str) -> str:
    host = get_host(url)
    _, dom, suffix = split_domain(host)
    return f"{dom}.{suffix}" if suffix else host


def metrics(y_true, prob, threshold=0.5) -> dict:
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y_true, pred), "precision": precision_score(y_true, pred, zero_division=0),
            "recall": recall_score(y_true, pred, zero_division=0), "f1": f1_score(y_true, pred, zero_division=0),
            "roc_auc": roc_auc_score(y_true, prob) if len(set(y_true)) > 1 else float("nan"),
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def threshold_for_precision(y_true, prob, target):
    precision, recall, thresholds = precision_recall_curve(y_true, prob)
    for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
        if p >= target:
            return float(t), float(r)
    return 1.0, 0.0


# Everyday legitimate links WITH paths - a fairer false-alarm test than bare homepages
EVERYDAY_LEGIT = [
    "https://en.wikipedia.org/wiki/Bahrain",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://ar.wikipedia.org/wiki/%D8%A7%D9%84%D8%A8%D8%AD%D8%B1%D9%8A%D9%86",
    "https://www.bbc.com/news/world-middle-east",
    "https://www.aljazeera.com/news/",
    "https://www.gdnonline.com/Details/1379890",
    "https://www.newsofbahrain.com/bahrain/120584.html",
    "https://github.com/openphish/public_feed",
    "https://github.com/scikit-learn/scikit-learn/issues",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.google.com/maps/place/Manama,+Bahrain",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://accounts.google.com/signin/v2/identifier",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://outlook.live.com/mail/0/inbox",
    "https://www.linkedin.com/in/example-profile/",
    "https://www.linkedin.com/jobs/search/?keywords=cybersecurity&location=Bahrain",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.amazon.ae/s?k=laptop",
    "https://www.noon.com/uae-en/electronics-and-mobiles/",
    "https://www.talabat.com/bahrain/restaurants",
    "https://www.instagram.com/explore/tags/bahrain/",
    "https://x.com/search?q=bahrain&src=typed_query",
    "https://www.reddit.com/r/Bahrain/",
    "https://www.apple.com/shop/buy-iphone/iphone-16",
    "https://support.apple.com/en-us/102654",
    "https://www.paypal.com/myaccount/summary",
    "https://www.netflix.com/browse/genre/34399",
    "https://store.steampowered.com/app/730/CounterStrike_2/",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.udemy.com/course/python-for-beginners/",
    "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
    "https://www.virustotal.com/gui/home/url",
    "https://developers.google.com/safe-browsing/v4/lookup-api",
    "https://www.nbb.com.bh/personal/cards/",
    "https://www.bisb.com/en/personal/accounts",
    "https://www.batelco.com/personal/mobile/postpaid/",
]


def external_test(model, feature_names):
    """Live OpenPhish links (phishing) + official Bahrain sites and everyday links (legitimate)."""
    from evaluate import KNOWN_SAFE
    from url_features import features_for

    def score(urls):
        return model.predict_proba(np.array([features_for(u, feature_names) for u in urls]))[:, 1]
    try:
        with urllib.request.urlopen(FEED_URL, timeout=30) as r:
            phish = [l.strip() for l in r.read().decode("utf-8", "ignore").splitlines() if l.strip()]
    except Exception as e:
        print(f"  (could not download OpenPhish feed: {e})")
        phish = []
    global PHISH_URLS
    PHISH_URLS = phish
    out = {}
    if phish:
        out["openphish"] = (len(phish), score(phish))
    out["official"] = (len(KNOWN_SAFE), score(KNOWN_SAFE))
    out["everyday"] = (len(EVERYDAY_LEGIT), score(EVERYDAY_LEGIT))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(DATASET))
    ap.add_argument("--sample", type=int, default=0, help="use only N rows (balanced) for a quick run")
    ap.add_argument("--features", choices=FEATURE_SETS, default="host",
                    help="host = domain-name features only (default); full = also path/query features")
    args = ap.parse_args()

    if not Path(args.data).exists():
        raise SystemExit(f"Dataset not found: {args.data}\n"
                         "Download it from https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset")

    t0 = time.time()
    df = load_dataset(Path(args.data), args.sample)
    print(f"Loaded {len(df):,} URLs  ({df.is_phishing.sum():,} phishing, {(1 - df.is_phishing).sum():,} legitimate)")

    print("Extracting features (1-3 minutes for the full dataset)...")
    X_all = np.array([extract_features(u) for u in df.url])
    feature_names = FEATURE_SETS[args.features]
    X = X_all[:, [FEATURE_NAMES.index(n) for n in feature_names]]
    y = df.is_phishing.values
    groups = df.url.map(registered_domain).values

    # Diagnostic: does the dataset contain the "homepage vs. path" shortcut?
    has_path = X_all[:, FEATURE_NAMES.index("path_length")] > 0
    print(f"URLs with a path:  legitimate {has_path[y == 0].mean():.0%}  |  phishing {has_path[y == 1].mean():.0%}")
    print(f"Feature set: {args.features} ({len(feature_names)} features)")

    # 70% train / 15% validation / 15% test, split by domain
    gss = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=42)
    train_idx, rest_idx = next(gss.split(X, y, groups))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=42)
    val_rel, test_rel = next(gss2.split(X[rest_idx], y[rest_idx], groups[rest_idx]))
    val_idx, test_idx = rest_idx[val_rel], rest_idx[test_rel]
    print(f"Train {len(train_idx):,} | validation {len(val_idx):,} | test {len(test_idx):,} (no domain appears in two sets)")

    # Baseline vs main model
    baseline = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000))
    baseline.fit(X[train_idx], y[train_idx])
    # Depth/leaf limits keep the saved model small (a few MB) so it can go on GitHub
    # and later run on a free web host, with almost no loss in accuracy.
    model = RandomForestClassifier(n_estimators=150, max_depth=18, min_samples_leaf=5, n_jobs=-1,
                                   class_weight="balanced", random_state=42)
    print("Training Random Forest...")
    model.fit(X[train_idx], y[train_idx])

    # Pick the "SCAM" threshold on the validation set, then report on the untouched test set
    val_prob = model.predict_proba(X[val_idx])[:, 1]
    scam_threshold, val_recall = threshold_for_precision(y[val_idx], val_prob, TARGET_PRECISION)
    scam_threshold = max(scam_threshold, MIN_SCAM_THRESHOLD)

    test_prob = model.predict_proba(X[test_idx])[:, 1]
    base_prob = baseline.predict_proba(X[test_idx])[:, 1]
    m_rf = metrics(y[test_idx], test_prob)
    m_base = metrics(y[test_idx], base_prob)
    m_strict = metrics(y[test_idx], test_prob, scam_threshold)

    importances = sorted(zip(feature_names, model.feature_importances_), key=lambda x: -x[1])

    print("Running external test (OpenPhish + official Bahrain sites)...")
    ext = external_test(model, feature_names)

    joblib.dump({"model": model, "features": feature_names, "feature_set": args.features, "scam_threshold": scam_threshold,
                 "trained": datetime.now().isoformat(timespec="minutes"),
                 "dataset": "PhiUSIIL Phishing URL Dataset (UCI, CC BY 4.0)"}, MODEL_FILE, compress=3)
    size_mb = MODEL_FILE.stat().st_size / 1e6

    # ---------- report ----------
    def row(name, m):
        return (f"| {name} | {m['accuracy']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} | "
                f"{m['f1']:.3f} | {m['roc_auc']:.3f} |")

    lines = [
        f"# Layer 3 - URL phishing model: training report ({args.features} features)", "",
        f"Trained {datetime.now():%Y-%m-%d %H:%M} on {len(df):,} URLs from the "
        "[PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset).",
        f"Split by registered domain: train {len(train_idx):,} / validation {len(val_idx):,} / test {len(test_idx):,}.", "",
        "## Test-set results (URLs from domains the model never saw)", "",
        "| Model | Accuracy | Precision | Recall | F1 | ROC AUC |", "|---|---|---|---|---|---|",
        row("Logistic regression (baseline)", m_base),
        row("Random Forest, threshold 0.50", m_rf),
        row(f"Random Forest, SCAM threshold {scam_threshold:.2f}", m_strict), "",
        f"Confusion matrix (Random Forest, 0.50): TP {m_rf['tp']:,} · FP {m_rf['fp']:,} · "
        f"TN {m_rf['tn']:,} · FN {m_rf['fn']:,}", "",
        f"The SCAM threshold ({scam_threshold:.2f}) was chosen on the validation set so that at least "
        f"{TARGET_PRECISION:.0%} of links the model calls a scam really are phishing (minimum "
        f"{MIN_SCAM_THRESHOLD:.2f}). Below it, the model only "
        "adds a warning; it never marks a link SAFE.", "",
        "## External test (data from outside the training set)", "",
    ]
    if "openphish" in ext:
        n, p = ext["openphish"]
        lines.append(f"- **Live OpenPhish links ({n}):** {np.mean(p >= 0.5):.0%} scored as phishing (≥ 0.50), "
                     f"{np.mean(p >= scam_threshold):.0%} above the SCAM threshold.")
    n, p = ext["official"]
    lines.append(f"- **Official Bahrain sites ({n}):** {np.mean(p >= 0.5):.0%} wrongly scored as phishing "
                 f"(≥ 0.50), {np.mean(p >= scam_threshold):.0%} above the SCAM threshold. "
                 "(In the full checker these are already SAFE from Layer 1, so the model never overrides them.)")
    n, p = ext["everyday"]
    lines.append(f"- **Everyday legitimate links ({n}, e.g. Wikipedia, news, GitHub):** "
                 f"{np.mean(p >= 0.5):.0%} wrongly scored as phishing (≥ 0.50), "
                 f"{np.mean(p >= scam_threshold):.0%} above the SCAM threshold.")
    from url_features import load_popular, popular_domain
    if load_popular():
        flagged = [u for u, s in zip(EVERYDAY_LEGIT, p) if s >= scam_threshold and not popular_domain(u)]
        lines.append(f"  - With the popular-sites rule (popular_domains.txt): **{len(flagged)} of {n}** "
                     "would be called a scam" + (f" ({', '.join(flagged)})" if flagged else "") + ".")
        if "openphish" in ext:
            n_o, p_o = ext["openphish"]
            still = sum(1 for u, s in zip(PHISH_URLS, p_o) if s >= scam_threshold and not popular_domain(u))
            lines.append(f"  - Live OpenPhish links still above the SCAM threshold with the rule: "
                         f"**{still / n_o:.0%}** ({still} of {n_o}).")
    else:
        lines.append("  - Run build_popular_list.py to apply the popular-sites rule.")
    lines += ["", "## Most important features", "", "| Feature | Importance |", "|---|---|"]
    lines += [f"| `{name}` | {imp:.3f} |" for name, imp in importances[:12]]
    lines += ["", "## Limitations", "",
              "- The model sees only the URL text. Phishing pages on clean-looking URLs (e.g. hacked legitimate sites) "
              "can score low.",
              "- Public datasets differ from real-world traffic, so external-test numbers are the more honest ones.",
              "- Phishing patterns change; the model should be retrained regularly on fresh data."]
    REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "\n".join(lines[6:12]))
    for l in lines:
        if l.startswith("- **") or l.startswith("  - "):
            print(l)
    print(f"\nSaved {MODEL_FILE.name} ({size_mb:.1f} MB) and {REPORT_FILE.name}  ({time.time() - t0:.0f} s)")


if __name__ == "__main__":
    main()

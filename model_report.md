# Layer 3 - URL phishing model: training report (host features)

Trained 2026-11-05 20:51 on 235,370 URLs from the [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset).
Split by registered domain: train 170,215 / validation 32,227 / test 32,928.

## Test-set results (URLs from domains the model never saw)

| Model | Accuracy | Precision | Recall | F1 | ROC AUC |
|---|---|---|---|---|---|
| Logistic regression (baseline) | 0.813 | 0.876 | 0.603 | 0.715 | 0.817 |
| Random Forest, threshold 0.50 | 0.817 | 0.893 | 0.601 | 0.718 | 0.831 |
| Random Forest, SCAM threshold 0.94 | 0.761 | 0.993 | 0.390 | 0.560 | 0.831 |

Confusion matrix (Random Forest, 0.50): TP 7,694 · FP 919 · TN 19,198 · FN 5,117

The SCAM threshold (0.94) was chosen on the validation set so that at least 99% of links the model calls a scam really are phishing (minimum 0.85). Below it, the model only adds a warning; it never marks a link SAFE.

## External test (data from outside the training set)

- **Live OpenPhish links (300):** 81% scored as phishing (≥ 0.50), 66% above the SCAM threshold.
- **Official Bahrain sites (29):** 10% wrongly scored as phishing (≥ 0.50), 0% above the SCAM threshold. (In the full checker these are already SAFE from Layer 1, so the model never overrides them.)
- **Everyday legitimate links (40, e.g. Wikipedia, news, GitHub):** 28% wrongly scored as phishing (≥ 0.50), 5% above the SCAM threshold.
  - With the popular-sites rule (popular_domains.txt): **0 of 40** would be called a scam.
  - Live OpenPhish links still above the SCAM threshold with the rule: **65%** (195 of 300).

## Most important features

| Feature | Importance |
|---|---|
| `num_subdomains` | 0.356 |
| `num_dots_host` | 0.136 |
| `host_length` | 0.133 |
| `num_digits_host` | 0.125 |
| `host_entropy` | 0.096 |
| `tld_length` | 0.049 |
| `num_hyphens_host` | 0.043 |
| `tld_risky` | 0.040 |
| `is_shortener` | 0.010 |
| `host_suspicious_words` | 0.009 |
| `has_ip` | 0.002 |
| `is_punycode` | 0.000 |

## Limitations

- The model sees only the URL text. Phishing pages on clean-looking URLs (e.g. hacked legitimate sites) can score low.
- Public datasets differ from real-world traffic, so external-test numbers are the more honest ones.
- Phishing patterns change; the model should be retrained regularly on fresh data.
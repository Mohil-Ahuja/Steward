# Behavioural detector report

690 sessions (483 train / 207 test), positive rate 13.0%.

This detector exists to catch what per-action authorization cannot: harm assembled from individually permitted calls. It is the answer to the residual `scope_abuse` failures in the authorization evaluation.

## Held-out performance

| Model | ROC-AUC | Average precision |
| --- | --- | --- |
| Supervised (logistic regression) | 0.999 | 0.991 |
| Unsupervised (Mahalanobis, benign-only fit) | 0.989 | 0.955 |

Average precision is the headline rather than ROC-AUC: at a 13% positive rate, ROC-AUC flatters a detector that an analyst would find unusable.

## Operating point

Threshold chosen as the lowest meeting a precision floor of 90%.

| Threshold | Precision | Recall | F1 | TP | FP | FN | TN |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0.809 | 0.964 | 1.000 | 0.982 | 27 | 1 | 0 | 179 |

Expected calibration error: 0.061.

## Detection rate by session profile

| Profile | Class | n | Flagged | Rate |
| --- | --- | --- | --- | --- |
| `bulk_report` | benign | 47 | 0 | 0% |
| `drip_spend` | abusive | 5 | 5 | 100% |
| `enumeration` | abusive | 5 | 5 | 100% |
| `exfiltration` | abusive | 5 | 5 | 100% |
| `focused_batch` | benign | 45 | 0 | 0% |
| `probing` | abusive | 7 | 7 | 100% |
| `stealth_enumeration` | abusive | 5 | 5 | 100% |
| `task` | benign | 53 | 1 | 2% |
| `with_denial` | benign | 35 | 0 | 0% |

`focused_batch` is the hard negative: a benign session that legitimately repeats one tool. Its flag rate is the false-alarm cost of catching enumeration.

## Learned coefficients

| Feature | Weight |
| --- | --- |
| `top_tool_share` | +2.947 |
| `distinct_arg_ratio` | +2.851 |
| `calls_per_minute` | +2.529 |
| `log_duration_s` | +2.321 |
| `distinct_reason_codes` | -1.816 |
| `injection_flag_share` | +1.588 |
| `n_calls` | +1.479 |
| `denied_share` | +1.442 |
| `tool_entropy` | -1.373 |
| `n_distinct_tools` | +1.125 |

Positive weights push toward *abusive*. Features are standardised, so magnitudes are comparable.

## Feature ablation

Average precision after removing each feature and retraining. A large negative delta means the whole result leans on that one signal.

| Removed feature | Average precision | Delta |
| --- | --- | --- |
| `distinct_arg_ratio` | 0.959 | -0.032 |
| `injection_flag_share` | 0.973 | -0.019 |
| `log_duration_s` | 0.978 | -0.013 |
| `distinct_reason_codes` | 0.985 | -0.006 |
| `denied_share` | 0.985 | -0.006 |
| `n_calls` | 0.988 | -0.003 |

## Limitations

- Trained on synthetic sessions from an explicit behavioural model (`detector/dataset.py`). These numbers measure whether the features separate the behaviours **as modelled**, not whether the detector would catch a real adversary.
- An adaptive attacker who paces calls to look like a task will evade a rate-and-entropy detector. This is a cost-imposition control, not a boundary.
- Retraining on real audit traffic (`sessions_from_audit`) is the intended production path; the synthetic generator exists so the result is reproducible from a clean checkout.
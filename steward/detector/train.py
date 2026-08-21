"""Train and evaluate the behavioural detector, and report honestly."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from .dataset import LabelledSession, generate_sessions
from .features import FEATURE_NAMES, explain, extract_features
from .model import (
    LogisticRegression,
    MahalanobisDetector,
    StandardScaler,
    average_precision,
    calibration_bins,
    confusion_at,
    expected_calibration_error,
    roc_auc,
    stratified_split,
    threshold_for_precision,
)


@dataclass
class TrainedDetector:
    scaler: StandardScaler
    classifier: LogisticRegression
    anomaly: MahalanobisDetector
    threshold: float = 0.5
    metrics: dict[str, Any] = field(default_factory=dict)

    def score_session(self, events: Sequence[Any]) -> dict[str, Any]:
        """Score one session and explain the result."""
        raw = extract_features(events)
        scaled = self.scaler.transform(raw.reshape(1, -1))
        probability = float(self.classifier.predict_proba(scaled)[0])
        distance = float(self.anomaly.score(scaled)[0])

        assert self.classifier.weights is not None
        return {
            "probability": probability,
            "flagged": probability >= self.threshold,
            "anomaly_distance": distance,
            "top_factors": explain(scaled[0], self.classifier.weights),
        }

    def to_dict(self) -> dict[str, Any]:
        assert self.classifier.weights is not None
        assert self.scaler.mean is not None and self.scaler.scale is not None
        return {
            "feature_names": FEATURE_NAMES,
            "scaler_mean": self.scaler.mean.tolist(),
            "scaler_scale": self.scaler.scale.tolist(),
            "weights": self.classifier.weights.tolist(),
            "bias": float(self.classifier.bias),
            "threshold": self.threshold,
            "metrics": self.metrics,
        }


def train(
    sessions: Sequence[LabelledSession] | None = None,
    *,
    seed: int = 0,
    test_fraction: float = 0.3,
    target_precision: float = 0.9,
) -> TrainedDetector:
    """Fit both detectors on a training split and score the held-out split."""
    sessions = list(sessions or generate_sessions(seed=seed))

    features = np.vstack([extract_features(item.events) for item in sessions])
    labels = np.array([item.label for item in sessions])

    train_index, test_index = stratified_split(
        labels, test_fraction=test_fraction, seed=seed
    )

    scaler = StandardScaler().fit(features[train_index])
    train_x = scaler.transform(features[train_index])
    test_x = scaler.transform(features[test_index])
    train_y, test_y = labels[train_index], labels[test_index]

    classifier = LogisticRegression().fit(train_x, train_y)

    # The unsupervised detector sees only benign training sessions, so it
    # models "normal" rather than "known bad" and can flag novel behaviour.
    anomaly = MahalanobisDetector().fit(train_x[train_y == 0])

    test_probabilities = classifier.predict_proba(test_x)
    test_distances = anomaly.score(test_x)

    threshold, precision_at, recall_at = threshold_for_precision(
        test_y, test_probabilities, target_precision
    )
    if not np.isfinite(threshold):
        threshold = 0.5

    metrics: dict[str, Any] = {
        "n_sessions": len(sessions),
        "n_train": int(len(train_index)),
        "n_test": int(len(test_index)),
        "positive_rate": float(labels.mean()),
        "supervised": {
            "roc_auc": roc_auc(test_y, test_probabilities),
            "average_precision": average_precision(test_y, test_probabilities),
            "expected_calibration_error": expected_calibration_error(
                test_y, test_probabilities
            ),
            "operating_point": confusion_at(test_y, test_probabilities, threshold),
            "target_precision": target_precision,
            "achieved_precision": precision_at,
            "recall_at_target": recall_at,
        },
        "unsupervised": {
            "roc_auc": roc_auc(test_y, test_distances),
            "average_precision": average_precision(test_y, test_distances),
        },
        "coefficients": sorted(
            (
                {"feature": name, "weight": float(weight)}
                for name, weight in zip(
                    FEATURE_NAMES,
                    classifier.weights if classifier.weights is not None else [],
                    strict=False,
                )
            ),
            key=lambda item: -abs(item["weight"]),
        ),
        "calibration": calibration_bins(test_y, test_probabilities),
    }

    # Per-profile recall answers the question the aggregate hides: which
    # attack shapes does this actually catch?
    by_profile: dict[str, dict[str, Any]] = {}
    for position, index in enumerate(test_index):
        item = sessions[index]
        entry = by_profile.setdefault(
            item.profile, {"label": item.label, "n": 0, "flagged": 0}
        )
        entry["n"] += 1
        entry["flagged"] += int(test_probabilities[position] >= threshold)
    for entry in by_profile.values():
        entry["flag_rate"] = entry["flagged"] / entry["n"] if entry["n"] else 0.0
    metrics["by_profile"] = dict(sorted(by_profile.items()))

    metrics["ablation"] = _feature_ablation(
        features, labels, train_index, test_index, baseline=supervised_ap(metrics)
    )

    return TrainedDetector(
        scaler=scaler,
        classifier=classifier,
        anomaly=anomaly,
        threshold=float(threshold),
        metrics=metrics,
    )


def supervised_ap(metrics: dict[str, Any]) -> float:
    return float(metrics["supervised"]["average_precision"])


def _feature_ablation(
    features: np.ndarray,
    labels: np.ndarray,
    train_index: np.ndarray,
    test_index: np.ndarray,
    *,
    baseline: float,
) -> list[dict[str, Any]]:
    """Leave-one-feature-out average precision.

    A near-ceiling score is only trustworthy if you can say what is producing
    it. Retraining without each feature in turn shows whether performance rests
    on one lucky signal -- which, on synthetic data, is the usual explanation
    for a suspiciously good result -- or is spread across several.
    """
    results: list[dict[str, Any]] = []

    for index, name in enumerate(FEATURE_NAMES):
        keep = [position for position in range(features.shape[1]) if position != index]
        subset = features[:, keep]

        scaler = StandardScaler().fit(subset[train_index])
        model = LogisticRegression().fit(
            scaler.transform(subset[train_index]), labels[train_index]
        )
        scores = model.predict_proba(scaler.transform(subset[test_index]))
        ablated = average_precision(labels[test_index], scores)

        results.append(
            {
                "removed": name,
                "average_precision": float(ablated),
                "delta": float(ablated - baseline),
            }
        )

    return sorted(results, key=lambda item: item["delta"])


def to_markdown(detector: TrainedDetector) -> str:
    metrics = detector.metrics
    supervised = metrics["supervised"]
    operating = supervised["operating_point"]

    lines: list[str] = []
    add = lines.append

    add("# Behavioural detector report")
    add("")
    add(
        f"{metrics['n_sessions']} sessions "
        f"({metrics['n_train']} train / {metrics['n_test']} test), "
        f"positive rate {metrics['positive_rate'] * 100:.1f}%."
    )
    add("")
    add(
        "This detector exists to catch what per-action authorization cannot: "
        "harm assembled from individually permitted calls. It is the answer to "
        "the residual `scope_abuse` failures in the authorization evaluation."
    )
    add("")

    add("## Held-out performance")
    add("")
    add("| Model | ROC-AUC | Average precision |")
    add("| --- | --- | --- |")
    add(
        f"| Supervised (logistic regression) | {supervised['roc_auc']:.3f} "
        f"| {supervised['average_precision']:.3f} |"
    )
    add(
        f"| Unsupervised (Mahalanobis, benign-only fit) "
        f"| {metrics['unsupervised']['roc_auc']:.3f} "
        f"| {metrics['unsupervised']['average_precision']:.3f} |"
    )
    add("")
    add(
        "Average precision is the headline rather than ROC-AUC: at a "
        f"{metrics['positive_rate'] * 100:.0f}% positive rate, ROC-AUC flatters "
        "a detector that an analyst would find unusable."
    )
    add("")

    add("## Operating point")
    add("")
    add(
        f"Threshold chosen as the lowest meeting a precision floor of "
        f"{supervised['target_precision']:.0%}."
    )
    add("")
    add("| Threshold | Precision | Recall | F1 | TP | FP | FN | TN |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    add(
        f"| {operating['threshold']:.3f} | {operating['precision']:.3f} "
        f"| {operating['recall']:.3f} | {operating['f1']:.3f} "
        f"| {operating['true_positive']} | {operating['false_positive']} "
        f"| {operating['false_negative']} | {operating['true_negative']} |"
    )
    add("")
    add(
        f"Expected calibration error: "
        f"{supervised['expected_calibration_error']:.3f}."
    )
    add("")

    add("## Detection rate by session profile")
    add("")
    add("| Profile | Class | n | Flagged | Rate |")
    add("| --- | --- | --- | --- | --- |")
    for name, entry in metrics["by_profile"].items():
        label = "abusive" if entry["label"] == 1 else "benign"
        add(
            f"| `{name}` | {label} | {entry['n']} | {entry['flagged']} "
            f"| {entry['flag_rate'] * 100:.0f}% |"
        )
    add("")
    add(
        "`focused_batch` is the hard negative: a benign session that legitimately "
        "repeats one tool. Its flag rate is the false-alarm cost of catching "
        "enumeration."
    )
    add("")

    add("## Learned coefficients")
    add("")
    add("| Feature | Weight |")
    add("| --- | --- |")
    for entry in metrics["coefficients"][:10]:
        add(f"| `{entry['feature']}` | {entry['weight']:+.3f} |")
    add("")
    add(
        "Positive weights push toward *abusive*. Features are standardised, so "
        "magnitudes are comparable."
    )
    add("")

    add("## Feature ablation")
    add("")
    add(
        "Average precision after removing each feature and retraining. A large "
        "negative delta means the whole result leans on that one signal."
    )
    add("")
    add("| Removed feature | Average precision | Delta |")
    add("| --- | --- | --- |")
    for entry in metrics["ablation"][:6]:
        add(
            f"| `{entry['removed']}` | {entry['average_precision']:.3f} "
            f"| {entry['delta']:+.3f} |"
        )
    add("")

    add("## Limitations")
    add("")
    add(
        "- Trained on synthetic sessions from an explicit behavioural model "
        "(`detector/dataset.py`). These numbers measure whether the features "
        "separate the behaviours **as modelled**, not whether the detector "
        "would catch a real adversary."
    )
    add(
        "- An adaptive attacker who paces calls to look like a task will evade "
        "a rate-and-entropy detector. This is a cost-imposition control, not a "
        "boundary."
    )
    add(
        "- Retraining on real audit traffic (`sessions_from_audit`) is the "
        "intended production path; the synthetic generator exists so the result "
        "is reproducible from a clean checkout."
    )

    return "\n".join(lines)


def write_report(detector: TrainedDetector, directory: str | Path) -> dict[str, Path]:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)

    markdown_path = target / "detector.md"
    json_path = target / "detector.json"

    markdown_path.write_text(to_markdown(detector), encoding="utf-8")
    json_path.write_text(json.dumps(detector.to_dict(), indent=2), encoding="utf-8")
    return {"markdown": markdown_path, "json": json_path}

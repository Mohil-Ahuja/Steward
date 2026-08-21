"""Learned models for behavioural anomaly detection, implemented in NumPy.

The evaluation shows where per-action authorization runs out: an agent can do
harm entirely through calls it is permitted to make. Reading one contact is
support work; reading every contact one at a time is a bulk export, and no
policy that examines a single call can tell them apart. Catching that needs a
model of *behaviour over a session* rather than a rule about an action.

Two complementary detectors:

:class:`LogisticRegression`
    Supervised, and the primary detector when labels exist. Trained with L2
    regularisation by full-batch gradient descent. Chosen over anything fancier
    because the decisive property here is not accuracy, it is that each
    coefficient is readable: an analyst asked to act on an alert needs to know
    the session fired because its tool-entropy was low and its call rate high,
    not because a forest voted.

:class:`MahalanobisDetector`
    Unsupervised, for the case that matters operationally -- novel abuse
    nobody has labelled yet. It fits a robust Gaussian to *benign* sessions
    only and scores by distance from that centre, so it flags "unlike normal"
    rather than "like known-bad" and does not need attack examples.

Written against NumPy rather than scikit-learn deliberately. The published
numbers must be reproducible from a clean checkout, and this project's own
environment demonstrates why that matters: the installed scikit-learn fails to
import against NumPy 2.x because of a transitive ABI break. A detector nobody
can run is not a result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

# ---------------------------------------------------------------------------
# Scaling
# ---------------------------------------------------------------------------


@dataclass
class StandardScaler:
    """Zero mean, unit variance, fitted on the training split only."""

    mean: np.ndarray | None = None
    scale: np.ndarray | None = None

    def fit(self, features: np.ndarray) -> StandardScaler:
        self.mean = features.mean(axis=0)
        deviation = features.std(axis=0)
        # A constant feature has zero variance; dividing by it yields nan and
        # silently poisons every downstream coefficient.
        self.scale = np.where(deviation < 1e-12, 1.0, deviation)
        return self

    def transform(self, features: np.ndarray) -> np.ndarray:
        assert self.mean is not None and self.scale is not None
        return (features - self.mean) / self.scale

    def fit_transform(self, features: np.ndarray) -> np.ndarray:
        return self.fit(features).transform(features)


# ---------------------------------------------------------------------------
# Supervised
# ---------------------------------------------------------------------------


def _sigmoid(z: np.ndarray) -> np.ndarray:
    # Branch on sign to avoid overflow in exp for large-magnitude logits.
    out = np.empty_like(z, dtype=float)
    positive = z >= 0
    out[positive] = 1.0 / (1.0 + np.exp(-z[positive]))
    exp_z = np.exp(z[~positive])
    out[~positive] = exp_z / (1.0 + exp_z)
    return out


@dataclass
class LogisticRegression:
    learning_rate: float = 0.1
    epochs: int = 3000
    l2: float = 1e-3
    class_weight: str | None = "balanced"
    tolerance: float = 1e-8

    weights: np.ndarray | None = None
    bias: float = 0.0
    loss_history: list[float] = field(default_factory=list)

    def fit(self, features: np.ndarray, labels: np.ndarray) -> LogisticRegression:
        samples, dimensions = features.shape
        self.weights = np.zeros(dimensions)
        self.bias = 0.0

        if self.class_weight == "balanced":
            # Abuse is rare by construction. Without reweighting, the model
            # minimises loss by predicting "benign" everywhere and scores well
            # on accuracy while being operationally useless.
            positives = max(labels.sum(), 1.0)
            negatives = max(samples - labels.sum(), 1.0)
            sample_weight = np.where(labels == 1, samples / (2 * positives), samples / (2 * negatives))
        else:
            sample_weight = np.ones(samples)

        previous = np.inf
        for _ in range(self.epochs):
            logits = features @ self.weights + self.bias
            predictions = _sigmoid(logits)
            error = (predictions - labels) * sample_weight

            grad_w = features.T @ error / samples + self.l2 * self.weights
            grad_b = error.sum() / samples

            self.weights -= self.learning_rate * grad_w
            self.bias -= self.learning_rate * grad_b

            eps = 1e-12
            loss = float(
                -np.mean(
                    sample_weight
                    * (
                        labels * np.log(predictions + eps)
                        + (1 - labels) * np.log(1 - predictions + eps)
                    )
                )
                + 0.5 * self.l2 * float(self.weights @ self.weights)
            )
            self.loss_history.append(loss)
            if abs(previous - loss) < self.tolerance:
                break
            previous = loss

        return self

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        assert self.weights is not None
        return _sigmoid(features @ self.weights + self.bias)

    def predict(self, features: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(features) >= threshold).astype(int)


# ---------------------------------------------------------------------------
# Unsupervised
# ---------------------------------------------------------------------------


@dataclass
class MahalanobisDetector:
    """Distance from the centre of benign behaviour.

    Uses a shrunk covariance estimate. With few sessions relative to features
    the sample covariance is near-singular and its inverse explodes, turning
    the detector into a noise amplifier; shrinking toward a diagonal target
    keeps it stable.
    """

    shrinkage: float = 0.1
    mean: np.ndarray | None = None
    precision: np.ndarray | None = None

    def fit(self, benign_features: np.ndarray) -> MahalanobisDetector:
        self.mean = benign_features.mean(axis=0)
        covariance = np.cov(benign_features, rowvar=False)
        covariance = np.atleast_2d(covariance)

        target = np.eye(covariance.shape[0]) * np.trace(covariance) / covariance.shape[0]
        shrunk = (1 - self.shrinkage) * covariance + self.shrinkage * target
        shrunk += np.eye(shrunk.shape[0]) * 1e-6

        self.precision = np.linalg.pinv(shrunk)
        return self

    def score(self, features: np.ndarray) -> np.ndarray:
        """Squared Mahalanobis distance; higher is more anomalous."""
        assert self.mean is not None and self.precision is not None
        centred = features - self.mean
        return np.einsum("ij,jk,ik->i", centred, self.precision, centred)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def roc_auc(labels: np.ndarray, scores: np.ndarray) -> float:
    """AUC via the rank formulation, with ties averaged."""
    positives = labels == 1
    n_pos = int(positives.sum())
    n_neg = int((~positives).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")

    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=float)
    ranks[order] = np.arange(1, len(scores) + 1)

    # Average ranks within tied groups, otherwise ordering artefacts leak into
    # the score.
    sorted_scores = scores[order]
    start = 0
    for index in range(1, len(sorted_scores) + 1):
        if index == len(sorted_scores) or sorted_scores[index] != sorted_scores[start]:
            if index - start > 1:
                ranks[order[start:index]] = ranks[order[start:index]].mean()
            start = index

    return float((ranks[positives].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def precision_recall_curve(
    labels: np.ndarray, scores: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    order = np.argsort(-scores, kind="mergesort")
    sorted_labels = labels[order]
    sorted_scores = scores[order]

    true_positives = np.cumsum(sorted_labels)
    predicted_positives = np.arange(1, len(sorted_labels) + 1)
    total_positives = max(int(labels.sum()), 1)

    precision = true_positives / predicted_positives
    recall = true_positives / total_positives
    return precision, recall, sorted_scores


def average_precision(labels: np.ndarray, scores: np.ndarray) -> float:
    """Area under the PR curve, the honest headline for imbalanced data."""
    precision, recall, _ = precision_recall_curve(labels, scores)
    if len(recall) == 0:
        return float("nan")
    recall_deltas = np.diff(np.concatenate([[0.0], recall]))
    return float(np.sum(precision * recall_deltas))


def threshold_for_precision(
    labels: np.ndarray, scores: np.ndarray, target_precision: float = 0.9
) -> tuple[float, float, float]:
    """Lowest threshold meeting a precision floor, with the recall it buys.

    Operationally this is the number that matters. An analyst can absorb a
    fixed false-alarm rate; asking them to triage a detector tuned for maximum
    F1 usually means asking them to ignore it by week two.
    """
    precision, recall, thresholds = precision_recall_curve(labels, scores)
    viable = np.where(precision >= target_precision)[0]
    if len(viable) == 0:
        return float("inf"), float("nan"), 0.0
    best = viable[np.argmax(recall[viable])]
    return float(thresholds[best]), float(precision[best]), float(recall[best])


def calibration_bins(
    labels: np.ndarray, probabilities: np.ndarray, bins: int = 10
) -> list[dict[str, float]]:
    """Reliability curve: predicted probability against observed frequency.

    A detector whose 0.9 means 0.55 in practice cannot be used to prioritise
    a queue, however good its AUC.
    """
    edges = np.linspace(0.0, 1.0, bins + 1)
    report: list[dict[str, float]] = []
    for index in range(bins):
        low, high = edges[index], edges[index + 1]
        mask = (probabilities >= low) & (
            probabilities < high if index < bins - 1 else probabilities <= high
        )
        count = int(mask.sum())
        if count == 0:
            continue
        report.append(
            {
                "bin_low": float(low),
                "bin_high": float(high),
                "count": count,
                "mean_predicted": float(probabilities[mask].mean()),
                "observed_rate": float(labels[mask].mean()),
            }
        )
    return report


def expected_calibration_error(
    labels: np.ndarray, probabilities: np.ndarray, bins: int = 10
) -> float:
    report = calibration_bins(labels, probabilities, bins)
    total = len(labels)
    if total == 0:
        return float("nan")
    return float(
        sum(
            entry["count"] / total * abs(entry["mean_predicted"] - entry["observed_rate"])
            for entry in report
        )
    )


def stratified_split(
    labels: np.ndarray, *, test_fraction: float = 0.3, seed: int = 0
) -> tuple[np.ndarray, np.ndarray]:
    """Class-balanced train/test indices.

    Stratifying matters at this sample size: a random split can easily land
    almost every positive on one side and produce a meaningless test score.
    """
    rng = np.random.default_rng(seed)
    train: list[int] = []
    test: list[int] = []

    for value in np.unique(labels):
        indices = np.where(labels == value)[0]
        rng.shuffle(indices)
        cut = max(1, int(round(len(indices) * test_fraction)))
        test.extend(indices[:cut].tolist())
        train.extend(indices[cut:].tolist())

    return np.array(sorted(train)), np.array(sorted(test))


def confusion_at(
    labels: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, Any]:
    predicted = (scores >= threshold).astype(int)
    true_positive = int(((predicted == 1) & (labels == 1)).sum())
    false_positive = int(((predicted == 1) & (labels == 0)).sum())
    false_negative = int(((predicted == 0) & (labels == 1)).sum())
    true_negative = int(((predicted == 0) & (labels == 0)).sum())

    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else float("nan")
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if np.isfinite(precision) and np.isfinite(recall) and (precision + recall) > 0
        else float("nan")
    )

    return {
        "threshold": float(threshold),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }

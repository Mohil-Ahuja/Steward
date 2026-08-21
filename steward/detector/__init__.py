"""Behavioural anomaly detection over the audit stream."""

from .dataset import ABUSIVE, BENIGN, LabelledSession, generate_sessions
from .features import FEATURE_NAMES, SessionEvent, explain, extract_features, feature_matrix
from .model import (
    LogisticRegression,
    MahalanobisDetector,
    StandardScaler,
    average_precision,
    calibration_bins,
    confusion_at,
    expected_calibration_error,
    precision_recall_curve,
    roc_auc,
    stratified_split,
    threshold_for_precision,
)
from .train import TrainedDetector, to_markdown, train, write_report

__all__ = [
    "ABUSIVE",
    "BENIGN",
    "FEATURE_NAMES",
    "LabelledSession",
    "LogisticRegression",
    "MahalanobisDetector",
    "SessionEvent",
    "StandardScaler",
    "TrainedDetector",
    "average_precision",
    "calibration_bins",
    "confusion_at",
    "expected_calibration_error",
    "explain",
    "extract_features",
    "feature_matrix",
    "generate_sessions",
    "precision_recall_curve",
    "roc_auc",
    "stratified_split",
    "threshold_for_precision",
    "to_markdown",
    "train",
    "write_report",
]

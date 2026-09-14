"""Evaluate trace-level predictions on an independent labelled CSV."""

from pathlib import Path

from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

from .predict import load_model, predict_trace
from .preprocess import load_traces
from .train import DEFAULT_MODEL_PATH


def evaluate_model(data_path: str | Path, model_path: str | Path = DEFAULT_MODEL_PATH, *, threshold: float | None = None) -> dict:
    rows = load_traces(data_path, require_labels=True)
    actual = [int(row["label"] == "anomalous") for row in rows]
    if len(set(actual)) != 2:
        raise ValueError("Evaluation data must contain both normal and anomalous traces")
    artifact = load_model(model_path)
    predicted = [int(predict_trace(row["calls"], artifact, threshold=threshold)["status"] == "ANOMALOUS") for row in rows]
    precision, recall, f1, _ = precision_recall_fscore_support(actual, predicted, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "false_positive_rate": float(fp / (fp + tn)),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "traces": len(rows),
    }

"""Load a fitted artifact and score new, cleaned traces."""

from pathlib import Path

import joblib
import numpy as np

from .preprocess import parse_trace
from .supervised import SUPERVISED_ARTIFACT_VERSION
from .train import ARTIFACT_VERSION, DEFAULT_MODEL_PATH, trace_score


def load_model(model_path: str | Path = DEFAULT_MODEL_PATH) -> dict:
    path = Path(model_path)
    if not path.is_file():
        raise ValueError(f"Model file does not exist: {path}. Run train first.")
    # joblib uses pickle: load only model files created by this project/trusted users.
    artifact = joblib.load(path)
    if not isinstance(artifact, dict) or artifact.get("version") not in {ARTIFACT_VERSION, SUPERVISED_ARTIFACT_VERSION}:
        raise ValueError("Model artifact is incompatible with this version; run train again")
    required = ({"model", "encoder", "threshold", "novelty_weights"}
                if artifact["version"] == ARTIFACT_VERSION
                else {"model", "vectorizer", "threshold", "model_type"})
    if not required <= artifact.keys() or (artifact["version"] == SUPERVISED_ARTIFACT_VERSION and artifact["model_type"] != "tfidf_logistic_regression"):
        raise ValueError("Model file is not a valid anomaly detector artifact")
    return artifact


def predict_trace(trace: str | list[str], artifact: dict | None = None, *, threshold: float | None = None) -> dict:
    """Return one result per trace; load once and pass artifact for repeated calls."""
    calls = parse_trace(trace)
    artifact = artifact if artifact is not None else load_model()
    if artifact.get("version") not in {ARTIFACT_VERSION, SUPERVISED_ARTIFACT_VERSION}:
        raise ValueError("Model artifact is incompatible with this version; run train again")
    cutoff = float(artifact["threshold"] if threshold is None else threshold)
    if not np.isfinite(cutoff) or not 0 <= cutoff <= 1:
        raise ValueError("Threshold must be a finite number between 0 and 1")
    if artifact["version"] == ARTIFACT_VERSION:
        score = trace_score(artifact["model"], artifact["encoder"], calls, artifact["novelty_weights"])
    else:
        features = artifact["vectorizer"].transform([" ".join(calls)])
        score = float(artifact["model"].predict_proba(features)[0, 1])
    return {
        "status": "ANOMALOUS" if score >= cutoff else "NORMAL",
        "anomaly_score": score,
        "threshold": cutoff,
    }

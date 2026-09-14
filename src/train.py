"""Train only on normal behaviour and calibrate a trace-level cutoff."""

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from .features import FeatureEncoder, make_windows
from .preprocess import load_traces


DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "anomaly_model.pkl"
RANDOM_SEED = 42
ARTIFACT_VERSION = 2
NOVELTY_WEIGHTS = {"unknown_call": 0.20, "unseen_pair": 0.10}


def trace_score(model: IsolationForest, encoder: FeatureEncoder, calls: list[str],
                novelty_weights: dict[str, float] = NOVELTY_WEIGHTS) -> float:
    """Combine forest isolation with explicit novelty; take the worst window."""
    windows = make_windows(calls, encoder.window_size)
    features = np.vstack([encoder.transform_window(window) for window in windows])
    forest_scores = -model.score_samples(features)
    scores = []
    for window, forest_score in zip(windows, forest_scores):
        unknown_rate, unseen_pair_rate = encoder.novelty_rates(window)
        score = forest_score + novelty_weights["unknown_call"] * unknown_rate
        score += novelty_weights["unseen_pair"] * unseen_pair_rate
        scores.append(min(1.0, score))
    return float(max(scores))


def train_model(data_path: str | Path, model_path: str | Path = DEFAULT_MODEL_PATH, *, window_size: int = 10) -> dict:
    rows = load_traces(data_path)
    normal = [row["calls"] for row in rows if row["label"] in (None, "normal")]
    if len(normal) < 10:
        raise ValueError("Training requires at least 10 normal traces for fitting and calibration")

    # Split by whole trace before windowing to avoid sharing neighbouring windows.
    fit_traces, calibration_traces = train_test_split(normal, test_size=0.2, random_state=RANDOM_SEED)
    encoder = FeatureEncoder(window_size=window_size).fit(fit_traces)
    features = np.vstack([encoder.transform_trace(calls) for calls in fit_traces])
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=RANDOM_SEED)
    model.fit(features)

    calibration_scores = [trace_score(model, encoder, calls) for calls in calibration_traces]
    threshold = float(np.quantile(calibration_scores, 0.95))
    artifact = {
        "version": ARTIFACT_VERSION,
        "model": model,
        "encoder": encoder,
        "threshold": threshold,
        "novelty_weights": NOVELTY_WEIGHTS.copy(),
        "random_seed": RANDOM_SEED,
        "score_method": "max(min(1, -score_samples(window) + 0.20*unknown_call_rate + 0.10*unseen_pair_rate))",
    }
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path)
    return {
        "model_path": str(model_path),
        "training_traces": len(fit_traces),
        "calibration_traces": len(calibration_traces),
        "ignored_anomalous_traces": len(rows) - len(normal),
        "training_windows": len(features),
        "threshold": threshold,
    }

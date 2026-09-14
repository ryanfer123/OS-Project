"""Optional known-attack classifier for datasets with labelled attack traces.

This is separate from the normal-only Isolation Forest baseline. Its held-out
test partition is never used to fit features, fit the classifier, or set the
decision threshold.
"""

import csv
import hashlib
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import train_test_split

from .preprocess import load_traces
from .train import RANDOM_SEED


SUPERVISED_ARTIFACT_VERSION = 3
HOLDOUT_SEED = 2026
DEFAULT_SUPERVISED_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "supervised_model.pkl"


def train_supervised_model(
    normal_data_path: str | Path,
    labelled_data_path: str | Path,
    model_path: str | Path = DEFAULT_SUPERVISED_MODEL_PATH,
    *,
    holdout_path: str | Path,
) -> dict:
    """Fit on normal + known attacks; save a disjoint evaluation partition."""
    normal_rows = load_traces(normal_data_path)
    if any(row["label"] == "anomalous" for row in normal_rows):
        raise ValueError("Normal training data must not contain anomalous rows")
    labelled_rows = load_traces(labelled_data_path, require_labels=True)
    input_paths = {Path(normal_data_path).resolve(), Path(labelled_data_path).resolve()}
    if Path(model_path).resolve() in input_paths or Path(holdout_path).resolve() in input_paths:
        raise ValueError("Model and holdout output paths must differ from input data paths")
    normal_sequences = {tuple(row["calls"]) for row in normal_rows}
    labelled_sequences = [tuple(row["calls"]) for row in labelled_rows]
    if normal_sequences.intersection(labelled_sequences) or len(set(labelled_sequences)) != len(labelled_sequences):
        raise ValueError("Input files contain duplicate traces across or within splits; deduplicate before training")
    labels = np.array([int(row["label"] == "anomalous") for row in labelled_rows])
    if len(normal_rows) < 10 or min(np.bincount(labels, minlength=2)) < 8:
        raise ValueError("Need at least 10 normal training rows and 8 rows of each class in labelled data")

    # The holdout is fixed before model selection; validation alone sets cutoff.
    indices = np.arange(len(labelled_rows))
    development, holdout = train_test_split(
        indices, test_size=0.5, stratify=labels, random_state=HOLDOUT_SEED
    )
    fit_indices, validation = train_test_split(
        development, test_size=0.3, stratify=labels[development], random_state=RANDOM_SEED
    )
    fit_rows = normal_rows + [labelled_rows[index] for index in fit_indices]
    fit_labels = np.array([0] * len(normal_rows) + labels[fit_indices].tolist())
    texts = [" ".join(row["calls"]) for row in fit_rows]
    vectorizer = TfidfVectorizer(
        token_pattern=r"[^ ]+", ngram_range=(1, 2), min_df=2,
        sublinear_tf=True, max_features=20_000,
    )
    features = vectorizer.fit_transform(texts)
    model = LogisticRegression(C=10, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED)
    model.fit(features, fit_labels)

    validation_texts = [" ".join(labelled_rows[index]["calls"]) for index in validation]
    validation_scores = model.predict_proba(vectorizer.transform(validation_texts))[:, 1]
    precision, recall, cutoffs = precision_recall_curve(labels[validation], validation_scores)
    f1 = np.divide(2 * precision * recall, precision + recall,
                   out=np.zeros_like(precision), where=precision + recall > 0)
    best = int(np.argmax(f1[:-1]))  # The last PR point has no usable threshold.
    threshold = float(cutoffs[best])

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "version": SUPERVISED_ARTIFACT_VERSION,
        "model_type": "tfidf_logistic_regression",
        "model": model,
        "vectorizer": vectorizer,
        "threshold": threshold,
        "training_kind": "supervised_known_attack",
        "holdout_seed": HOLDOUT_SEED,
        "validation_seed": RANDOM_SEED,
    }
    joblib.dump(artifact, model_path)

    holdout_path = Path(holdout_path)
    holdout_path.parent.mkdir(parents=True, exist_ok=True)
    with holdout_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["process_id", "label", "syscalls"])
        for index in sorted(holdout):
            row = labelled_rows[index]
            writer.writerow([row["process_id"], row["label"], " ".join(row["calls"])])

    return {
        "model_path": str(model_path),
        "holdout_path": str(holdout_path),
        "normal_fit": int(np.sum(fit_labels == 0)),
        "anomalous_fit": int(np.sum(fit_labels == 1)),
        "normal_validation": int(np.sum(labels[validation] == 0)),
        "anomalous_validation": int(np.sum(labels[validation] == 1)),
        "normal_holdout": int(np.sum(labels[holdout] == 0)),
        "anomalous_holdout": int(np.sum(labels[holdout] == 1)),
        "validation_f1": float(f1[best]),
        "threshold": threshold,
        "labelled_data_sha256": hashlib.sha256(Path(labelled_data_path).read_bytes()).hexdigest(),
    }

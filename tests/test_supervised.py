"""Verify the optional labelled-data path and its saved prediction contract."""

import csv
import tempfile
import unittest
from pathlib import Path

from src.evaluate import evaluate_model
from src.predict import load_model, predict_trace
from src.supervised import train_supervised_model


def write_rows(path: Path, rows: list[tuple[str, str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["process_id", "label", "syscalls"])
        writer.writerows(rows)


class SupervisedTests(unittest.TestCase):
    def test_train_holdout_reload_and_predict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            normal_path, labelled_path = root / "normal.csv", root / "labelled.csv"
            model_path, holdout_path = root / "model.pkl", root / "holdout.csv"
            write_rows(normal_path, [
                (str(i), "normal", f"openat read read close normal{i}") for i in range(12)
            ])
            write_rows(labelled_path, [
                (str(i), "normal", f"openat read close benign{i}") for i in range(10)
            ] + [
                (str(i + 10), "anomalous", f"socket connect execve kill attack{i}") for i in range(10)
            ])
            result = train_supervised_model(normal_path, labelled_path, model_path,
                                            holdout_path=holdout_path)
            self.assertEqual(result["normal_holdout"], 5)
            self.assertEqual(result["anomalous_holdout"], 5)
            artifact = load_model(model_path)
            prediction = predict_trace(["socket", "connect", "execve", "kill"], artifact)
            self.assertEqual(set(prediction), {"status", "anomaly_score", "threshold"})
            self.assertTrue(0 <= prediction["anomaly_score"] <= 1)
            self.assertEqual(prediction, predict_trace("socket connect execve kill", artifact))
            self.assertTrue(0 <= predict_trace("never_seen_syscall", artifact)["anomaly_score"] <= 1)
            self.assertEqual(evaluate_model(holdout_path, model_path)["traces"], 10)
            with self.assertRaisesRegex(ValueError, "must differ"):
                train_supervised_model(normal_path, labelled_path, model_path,
                                       holdout_path=labelled_path)

    def test_rejects_overlapping_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            normal_path, labelled_path = root / "normal.csv", root / "labelled.csv"
            write_rows(normal_path, [
                (str(i), "normal", f"openat read close normal{i}") for i in range(12)
            ])
            write_rows(labelled_path, [
                ("x", "normal", "openat read close normal0"),
                *[(str(i), "normal", f"openat read close benign{i}") for i in range(9)],
                *[(str(i + 10), "anomalous", f"socket connect kill attack{i}") for i in range(10)],
            ])
            with self.assertRaisesRegex(ValueError, "duplicate traces"):
                train_supervised_model(normal_path, labelled_path, root / "model.pkl",
                                       holdout_path=root / "holdout.csv")


if __name__ == "__main__":
    unittest.main()

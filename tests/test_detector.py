"""Focused tests of the OS/AI input contract and the complete baseline."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

from src.evaluate import evaluate_model
from src.features import PAD_ID, UNKNOWN_ID, make_windows
from src.predict import load_model, predict_trace
from src.preprocess import load_traces, parse_trace
from src.train import trace_score, train_model


ROOT = Path(__file__).resolve().parents[1]


class ParsingTests(unittest.TestCase):
    def test_string_and_list_inputs(self):
        expected = ["openat", "read", "close"]
        self.assertEqual(parse_trace("openat, read close"), expected)
        self.assertEqual(parse_trace(["openat", "read", "close"]), expected)

    def test_invalid_inputs(self):
        for bad in ("", [], "openat(3) read", ["openat read"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_trace(bad)

    def test_text_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "normal.txt"
            path.write_text("openat read close\n\nsocket connect close\n", encoding="utf-8")
            rows = load_traces(path)
            self.assertEqual(len(rows), 2)
            self.assertIsNone(rows[0]["label"])
            with self.assertRaisesRegex(ValueError, "labelled CSV"):
                load_traces(path, require_labels=True)

    def test_windows_cover_long_and_short_traces(self):
        calls = [f"call{i}" for i in range(13)]
        windows = make_windows(calls, 6)
        self.assertEqual(windows[0], calls[:6])
        self.assertEqual(windows[-1], calls[-6:])
        self.assertEqual(make_windows(calls[:3], 6), [calls[:3]])


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.model_path = Path(cls.directory.name) / "model.pkl"
        cls.training = train_model(ROOT / "data/train.csv", cls.model_path)
        cls.artifact = load_model(cls.model_path)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_artifact_and_unseen_syscalls(self):
        encoder = self.artifact["encoder"]
        self.assertEqual(encoder.encode(["never_seen_call"]), [UNKNOWN_ID])
        encoded = encoder.encode_window(["openat", "never_seen_call"])
        self.assertEqual(len(encoded), encoder.window_size)
        self.assertEqual(encoded[1], UNKNOWN_ID)
        self.assertEqual(encoded[-1], PAD_ID)
        vector = encoder.transform_trace(["openat", "never_seen_call", "close"])
        self.assertTrue(np.isfinite(vector).all())
        result = predict_trace(["openat", "never_seen_call", "close"], self.artifact)
        self.assertIn(result["status"], {"NORMAL", "ANOMALOUS"})
        self.assertGreaterEqual(result["anomaly_score"], 0)
        self.assertLessEqual(result["anomaly_score"], 1)

    def test_novelty_bonus_and_three_call_features(self):
        encoder = self.artifact["encoder"]
        self.assertTrue(encoder.common_triples)
        self.assertEqual(encoder.novelty_rates(["never_seen_call"]), (1.0, 0.0))
        self.assertEqual(encoder.novelty_rates(["read", "socket"]), (0.0, 1.0))
        calls = ["never_seen_call"] * 3
        forest_only = trace_score(self.artifact["model"], encoder, calls,
                                  {"unknown_call": 0.0, "unseen_pair": 0.0})
        combined = predict_trace(calls, self.artifact)
        self.assertGreater(combined["anomaly_score"], forest_only)
        self.assertEqual(combined["status"], "ANOMALOUS")

    def test_old_artifact_requires_retraining(self):
        old_artifact = dict(self.artifact, version=1)
        with self.assertRaisesRegex(ValueError, "run train again"):
            predict_trace("openat read close", old_artifact)

    def test_saved_model_and_threshold_override(self):
        trace = "openat read mmap socket connect close"
        first = predict_trace(trace, self.artifact)
        reloaded = predict_trace(trace, load_model(self.model_path))
        self.assertEqual(first, reloaded)
        self.assertEqual(predict_trace(trace, self.artifact, threshold=0)["status"], "ANOMALOUS")
        self.assertEqual(predict_trace(trace, self.artifact, threshold=1)["status"], "NORMAL")
        with self.assertRaisesRegex(ValueError, "Threshold"):
            predict_trace(trace, self.artifact, threshold=1.5)

    def test_evaluation_uses_labelled_rows(self):
        metrics = evaluate_model(ROOT / "data/test.csv", self.model_path)
        self.assertEqual(metrics["traces"], 18)
        self.assertEqual(sum(metrics[key] for key in ("true_negatives", "false_positives", "false_negatives", "true_positives")), 18)
        for key in ("accuracy", "precision", "recall", "f1_score", "false_positive_rate"):
            self.assertGreaterEqual(metrics[key], 0)
            self.assertLessEqual(metrics[key], 1)

    def test_json_cli(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "predict", "--trace", "openat read close", "--model", str(self.model_path), "--json"],
            capture_output=True, text=True, check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(set(result), {"status", "anomaly_score", "threshold"})


if __name__ == "__main__":
    unittest.main()

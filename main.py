"""Command-line interface for the system-call anomaly detector."""

import argparse
import json
import sys

from src.evaluate import evaluate_model
from src.predict import load_model, predict_trace
from src.train import DEFAULT_MODEL_PATH, train_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="System Call Anomaly Detector")
    commands = parser.add_subparsers(dest="command", required=True)

    train = commands.add_parser("train", help="Fit on normal traces and save model")
    train.add_argument("--data", required=True, help="Training CSV or text file")
    train.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="Output model path")
    train.add_argument("--window-size", type=int, default=10, help="Syscalls per window (default: 10)")

    predict = commands.add_parser("predict", help="Score one cleaned trace")
    predict.add_argument("--trace", required=True, help="Whitespace- or comma-separated syscall names")
    predict.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="Saved model path")
    predict.add_argument("--threshold", type=float, help="Override saved cutoff (0 to 1)")
    predict.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    evaluate = commands.add_parser("evaluate", help="Measure results on labelled test CSV")
    evaluate.add_argument("--data", required=True, help="Labelled test CSV")
    evaluate.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="Saved model path")
    evaluate.add_argument("--threshold", type=float, help="Override saved cutoff (0 to 1)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "train":
            result = train_model(args.data, args.model, window_size=args.window_size)
            print("System Call Anomaly Detector\n")
            print(f"Model saved: {result['model_path']}")
            print(f"Normal training traces: {result['training_traces']}")
            print(f"Normal calibration traces: {result['calibration_traces']}")
            print(f"Training windows: {result['training_windows']}")
            print(f"Ignored anomalous traces: {result['ignored_anomalous_traces']}")
            print(f"Calibrated threshold: {result['threshold']:.4f}")
        elif args.command == "predict":
            result = predict_trace(args.trace, load_model(args.model), threshold=args.threshold)
            if args.json:
                print(json.dumps(result))
            else:
                print("System Call Anomaly Detector\n")
                print(f"Calls analysed: {len(args.trace.replace(',', ' ').split())}")
                print(f"Anomaly score: {result['anomaly_score']:.4f}")
                print(f"Threshold: {result['threshold']:.4f}\n")
                print(f"Result: {result['status']}")
        else:
            result = evaluate_model(args.data, args.model, threshold=args.threshold)
            print("System Call Anomaly Detector — evaluation\n")
            print(f"Traces: {result['traces']}")
            print(f"Accuracy: {result['accuracy']:.4f}")
            print(f"Precision: {result['precision']:.4f}")
            print(f"Recall: {result['recall']:.4f}")
            print(f"F1 Score: {result['f1_score']:.4f}")
            print(f"False Positive Rate: {result['false_positive_rate']:.4f}")
            print(f"Confusion counts (TN, FP, FN, TP): {result['true_negatives']}, {result['false_positives']}, {result['false_negatives']}, {result['true_positives']}")
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

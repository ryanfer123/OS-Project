"""Read already-cleaned syscall traces at the OS/AI boundary."""

import csv
import re
from pathlib import Path


SYSCALL_NAME = re.compile(r"[a-z_][a-z0-9_]*\Z")
VALID_LABELS = {"normal", "anomalous"}


def parse_trace(trace: str | list[str]) -> list[str]:
    """Accept a whitespace/comma-separated string or a list of syscall names."""
    if isinstance(trace, str):
        calls = re.split(r"[,\s]+", trace.strip()) if trace.strip() else []
    elif isinstance(trace, list) and all(isinstance(call, str) for call in trace):
        calls = [call.strip() for call in trace]
    else:
        raise ValueError("Trace must be a string or a list of syscall names")

    if not calls or any(not call for call in calls):
        raise ValueError("Trace must contain at least one syscall")
    calls = [call.lower() for call in calls]
    if any(not SYSCALL_NAME.fullmatch(call) for call in calls):
        raise ValueError("Expected cleaned syscall names, such as 'openat read close'")
    return calls


def load_traces(path: str | Path, *, require_labels: bool = False) -> list[dict]:
    """Load CSV rows or one cleaned trace per line in a .txt file."""
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"Data file does not exist: {path}")

    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or "syscalls" not in reader.fieldnames:
                raise ValueError("CSV must contain a 'syscalls' column")
            if require_labels and "label" not in reader.fieldnames:
                raise ValueError("Evaluation CSV must contain a 'label' column")
            rows = []
            for line_number, row in enumerate(reader, start=2):
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"CSV row {line_number}: wrong number of columns; quote syscall lists containing commas")
                try:
                    calls = parse_trace(row.get("syscalls") or "")
                except ValueError as error:
                    raise ValueError(f"CSV row {line_number}: {error}") from error
                raw_label = (row.get("label") or "").strip().lower()
                if "label" in reader.fieldnames and raw_label not in VALID_LABELS:
                    raise ValueError(f"CSV row {line_number}: label must be normal or anomalous")
                rows.append({
                    "process_id": row.get("process_id"),
                    "label": raw_label or None,
                    "calls": calls,
                })
    elif path.suffix.lower() == ".txt":
        if require_labels:
            raise ValueError("Evaluation requires a labelled CSV file")
        rows = []
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    calls = parse_trace(line)
                except ValueError as error:
                    raise ValueError(f"Text line {line_number}: {error}") from error
                rows.append({"process_id": None, "label": None, "calls": calls})
    else:
        raise ValueError("Data file must have a .csv or .txt extension")

    if not rows:
        raise ValueError("Data file contains no traces")
    return rows

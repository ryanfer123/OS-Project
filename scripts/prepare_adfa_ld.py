"""Convert an ADFA-LD ZIP archive into this project's CSV input format.

ADFA-LD contains numeric syscall IDs, not syscall names. Preserve each ID as
`syscall_<number>` rather than guessing an architecture-dependent name.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile


SPLITS = {
    "Training_Data_Master": "train",
    "Validation_Data_Master": "normal_test",
    "Attack_Data_Master": "attack_test",
}
SOURCE_URL = "https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset"


def read_archive(archive_path: Path) -> tuple[dict, dict]:
    """Return unique numeric sequences per original split and source counts."""
    groups = {split: {} for split in SPLITS.values()}
    counts = {split: 0 for split in SPLITS.values()}
    with ZipFile(archive_path) as archive:
        for member in sorted(archive.namelist()):
            if not member.endswith(".txt"):
                continue
            parts = Path(member).parts
            split_name = next((part for part in parts if part in SPLITS), None)
            if split_name is None:
                continue
            split = SPLITS[split_name]
            tokens = archive.read(member).decode("utf-8").split()
            if not tokens or any(not token.isdecimal() for token in tokens):
                raise ValueError(f"Invalid numeric syscall sequence in {member}")
            # Canonicalize leading zeros so equal IDs cannot evade deduplication.
            sequence = tuple(str(int(token)) for token in tokens)
            groups[split].setdefault(sequence, member)
            counts[split] += 1
    if any(not group for group in groups.values()):
        raise ValueError("Archive must contain nonempty training, validation, and attack splits")
    return groups, counts


def prepare(archive_path: str | Path, output_dir: str | Path) -> dict:
    archive_path = Path(archive_path)
    output_dir = Path(output_dir)
    if not archive_path.is_file():
        raise ValueError(f"Archive does not exist: {archive_path}")
    groups, source_counts = read_archive(archive_path)
    train, normal_test, attack_test = (groups[key] for key in SPLITS.values())

    # A sequence with both labels cannot be a reliable evaluation example.
    ambiguous = set(attack_test) & (set(train) | set(normal_test))
    train_keys = set(train) - ambiguous
    normal_keys = set(normal_test) - set(train) - ambiguous
    attack_keys = set(attack_test) - ambiguous

    def write_csv(path: Path, entries: list[tuple[tuple[str, ...], str, str]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["process_id", "label", "syscalls"])
            for sequence, source_name, label in entries:
                calls = " ".join(f"syscall_{number}" for number in sequence)
                writer.writerow([source_name, label, calls])

    output_dir.mkdir(parents=True, exist_ok=True)
    train_rows = sorted(((key, train[key], "normal") for key in train_keys), key=lambda row: row[1])
    test_rows = sorted(
        [(key, normal_test[key], "normal") for key in normal_keys]
        + [(key, attack_test[key], "anomalous") for key in attack_keys],
        key=lambda row: row[1],
    )
    write_csv(output_dir / "train.csv", train_rows)
    write_csv(output_dir / "test.csv", test_rows)

    manifest = {
        "source_mirror": SOURCE_URL,
        "original_source": "https://research.unsw.edu.au/projects/adfa-ids-datasets",
        "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "original_files": source_counts,
        "unique_sequences": {key: len(group) for key, group in groups.items()},
        "ambiguous_normal_attack_sequences_removed": len(ambiguous),
        "normal_validation_sequences_seen_in_training_removed": len(set(normal_test) & set(train)),
        "output_train_normal": len(train_rows),
        "output_test_normal": len(normal_keys),
        "output_test_anomalous": len(attack_keys),
        "conversion": "numeric syscall ID n becomes syscall_n; identical traces deduplicated; cross-split and conflicting-label traces removed",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare ADFA-LD for the anomaly detector")
    parser.add_argument("--archive", required=True, help="Path to ADFA-LD ZIP archive")
    parser.add_argument("--output", default="data/adfa_ld", help="Output directory (default: data/adfa_ld)")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.archive, args.output), indent=2))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()

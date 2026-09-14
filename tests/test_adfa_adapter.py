"""The public dataset adapter must preserve splits and reject ambiguous labels."""

import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from scripts.prepare_adfa_ld import prepare
from src.preprocess import load_traces


class ADFAPreparationTests(unittest.TestCase):
    def test_split_deduplication_and_numeric_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "sample.zip"
            with ZipFile(archive_path, "w") as archive:
                for name, contents in {
                    "ADFA-LD/Training_Data_Master/a.txt": "1 2 3",
                    "ADFA-LD/Training_Data_Master/b.txt": "01 2 3",
                    "ADFA-LD/Training_Data_Master/c.txt": "1 2 4",
                    "ADFA-LD/Validation_Data_Master/d.txt": "1 2 3",
                    "ADFA-LD/Validation_Data_Master/e.txt": "5 6",
                    "ADFA-LD/Validation_Data_Master/f.txt": "7 8",
                    "ADFA-LD/Attack_Data_Master/g.txt": "7 8",
                    "ADFA-LD/Attack_Data_Master/h.txt": "9 10",
                }.items():
                    archive.writestr(name, contents)
            output = Path(directory) / "converted"
            manifest = prepare(archive_path, output)
            train = load_traces(output / "train.csv")
            test = load_traces(output / "test.csv", require_labels=True)
            self.assertEqual(len(train), 2)
            by_label = {row["label"]: row["calls"] for row in test}
            self.assertEqual(by_label, {
                "normal": ["syscall_5", "syscall_6"],
                "anomalous": ["syscall_9", "syscall_10"],
            })
            self.assertEqual(manifest["ambiguous_normal_attack_sequences_removed"], 1)
            self.assertEqual(manifest["normal_validation_sequences_seen_in_training_removed"], 1)


if __name__ == "__main__":
    unittest.main()

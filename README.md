# AI-Based System Call Anomaly Detector

The AI half of a third-year Operating Systems project. Given a **cleaned sequence of Linux system calls**, it returns one anomaly score and a `NORMAL` or `ANOMALOUS` decision per trace. The default model is a normal-only Isolation Forest. An optional classifier can learn from labelled examples of known attacks.

```text
OS module: running process → syscall monitoring → cleaned syscall sequence
AI module: cleaned sequence → features → model → score → threshold → result
```

## Measured results

These are **ADFA-LD benchmark results**, not scores from the synthetic demo. Both models were evaluated on the **same reserved holdout of 1,535 traces** (1,170 normal; 365 attack):

| Model | Accuracy | Precision | Recall | F1 | False-positive rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Normal-only Isolation Forest | 65.99% | 30.99% | 35.07% | 32.90% | 24.36% |
| Supervised TF-IDF + logistic regression | 93.75% | 83.21% | 92.33% | 87.53% | 5.81% |

`ANOMALOUS` is the positive class. The supervised model learned from **255 labelled attack traces**, and the holdout contains attack families represented during training. Its result measures **known-family detection**, not zero-day detection. The normal-only model uses no attack examples to fit or calibrate its threshold. On the full, separate 3,070-trace baseline test, its F1 was **31.00%** and false-positive rate **24.02%**. See the [evaluation report](reports/adfa_ld_evaluation.md) for confusion counts, splits, commands, and limitations.

The ADFA-LD archive came from a [public mirror](https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset) because the [official dataset page](https://research.unsw.edu.au/projects/adfa-ids-datasets) did not provide a reachable download during this run. Split counts matched published counts, but byte-for-byte identity with the official archive was not verified. The dataset has academic-use restrictions and is **not included in this repository**.

## Quick start

Use Python 3.11 or newer (verified with Python 3.13). From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py train --data data/train.csv
python main.py predict --trace "openat read mmap socket connect close"
python main.py evaluate --data data/test.csv
```

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`. Training writes `models/anomaly_model.pkl`; generated model files are ignored by Git. The included `data/train.csv` and `data/test.csv` are **small, synthetic smoke-test data**. Their evaluation output does not estimate real-world performance.

For machine-readable prediction, run:

```bash
python main.py predict --trace "openat read read mmap close" --json
```

The output contains `status`, `anomaly_score`, and `threshold`. A higher score means more unusual behaviour; it is **not an attack probability**. `predict` and `evaluate` accept `--threshold 0.55` to override the saved cutoff, and all commands accept `--model path/to/model.pkl`.

## Reproduce the public-dataset evaluation

Download the archived mirror and convert it into one CSV row per trace:

```bash
git clone --depth 1 https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset.git /tmp/adfa-ld-source
python scripts/prepare_adfa_ld.py --archive /tmp/adfa-ld-source/ADFA-LD.zip
```

Train and evaluate the **normal-only baseline**:

```bash
python main.py train --data data/adfa_ld/train.csv --model models/adfa_ld_model.pkl
python main.py evaluate --data data/adfa_ld/test.csv --model models/adfa_ld_model.pkl
```

Train and evaluate the **supervised known-attack model** on its reserved holdout:

```bash
python main.py train-supervised --normal-data data/adfa_ld/train.csv --data data/adfa_ld/test.csv --model models/adfa_ld_supervised.pkl --holdout-output data/adfa_ld/supervised_holdout.csv
python main.py evaluate --data data/adfa_ld/supervised_holdout.csv --model models/adfa_ld_supervised.pkl
```

The converter preserves numeric IDs as `syscall_n` tokens; it does not guess Linux syscall names. These ADFA-trained models therefore require `syscall_n` input and **cannot meaningfully score named live calls** until a verified mapping or matching training data is available. The detailed [evaluation report](reports/adfa_ld_evaluation.md) records the archive checksum, deduplication, data splits, model settings, and measured results. Converted data and trained models are ignored by Git.

## Input and OS-module integration

A CSV needs a `syscalls` column. `process_id` is optional metadata. Training may omit `label`, in which case every row is treated as normal; otherwise labels must be `normal` or `anomalous`. Evaluation requires labels. A `.txt` training file may contain one normal trace per nonempty line.

```csv
process_id,label,syscalls
101,normal,"openat read read mmap close"
102,anomalous,"openat socket connect execve chmod"
```

Separate calls with spaces or commas. Provide **clean syscall names only**: the OS module must remove `strace` arguments, timestamps, PIDs, and return values before calling this module. Empty traces and malformed names raise an error; unseen valid names are mapped to an `UNKNOWN` ID. Keep training, threshold-calibration, and test traces separate.

For repeated predictions, load the model once in the OS module:

```python
from src.predict import load_model, predict_trace

model = load_model("models/anomaly_model.pkl")
result = predict_trace(["openat", "read", "read", "mmap", "close"], model)
# A string such as "openat read read mmap close" also works.
# result: {"status": ..., "anomaly_score": ..., "threshold": ...}
```

The OS module can alert when `result["status"] == "ANOMALOUS"`. It may instead invoke the CLI with `--json` and parse the same result. The AI module does not monitor running processes itself.

## Models and evaluation

The baseline splits each trace into overlapping fixed-length windows (10 calls by default), learns syscall IDs from normal training data, and computes call frequencies, unique-call and window-length counts, selected syscall-category counts, and common adjacent pairs/triples. It fits an `IsolationForest` on **normal windows only**. Each window receives `-score_samples` plus small fixed penalties for unseen calls and pairs; the trace receives its highest window score. The saved cutoff is the 95th percentile of **held-out normal trace scores**. A score at or above the cutoff is `ANOMALOUS`. The model artifact includes the forest, vocabulary, feature settings, and threshold, so inference uses the same representation.

The optional supervised model uses TF-IDF features for single calls and adjacent pairs, then class-weighted logistic regression. It fits on labelled normal and known-attack examples and selects a cutoff on a separate validation partition. Its 0–1 decision score is **not a calibrated attack probability**. The final holdout does not fit the vectorizer, classifier, or cutoff.

`evaluate` prints accuracy, precision, recall, F1, false-positive rate, and confusion counts. A **false positive** is a genuinely normal trace labelled anomalous; its rate is `FP / (FP + TN)`. The baseline's main limitations are missing syscall arguments and return values, limited sequence context, mixed process behaviour, and the use of a maximum window score, which can raise alerts more often for long traces. These are reasons to evaluate on real traces before relying on an alert.

## Repository and contributing

| Path | Purpose |
| --- | --- |
| `main.py` | CLI entry point |
| `src/preprocess.py`, `src/features.py` | Parsing, windows, and feature representation |
| `src/train.py`, `src/supervised.py` | Normal-only and labelled model training |
| `src/predict.py`, `src/evaluate.py` | Inference and metrics |
| `scripts/prepare_adfa_ld.py` | Public-dataset conversion |
| `data/` | Synthetic examples; generated ADFA data is ignored |
| `reports/` | Reproducible benchmark notes |
| `tests/` | Unit and end-to-end tests |

Run the checks before a pull request:

```bash
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, test expectations, and data-handling rules. GitHub Actions runs the tests on pushes and pull requests. The baseline follows the [original Isolation Forest paper](https://doi.org/10.1109/ICDM.2008.17); [scikit-learn documents the direction of `score_samples`](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html). Recent syscall work motivates richer ordering and context: [position-specific scoring (2025)](https://doi.org/10.1016/j.cose.2025.104613) and [container intrusion detection (2025)](https://www.sciencedirect.com/science/article/pii/S0167404825001270).

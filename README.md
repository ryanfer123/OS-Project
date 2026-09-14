# AI-Based System Call Anomaly Detector

This is the **AI half** of a third-year Operating Systems project. It accepts cleaned Linux syscall names and returns one anomaly result per trace. The normal-only Isolation Forest remains the default baseline. An optional supervised model uses labelled examples of known attacks when those are available. The monitoring teammate owns `strace`/collection and basic extraction; this module begins after those steps.

```text
Running process → monitoring → cleaned syscall sequence
                                  ↓
                     windows → behavioural features → Isolation Forest
                                  ↓
                     anomaly score → threshold → NORMAL / ANOMALOUS
```

## Install and run

Use Python 3.13 (3.11+ should also work). From this project directory:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py train --data data/train.csv
python main.py predict --trace "openat read mmap socket connect close"
python main.py evaluate --data data/test.csv
python -m unittest discover -s tests -v
```

`data/train.csv` and `data/test.csv` are **small synthetic examples written only to exercise the pipeline**. Their labels and measured metrics are not a claim about real Linux attacks or deployment accuracy. Replace them with independently collected traces to evaluate a real system. Training creates `models/anomaly_model.pkl`; this generated artifact is ignored by Git, so retrain after a fresh clone.

## Public-dataset evaluation

The project has also been evaluated on [ADFA-LD](https://research.unsw.edu.au/projects/adfa-ids-datasets), a Linux syscall-trace benchmark. The official download endpoint was unavailable during this evaluation, so the archive came from a [public mirror](https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset). Its split counts match [published counts](https://www.mdpi.com/2076-3417/9/1/178) of 833 normal training, 4,372 normal validation, and 746 attack files, but no official checksum was available to verify byte-for-byte identity. See [the benchmark report](reports/adfa_ld_evaluation.md) for the exact counts, method, and results.

To reproduce the conversion and run locally:

```bash
git clone --depth 1 https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset.git /tmp/adfa-ld-source
python scripts/prepare_adfa_ld.py --archive /tmp/adfa-ld-source/ADFA-LD.zip
python main.py train --data data/adfa_ld/train.csv --model models/adfa_ld_model.pkl
python main.py evaluate --data data/adfa_ld/test.csv --model models/adfa_ld_model.pkl
```

The normal-only model has limited detection quality on this benchmark. For an explicitly **known-attack** comparison that reached the requested 75% target on a reserved holdout, run:

```bash
python main.py train-supervised --normal-data data/adfa_ld/train.csv --data data/adfa_ld/test.csv --model models/adfa_ld_supervised.pkl --holdout-output data/adfa_ld/supervised_holdout.csv
python main.py evaluate --data data/adfa_ld/supervised_holdout.csv --model models/adfa_ld_supervised.pkl
python main.py predict --trace "syscall_1 syscall_2 syscall_3" --model models/adfa_ld_supervised.pkl --json
```

`train-supervised` first reserves half the labelled input as a holdout, then splits the other half into model-fit and threshold-validation partitions. It adds the separate normal-only training file to model fitting. It learns TF-IDF frequencies of single calls and adjacent pairs, fits class-weighted logistic regression, and chooses the cutoff for best F1 on validation labels. Its `anomaly_score` is a **0–1 model decision score, not a calibrated probability of attack**. Holdout labels are used to stratify the split and compute final metrics, never to fit features, the classifier, or the cutoff. This model recognizes patterns similar to the attack examples it saw; it is not evidence of zero-day detection. **An ADFA-trained artifact expects `syscall_n` tokens; it cannot score the teammate's named-syscall stream meaningfully without a verified ID/name conversion.** Use the normal-only model for that separate research question.

The converter retains the dataset's syscall numbers as names such as `syscall_45`; it does **not** guess Linux syscall names from an unverified mapping. It removes duplicate traces, training/test overlap, and traces with conflicting normal/attack labels. Generated data and model files stay out of Git. Because these placeholders are not real names, the file/network/process/permission category features are zero in this evaluation.

The CLI also accepts `--model path/to/model.pkl` on all commands. `predict` and `evaluate` accept `--threshold 0.55` to override the saved cutoff. `predict --json` prints a machine-readable object. Training accepts `--window-size 10` (minimum 2).

## Input contract

CSV must have a `syscalls` header. `process_id` and `label` are optional for training; evaluation requires `label` with `normal` and `anomalous` values. If training labels are absent, **all rows are assumed normal**. Rows labelled anomalous in a training CSV are skipped. A label column, when present, must have a valid label on every row. Keep training and test traces separate.

```csv
process_id,label,syscalls
101,normal,"openat read read mmap close"
102,anomalous,"openat socket connect execve chmod"
```

For training, a `.txt` file may contain one cleaned normal trace per nonempty line. Evaluation uses labelled CSV only. Within a CSV cell or CLI string, commas and whitespace separate syscall names. Input must contain names only, such as `openat` or `clone3`; raw `strace` lines with arguments, timestamps, return values, and PIDs must be cleaned by the OS module first. Names are case-normalized. Empty traces and malformed names produce an error.

## How the baseline works

1. Split each trace into windows of 10 calls by default, moving half a window at a time. The last full window covers the end. A shorter trace becomes one window padded to 10 numeric IDs; padding is excluded from behaviour counts, and the actual length is a feature. No windows from a held-out calibration trace enter model training.
2. Learn a stable dictionary of syscall IDs from normal training traces. ID `0` is reserved for padding and ID `1` represents any previously unseen syscall. The model's feature columns never change at prediction time.
3. For each window, calculate relative frequency of each learned syscall, number of distinct calls, length, unseen-call count, file/network/process/permission category counts, and frequencies of the 20 most common adjacent syscall pairs and three-call patterns. These short patterns retain limited order information that a pure bag of calls would lose.
4. Fit `IsolationForest` to windows from normal training traces only, with random seed `42`. A window starts with `-model.score_samples(features)`; a **higher** value means the forest isolates it more readily. Add `0.20 × unseen-call fraction + 0.10 × unseen-pair fraction` (capped at 1), because a forest cannot split on a feature that was always zero during fitting. A trace's score is its highest window score, so one suspicious segment can alert. The weights are fixed before evaluation and saved in the artifact. This combined score is **not an attack probability**.
5. The default threshold is the 95th percentile of scores from held-out **normal traces**, using the same whole-trace aggregation. If `score >= threshold`, the status is `ANOMALOUS`; otherwise it is `NORMAL`. The threshold printed after training is learned from data, so it need not be `0.60`. An override changes the decision cutoff without retraining.

The artifact stores the forest, vocabulary, selected pairs/triples, window settings, novelty weights, and threshold together. Retrain after changing the artifact format; an incompatible old file produces a clear error. To try another model later, keep parsing/features and replace the fit/score functions while preserving the `predict_trace` result contract.

## Connect to the OS module

For repeated in-process predictions, load the model once:

```python
from src.predict import load_model, predict_trace

model = load_model("models/anomaly_model.pkl")
result = predict_trace(["openat", "read", "read", "mmap", "close"], model)
# The same function accepts "openat read read mmap close".
# {'status': 'NORMAL' or 'ANOMALOUS', 'anomaly_score': <float>, 'threshold': <float>}
```

For a separate process, the OS module can call:

```bash
python main.py predict --trace "openat read read mmap close" --json
```

Parse the JSON output and trigger the alert in the OS module when `status` is `ANOMALOUS`. `process_id` is carried in the CSV for identification but is not an AI feature. This first baseline pools normal traces across processes because the input does not identify a stable process type.

## Evaluation and viva notes

`evaluate` prints accuracy, precision, recall, F1, false-positive rate, and confusion counts. **Anomalous** is the positive class. False-positive rate is `FP / (FP + TN)`: a false positive is a genuinely normal trace flagged anomalous. For the normal-only baseline, no attack labels are used in fitting or threshold calibration. For the supervised option, labelled development examples train the classifier and choose its threshold; its reserved holdout labels are used only for final metrics.

- **Why Isolation Forest?** It can learn from mostly normal data, needs no attack examples to fit, trains quickly on simple numeric features, and is easier to explain than an LSTM. See the [original paper](https://doi.org/10.1109/ICDM.2008.17).
- **What does the score mean?** It combines the forest's isolation score with small penalties for calls and adjacent pairs missing from normal training data, using the trace's most unusual window. Higher is more unusual; it is not a probability or a guarantee of malicious activity. Scikit-learn's [`score_samples` documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html) explains the forest-score direction.
- **How does the threshold work?** It is calibrated on held-out normal traces; lowering it usually catches more anomalies but can create more false positives.
- **What are the limits?** Syscall names omit arguments and return values. Pairs/triples only capture local order. An unseen call maps to `UNKNOWN`; the explicit novelty bonus helps but can also flag legitimate new behaviour. A mixed-process model can mistake a legitimate new process for an anomaly or overlook an attack resembling known behaviour. Long traces have more opportunities to contain a high-scoring window. Synthetic metrics do not estimate field performance.

Recent syscall research explores richer ordering and context, including [position-specific scoring (2025)](https://doi.org/10.1016/j.cose.2025.104613), [graph-based representation for container intrusion detection (2025)](https://www.sciencedirect.com/science/article/pii/S0167404825001270), and [short-pattern feature extraction (2020)](https://doi.org/10.1016/j.infsof.2020.106348). After collecting real data, sensible next steps are process-type-specific baselines and threshold analysis on real held-out normal traces. Deep learning should follow only if this baseline's measured errors justify it.

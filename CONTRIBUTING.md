# Contributing

Contributions to parsing, features, models, evaluation, tests, and documentation are welcome. Keep the command-line and Python prediction contracts simple for the OS-module handoff.

## Set up and check a change

1. Fork the repository and create a branch for your change.
2. Use Python 3.11 or newer and install the dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   ```

   On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.
3. Make a focused change. The file map in [README.md](README.md#repository-and-contributing) shows where each part lives.
4. Run the tests and the synthetic end-to-end commands:

   ```bash
   python -m unittest discover -s tests -v
   python main.py train --data data/train.csv
   python main.py predict --trace "openat read mmap socket connect close" --json
   python main.py evaluate --data data/test.csv
   ```

5. Open a pull request describing the behaviour changed, how it was tested, and any effect on saved-model compatibility or reported metrics.

## Data and model changes

- Keep each CSV row as one whole trace. Do not let windows or duplicate traces cross model-fit, calibration, and final-test boundaries.
- Fit vocabularies and feature selectors only on the appropriate training partition. Set thresholds on validation or held-out normal traces, never on the final test set.
- When reporting a metric, name the dataset, split, sample counts, positive class, and model. Include confusion counts and false-positive rate. Do not present synthetic-data metrics as a benchmark.
- Add tests for parser or model-contract changes. Preserve the `predict_trace(...)` result keys: `status`, `anomaly_score`, and `threshold`.
- Do not commit downloaded datasets or trained `*.pkl` artifacts. ADFA-LD has academic-use restrictions; follow its source terms. Use the synthetic CSVs only as examples and smoke tests.

If a new model needs a different input vocabulary, document the conversion and avoid claiming that an ADFA `syscall_n` model accepts named live syscalls. Update [the evaluation report](reports/adfa_ld_evaluation.md) only with results from a reproducible run.

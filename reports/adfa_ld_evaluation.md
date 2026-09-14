# ADFA-LD evaluation

This report records a run on **public ADFA-LD traces**, separate from the synthetic demo. The [dataset owner describes ADFA-LD as a Linux system-call HIDS dataset](https://research.unsw.edu.au/projects/adfa-ids-datasets). The official download endpoint was not reachable during this run, so the archive was obtained from [this public mirror](https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset). Its three split counts match [published dataset counts](https://www.mdpi.com/2076-3417/9/1/178); byte-for-byte identity with the official archive could not be checked. UNSW grants free academic research use and prohibits commercial use.

Archive SHA-256: `58d625470749344843a7f730b0875ce9b8769f6fa48f18dc4a92bd07c342ead5`.

## Preparation

`scripts/prepare_adfa_ld.py` converted each numeric syscall ID `n` to the token `syscall_n`. It kept the source split: original training files became normal training rows, and validation plus attack files became evaluation rows. It removed identical traces within splits, validation traces also present in training, and two sequences carrying conflicting normal/attack labels. Each CSV row remains a whole source trace.

| Split | Original files | Unique sequences | Used |
| --- | ---: | ---: | ---: |
| Normal training | 833 | 780 | 780 |
| Normal validation | 4,372 | 2,420 | 2,340 normal test |
| Attack | 746 | 732 | 730 anomalous test |

The training command then split the 780 normal rows into **624 model-fit** and **156 threshold-calibration** traces with seed 42. No attack labels set the threshold. The test CSV contained 3,070 rows and was not used to fit features, the forest, or the cutoff. Numeric placeholders mean the model's named syscall-category counts contribute no information here.

## Measured results

Commands: `python main.py train --data data/adfa_ld/train.csv --model models/adfa_ld_model.pkl` and `python main.py evaluate --data data/adfa_ld/test.csv --model models/adfa_ld_model.pkl`.

| Metric | Result |
| --- | ---: |
| Accuracy | 0.6564 |
| Precision | 0.2966 |
| Recall | 0.3247 |
| F1-score | 0.3100 |
| False-positive rate | 0.2402 |

Confusion counts: **TN 1,778; FP 562; FN 493; TP 237**. The calibrated score threshold was **0.4086**. These numbers are from this specific archived mirror, conversion, fixed seed, and model version; they are not the synthetic-demo scores.

The false-positive rate rose with normal-trace length in this run: **16.0%** for traces of at most 100 calls and **41.9%** for traces longer than 1,000 calls. This is consistent with the current choice to take the maximum score across all windows: longer traces provide more chances for one unusual window. That pattern is an observation, not proof that length is the only cause. The model also lacks syscall arguments and true syscall-name categories, and it pools different process behaviours. The benchmark therefore shows a meaningful limitation rather than deployment-ready detection.

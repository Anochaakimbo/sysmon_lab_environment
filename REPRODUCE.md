# Reproducing the paper's tables

Paper: *A System for Classifying Simulated Attack Behavior on Linux and Windows Using Machine Learning
and Sysmon Event Logs* (NCCY). This file maps every table to the command that produces it.

## 1. Environment

| | Version used for the check below |
|---|---|
| Python | 3.14.7 |
| scikit-learn | 1.9.0 |
| pandas | 3.0.5 |
| numpy | 2.5.2 |
| scipy | 1.18.1 |

`pip install -r requirements.txt` installs these versions.
Random seed: `SEED = 0` in `host/revised_experiments.py` (models, `GroupShuffleSplit`);
the 5 repeats of the lineage CV use `StratifiedGroupKFold(random_state=0..4)`.

## 2. Data

The dataset is in the repository, no VM is needed:

| File | What |
|---|---|
| `FINAL_DATASET.csv` | the 81,331 events / 80 columns of the paper as submitted (12 runs) |
| `data/FINAL_DATASET_fixed.csv.gz` | **camera-ready dataset**: the same events after the Windows parser fix (multi-line CommandLine, 105 ProcessCreate events lost `ParentProcessGuid`); Windows label=1 33.3% -> 51.9% |
| `data/new_runs/*_labeled.csv` | the 2 independent Linux runs of Table 4 ("รอบทดลองใหม่") |
| `data/machine2/*_labeled.csv.gz` | post-review second machine per OS (Ubuntu 24.04, Windows 11), 12 runs |
| `data/machine1_win_fixed/*_labeled.csv.gz` | the 6 Windows runs of `FINAL_DATASET_fixed` per run; used by `machine_eval.py` |

The scripts read them from `host/dataset/`:

```bash
mkdir -p host/dataset
gunzip -c data/FINAL_DATASET_fixed.csv.gz > host/dataset/merged_dataset.csv   # camera-ready tables
# cp FINAL_DATASET.csv host/dataset/merged_dataset.csv                     # submitted version
cp data/new_runs/*_labeled.csv host/dataset/
```

To rebuild the CSVs from the raw Sysmon logs instead, see `host/rebuild_dataset.py` and `host/merge_dataset.py`
(raw logs are not in the repository because of their size).

## 3. Tables

| Paper | Command | Output |
|---|---|---|
| Table 3 (lineage CV, 25 folds, 7 models) | `python host/revised_experiments.py` | `reference/revised_results/p1_summary.csv` |
| Table 4 "แยกรอบทดลอง" (leave-one-attack-run-out) | same | `p2_summary.csv` |
| Table 4 "ตัดประเภทการโจมตี" (leave-one-scenario-out) | same | `p3_summary.csv` |
| Table 4 "รอบทดลองใหม่" (2 new Linux runs) | same | `p4_independent_runs.csv` |
| Section 4.1 composite key / random process split | same | `key_impact.csv`, `rf_random_process_split.csv` |
| Section 5 ablation without `cmd_len`, `pcmd_len` | `python host/ablation_cmdlen.py` | `reference/revised_results/ablation_cmdlen.json` |
| Table 6 feature importance (impurity + permutation) | `python host/feature_importance.py` | `reference/revised_results/feature_importance.csv` |
| Cross-platform transfer (train one OS, test the other) | `python host/cross_platform_eval.py --merged merged_dataset.csv` | `reference/cross_platform/` |
| Post-review leave-one-machine-out | `python host/machine_eval.py` (reads `FINAL_DATASET.csv`, `data/machine1_win_fixed/`, `data/machine2/`) | `reference/machine_eval/` |

`revised_experiments.py` takes optional `[dataset_dir] [output_dir]` arguments; it caches finished
protocols as CSV in the output directory, so delete that directory to recompute everything (~5 min on 16 cores).

## 4. Which code version

**Camera-ready tables** (after the review): evaluation code of `fa377a0` (unchanged protocol) on
`data/FINAL_DATASET_fixed.csv.gz`, so the only difference from the submitted tables is the corrected Windows labels.
`ablation_cmdlen.py`, `feature_importance.py` and `cross_platform_eval.py` come from `main`.
Running `fa377a0` twice in the environment above gives the same results (differences below 1e-15).

| Table | Model | Submitted | Camera-ready |
|---|---|---|---|
| 3 | Random Forest F1 / AUC | 0.920±0.008 / 0.986±0.002 | 0.925±0.012 / 0.987±0.003 |
| 3 | LOF AUC / Recall | 0.839±0.016 / 0.331 | 0.832±0.014 / 0.340 |
| 4 run-out | Random Forest F1 / AUC | 0.768±0.150 / 0.897±0.067 | 0.755±0.177 / 0.907±0.059 |
| 4 scenario-out | Random Forest F1 / AUC | 0.767±0.093 / 0.892±0.056 | 0.770±0.107 / 0.906±0.054 |
| 4 new runs | Random Forest F1 / FPR / AUC | 0.915 / 0.039 / 0.978 | 0.921 / 0.033 / 0.983 |
| 5 | RF Windows -> Windows F1 / AUC | 0.951 / 0.993 | 0.971 / 0.996 |
| 5 | RF Linux -> Windows / Windows -> Linux AUC | 0.568 / 0.389 | 0.581 / 0.351 |
| 6 | RF without `cmd_len`/`pcmd_len` F1 / AUC | 0.596±0.040 / 0.790 | 0.602±0.042 / 0.795 |

### Submitted version

The tables in the submitted paper were produced by `host/revised_experiments.py` as committed in
**`fa377a0`** (scaler fitted on the whole training fold, SVM trained on at most 8,000 samples).
Later commits changed the evaluation after review (anomaly detectors get a scaler fitted on benign data
only; SVM uses the full training fold; every metric also reported per platform). To reproduce the
paper exactly use `git checkout fa377a0` for the evaluation code; the current `main` gives the revised numbers.

## 5. Reproduction check (fa377a0, environment above)

| Table | Model | Paper | Re-run |
|---|---|---|---|
| 3 | Random Forest F1 / AUC | 0.920±0.008 / 0.986±0.002 | 0.919±0.009 / 0.986±0.003 |
| 3 | Decision Tree F1 / AUC | 0.775±0.079 / 0.911±0.056 | 0.759±0.073 / 0.901±0.052 |
| 3 | SVM, Naive Bayes, LOF, Isolation Forest, One-Class SVM | — | identical to 3 decimals |
| 4 run-out | Random Forest F1 / AUC | 0.768±0.150 / 0.897±0.067 | 0.760±0.155 / 0.894±0.063 |
| 4 scenario-out | Random Forest F1 / AUC | 0.767±0.093 / 0.892±0.056 | 0.764±0.109 / 0.894±0.053 |
| 4 new runs | Random Forest F1 / FPR / AUC | 0.915 / 0.039 / 0.978 | 0.913 / 0.047 / 0.977 |
| 4.1 | random process split RF F1 | 0.919±0.006 | 0.920±0.005 |
| 5 | RF without `cmd_len`/`pcmd_len` F1 / AUC (current `ablation_cmdlen.py`) | 0.596±0.040 / 0.790 | 0.595±0.039 / 0.790±0.019 |

The deterministic models reproduce exactly. Random Forest and Decision Tree differ by at most 0.016 F1;
the paper's numbers were computed in a different environment and tree construction is not bit-identical
across scikit-learn versions even with a fixed `random_state`.

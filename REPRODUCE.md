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
| `data/repeat/*_labeled.csv.gz` | post-review repetitions 1 and 2 of every scenario on machine 1 (same VMs as the paper), 24 runs |

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
| Post-review leave-one-repetition-out | `python host/repeat_eval.py` (reads the same files as `machine_eval.py` plus `data/repeat/`) | `reference/repeat_eval/` |

`revised_experiments.py` takes optional `[dataset_dir] [output_dir]` arguments; it caches finished
protocols as CSV in the output directory, so delete that directory to recompute everything (~5 min on 16 cores).

## 4. Which code version

**Camera-ready tables** (after the review): evaluation code of `fa377a0` (unchanged protocol) on
`data/FINAL_DATASET_fixed.csv.gz`, so the only difference from the submitted tables is the corrected Windows labels.
`ablation_cmdlen.py`, `feature_importance.py` and `cross_platform_eval.py` come from `main`.
Running `fa377a0` twice in the environment above gives the same results (differences below 1e-15).
The other scripts rerun identically except `cross_platform_eval.py`, whose per-fold ROC-AUC can differ by
up to 2e-7 (Random Forest probability ties); the summary to 3 decimals is unchanged.

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

## 6. Supplementary pooled Linux + Windows experiment (53 features)

This is a separate experiment from the primary 32-feature tables above. In the
updated manuscript it is Section 3.7 / Section 4.6, Table 6; feature importance
is consequently Table 7. The two command-line scripts below are also available
unchanged in commit `e496429` on `Web-model`; they do not require a web server.
Their preprocessing and RF definition use `host/replay_detect.py` and
`host/revised_experiments.py` from `98b9e43`.

Use a separate environment with **Python 3.12.14**, then run from the repository
root (use a new, empty output directory for each export):

```bash
python -m pip install -r model_web/requirements_experiment.txt
python model_web/export_updated_rf.py --combined --out model_web/exports/pooled
# Optional comparison: separate RF models for each OS, with the same holdout.
python model_web/export_updated_rf.py --out model_web/exports/per_os
```

Inputs are the already versioned `data/FINAL_DATASET_fixed.csv.gz`, 24 compressed
CSVs in `data/repeat/`, and 12 compressed CSVs in `data/machine2/`. An uncompressed
`FINAL_DATASET_fixed.csv` is not needed. All 480,888 events cover 48 runs. After
aggregation and harness filtering, machine 1 supplies 61,191 training processes
(36 runs); machine 2 supplies 23,413 test processes (12 runs). No run or lineage
appears in both splits.

Features use `prefix_features(behavior=True, ages=[np.inf])`, then remove harness
processes. The 53 features include `cmd_len` and `pcmd_len`; platform, run ID and
label are not model inputs. One RF is trained on both OSes with seed 0, without
scaling/PCA or test-set threshold tuning. The default `predict` decision is used.

| Held-out data | Processes | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|
| Both OSes pooled | 23,413 | 0.982 | 0.970 | 0.970 | 0.970 | 0.013 | 0.993 |
| Linux | 14,566 | 0.982 | 0.981 | 0.947 | 0.964 | 0.006 | 0.988 |
| Windows | 8,847 | 0.981 | 0.959 | 0.994 | 0.976 | 0.028 | 0.999 |

The separate-OS comparison gives F1 0.956 on Linux and 0.955 on Windows. These
are one machine holdout, not repeated-CV means. Machine-2 results had already
been used in repository method development, so this is not a fully blind test.
It also does not establish unseen-OS transfer, unseen attacks, real-malware
detection, or removal of command-length shortcuts. Do not compare these scores
directly with the primary 32-feature tables, whose data and preprocessing differ.

Outputs include `sysmon_rf_combined.pkl`, `test_combined_features.csv`,
`combined_metrics.json` (overall and per-OS scores), expected predictions,
input hashes, run/split manifests, copied preprocessing code, and exact runtime
versions. The exporter reloads its own saved model and CSV and checks predictions
and probabilities against the in-memory results. Generated files remain local
under ignored `model_web/exports/`; they are not committed.

To convert another CSV in the project's event schema with `platform` and `run_id`:

```bash
python model_web/prepare_behavior_csv.py --csv path/to/events.csv --os both --out path/to/features.csv
```

The resulting CSV has 53 feature columns plus metadata, and a label column only
when supplied in the input. Use independent runs for evaluation; reusing the
training events is not an independent accuracy test.

# Dataset schema — Sysmon cross-platform dataset (NCCY 2026, revised v6)

This file describes the data behind every number in the manuscript, so a reviewer can
check 81,331 events, 23,971 process samples, the labels, features, splits and metrics.

## 1. Files

| File | Content |
|---|---|
| `host/dataset/merged_dataset.csv` | Main event-level dataset: 81,331 events, 80 columns, 12 runs |
| `host/dataset/ransomware_dash_213312_20260825_213312_labeled.csv` | Independent Linux run (P4 test only): 3,101 events |
| `host/dataset/trojan_dash_211024_20260825_211024_labeled.csv` | Independent Linux run (P4 test only): 3,884 events |
| `host/revised_experiments.py` | Aggregation, lineage groups, protocols P1–P4, all metrics |
| `reference/revised_results/*.csv` | Per-fold results for every model and protocol |
| `reference/revised_results/numbers.json` | The formatted values printed in the manuscript |
| `provision/sysmon-config.xml`, `provision/windows/sysmon-config-win.xml` | Sysmon configurations (schema 4.81 / 4.90) |
| `scenarios/*.sh`, `scenarios_win/*.ps1` (Git HEAD) | Scenario scripts with Atomic Red Team technique and test numbers |

## 2. Event-level columns (merged_dataset.csv)

Sysmon fields are kept with their Sysmon names (`EventID`, `UtcTime`, `ProcessGuid`, `ProcessId`,
`Image`, `CommandLine`, `ParentProcessGuid`, `ParentImage`, `ParentCommandLine`, `TargetFilename`,
`DestinationIp`, `DestinationPort`, `TargetObject`, `Device`, …). Columns added by the pipeline:

| Column | Type | Meaning |
|---|---|---|
| `platform` | `linux` / `windows` | Operating system of the target VM |
| `computer` | string | Sysmon host name (`target1`, `DESKTOP-UO8S3RE`) |
| `session` | string | Scenario name (`benign`, `ransomware`, `ransomware_win`, …) — **not unique per run** |
| `run_id` | string | Unique id of one collection run (one snapshot revert + one scenario execution) |
| `label` | 0 / 1 | 1 = event of a seed process or one of its descendants in an attack run |
| `label_method` | `lineage` / `session` | `lineage` for attack runs (62,035 events), `session` for benign runs (19,296) |
| `is_seed` | 0 / 1 / empty | 1 = process matched the seed rule (sandbox directory or command) |
| `enriched`, `enrich_method`, `parent_known` | | Whether parent/command-line information was filled from other events |
| `ancestor_depth`, `root_image` | | Lineage bookkeeping — **never used as features** |
| `recv_timestamp`, `record_id`, `host_ip` | | Collection bookkeeping — never used as features |

## 3. Process-level samples (built by `aggregate()` in revised_experiments.py)

* Key: `platform | run_id | ProcessGuid`. Events with empty `ProcessGuid` (8) or the all-zero
  GUID `{00000000-0000-0000-0000-000000000000}` (612) are dropped → 80,711 events used.
* One row per key → **23,971 processes** (label 1: 8,011; label 0: 15,960).
* Sample label = max of its event labels.
* Lineage group: follow `ParentProcessGuid` upward inside the same run until the parent is not
  observed; the top-most observed ancestor is the group id → **5,072 groups**. Used only for splitting.

### 32 features

| Group | Features |
|---|---|
| Volume | `n_events` |
| Event mix | `ev_<id>` and `frac_<id>` for EventID 1, 2, 3, 4, 5, 8, 9, 11, 12, 13, 23 (22 columns) |
| Distinct values | `n_files`, `n_dst_ip`, `n_dst_port`, `n_regobj`, `n_device` |
| Time | `dur_s` (last − first event, s), `rate` (= n_events / max(dur_s, 1)) |
| Command | `cmd_len`, `pcmd_len` (length of first CommandLine / ParentCommandLine) |

Missing values → 0. Removed from the draft's 35: `img_len`, `depth`, `enriched`.

## 4. Protocols

| Id | Train | Test | Folds |
|---|---|---|---|
| P1 | 4/5 of lineage groups (StratifiedGroupKFold, seeds 0–4) | remaining groups | 25 |
| P2 | all runs except one attack run | the whole held-out run (attack + its background benign) | 10 |
| P3 | all runs except both runs of one scenario | both held-out runs | 5 |
| P4 | the 12 main runs | the 2 independent Linux runs | 1 (+ per run) |

Inside every fold: StandardScaler fit on train; anomaly detectors fit on benign train only
(80 % of benign lineage groups) and thresholded at the 95th percentile of scores on the other
20 % (target FPR 5 %). No malicious label is used by the anomaly detectors.

## 5. Reproduce

```bash
pip install pandas scikit-learn==1.8.0
python host/revised_experiments.py            # writes reference/revised_results/  (~6 min on 2 cores)
python docs/figures_src/collect_numbers.py    # numbers.json used in the manuscript
```

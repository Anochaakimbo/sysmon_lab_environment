"""build_dataset50.py - every labelled run in data/ as one CSV: the paper's 12 runs (FINAL_DATASET_fixed),
the 2 new Linux runs (data/new_runs), the 24 repetitions (data/repeat) and the 12 second-machine runs
(data/machine2). 50 runs, 4 machines. Adds `machine` (1 = Ubuntu 22.04 / Windows 10, 2 = Ubuntu 24.04 / Windows 11)
and `part` (where the run came from). The paper's tables still use FINAL_DATASET_fixed.

usage: python host/build_dataset50.py [--out data/FINAL_DATASET_50runs.csv.gz]
"""
import argparse, glob, os
import pandas as pd

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PARTS = [("new_runs", "data/new_runs/*_labeled.csv", 1), ("repeat", "data/repeat/*_labeled.csv.gz", 1),
         ("machine2", "data/machine2/*_labeled.csv.gz", 2)]


def build():
    d = pd.read_csv(os.path.join(ROOT, "data", "FINAL_DATASET_fixed.csv.gz"), low_memory=False)
    d["machine"], d["part"] = 1, "paper"
    frames = [d]
    for part, pattern, machine in PARTS:
        for f in sorted(glob.glob(os.path.join(ROOT, pattern))):
            e = pd.read_csv(f, low_memory=False)
            e["run_id"] = os.path.basename(f).split("_labeled.csv")[0]
            e["machine"], e["part"] = machine, part
            frames.append(e[list(d.columns)])
    out = pd.concat(frames, ignore_index=True)
    assert out.run_id.nunique() == 50, out.run_id.nunique()
    assert out.groupby("run_id").platform.nunique().max() == 1
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "FINAL_DATASET_50runs.csv.gz"))
    a = ap.parse_args()
    d = build()
    print(d.groupby(["part", "platform", "machine"]).agg(runs=("run_id", "nunique"), events=("label", "size"),
                                                         label1=("label", "mean")).round(3).to_string())
    print("total", d.run_id.nunique(), "runs", len(d), "events")
    d.to_csv(a.out, index=False)
    print("->", a.out)

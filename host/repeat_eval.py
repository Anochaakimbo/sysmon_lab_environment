# -*- coding: utf-8 -*-
"""
repeat_eval.py - leave-one-repetition-out on machine 1 (NCCY review group C: repeated runs).

Repetition 0 = the paper run of each scenario (machine 1 rows of machine_eval.load, Windows relabeled).
Repetitions 1, 2 = collected 12 Oct 2026 on the same VMs, snapshot revert before each run
(data/repeat/*_labeled.csv.gz). Per OS: train on two repetitions, test on the third, all three ways.
Detectors and thresholds as in cross_platform_eval.run_fold (thresholds from training repetitions only).

usage: python host/repeat_eval.py [--final ../FINAL_DATASET.csv]
"""
import argparse, glob, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import numpy as np
import pandas as pd
import replay_detect as rd
from cross_platform_eval import NEUTRAL, run_fold, tactic_counts
import machine_eval

OUT = os.path.join(os.path.dirname(_HERE), "reference", "repeat_eval")
DATA = os.path.join(os.path.dirname(_HERE), "data", "repeat")


def load(final):
    d = machine_eval.load(final)
    d = d[d.machine == 1].copy()
    d["rep"] = 0
    extra = []
    for f in sorted(glob.glob(os.path.join(DATA, "*_labeled.csv.gz"))):
        e = pd.read_csv(f, low_memory=False)
        e["run_id"] = os.path.basename(f)[:-len("_labeled.csv.gz")]
        extra.append(e)
    new = pd.concat(extra, ignore_index=True)
    # repetition = order of collection within (platform, session); run_id ends with the start time
    order = new.drop_duplicates("run_id")[["run_id", "platform", "session"]].copy()
    order["t"] = order.run_id.str[-15:]
    order["rep"] = order.sort_values("t").groupby(["platform", "session"]).cumcount() + 1
    new = new.merge(order[["run_id", "rep"]], on="run_id")
    new["machine"] = 1
    raw = pd.concat([d, new], ignore_index=True)
    n = raw.drop_duplicates("run_id").groupby(["platform", "session"]).rep.apply(sorted)
    assert all(r == [0, 1, 2] for r in n), n
    print(raw.groupby(["platform", "rep"]).agg(runs=("run_id", "nunique"), rows=("label", "size"),
                                               mal=("label", "mean")).round(3).to_string())
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--final", default=os.path.join(os.path.dirname(_HERE), "FINAL_DATASET.csv"))
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    raw = load(a.final)
    rep_of = raw.drop_duplicates("run_id").set_index("run_id").rep
    rows = []
    for fset, nh, beh in (("paper", False, False), ("clean", True, True), ("semantic", True, True)):
        feats, meta = rd.load_features(raw, no_harness=nh, behavior=beh)
        F = feats[np.inf]
        if fset == "semantic":
            F = pd.concat([F[NEUTRAL], tactic_counts(raw, F.index)], axis=1)
        X, y, run, plat = F.values, meta.label.values, meta.run.values, meta.platform.values
        rep = rep_of.reindex(run).values
        assert not pd.isna(rep).any(), "run without repetition"
        for p in ("linux", "windows"):
            for k in (0, 1, 2):
                rows += run_fold(X, y, run, np.where((plat == p) & (rep != k))[0],
                                 np.where((plat == p) & (rep == k))[0], dict(features=fset, platform=p, test_rep=k))
            print("  %s %s done" % (fset, p), flush=True)
    d = pd.DataFrame(rows)
    d.to_csv(os.path.join(OUT, "repeat_folds.csv"), index=False)
    g = d.groupby(["features", "platform", "detector"])[["recall", "fpr", "f1", "auc"]]
    s = g.mean().round(3).join(g.std().round(3), rsuffix="_std")
    s.to_csv(os.path.join(OUT, "repeat_summary.csv"))
    pd.set_option("display.width", 250)
    print(s.to_string())
    print("->", OUT)


if __name__ == "__main__":
    main()

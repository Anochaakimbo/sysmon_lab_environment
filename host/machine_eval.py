# -*- coding: utf-8 -*-
"""
machine_eval.py - leave-one-machine-out (NCCY review group C: more machines / OS versions).

Machine 1 = the paper dataset (FINAL_DATASET.csv): Ubuntu 22.04 target1, Windows 10 wintarget.
Machine 2 = collected after the review with the same scenarios: Ubuntu 24.04 target2,
            Windows 11 wintarget2 (data/machine2/*_labeled.csv.gz, listed in M2_RUNS).
Per OS: train on one machine, test on the other (both directions), plus a same-machine
reference (lineage-grouped 5-fold CV). Detectors and thresholds as in cross_platform_eval.run_fold
(thresholds from the training machine only).

usage: python host/machine_eval.py [--final ../FINAL_DATASET.csv]
"""
import argparse, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
import replay_detect as rd
from cross_platform_eval import NEUTRAL, run_fold, tactic_counts

OUT = os.path.join(os.path.dirname(_HERE), "reference", "machine_eval")
DATA = os.path.join(os.path.dirname(_HERE), "data", "machine2")
M2_RUNS = ["benign_target2_214347_20261011_214347", "ransomware_target2_215549_20261011_215549",
           "miner_target2_220721_20261011_220721", "exploit_target2_222003_20261011_222003",
           "botnet_target2_223155_20261011_223155", "trojan_target2_224548_20261011_224548",
           "benign_183520_20261011_114718", "ransomware_win_184757_20261011_115952",
           "miner_win_190031_20261011_124209", "botnet_win_194231_20261011_132414",
           "trojan_win_202437_20261011_133658", "exploit_win_203717_20261011_135538"]


def load(final):
    d = pd.read_csv(final, low_memory=False)
    d["machine"] = 1
    extra = []
    for r in M2_RUNS:
        e = pd.read_csv(os.path.join(DATA, r + "_labeled.csv.gz"), low_memory=False)
        e["run_id"], e["machine"] = r, 2
        extra.append(e)
    raw = pd.concat([d] + extra, ignore_index=True)
    assert raw.groupby("run_id").platform.nunique().max() == 1
    print(raw.groupby(["platform", "machine", "computer"]).agg(runs=("run_id", "nunique"), rows=("label", "size"),
                                                               mal=("label", "mean")).round(3).to_string())
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--final", default=os.path.join(os.path.dirname(_HERE), "FINAL_DATASET.csv"))
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    raw = load(a.final)
    machine_of = raw.drop_duplicates("run_id").set_index("run_id").machine
    rows = []
    for fset, nh, beh in (("paper", False, False), ("clean", True, True), ("semantic", True, True)):
        feats, meta = rd.load_features(raw, no_harness=nh, behavior=beh)
        F = feats[np.inf]
        if fset == "semantic":
            F = pd.concat([F[NEUTRAL], tactic_counts(raw, F.index)], axis=1)
        X, y, run, plat, grp = (F.values, meta.label.values, meta.run.values,
                                meta.platform.values, meta.lineage.values)
        mach = machine_of.reindex(run).values
        assert not pd.isna(mach).any(), "run without machine"
        for p in ("linux", "windows"):
            for src, dst in ((1, 2), (2, 1)):
                rows += run_fold(X, y, run, np.where((plat == p) & (mach == src))[0],
                                 np.where((plat == p) & (mach == dst))[0],
                                 dict(features=fset, platform=p, train=src, test=dst, fold=0))
            for m in (1, 2):                  # same-machine reference
                idx = np.where((plat == p) & (mach == m))[0]
                for f, (tr, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=0).split(idx, y[idx], grp[idx])):
                    rows += run_fold(X, y, run, idx[tr], idx[te], dict(features=fset, platform=p, train=m, test=m, fold=f))
            print("  %s %s done" % (fset, p), flush=True)
    d = pd.DataFrame(rows)
    d.to_csv(os.path.join(OUT, "machine_folds.csv"), index=False)
    s = d.groupby(["features", "platform", "train", "test", "detector"])[["recall", "fpr", "f1", "auc"]].mean().round(3)
    s.to_csv(os.path.join(OUT, "machine_summary.csv"))
    pd.set_option("display.width", 250)
    print(s.to_string())
    print("->", OUT)


if __name__ == "__main__":
    main()

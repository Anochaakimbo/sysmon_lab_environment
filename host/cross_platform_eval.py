# -*- coding: utf-8 -*-
"""
cross_platform_eval.py - train on one OS, test on the other (reviewer C007, advisor's suggestion).

Does what a model learns from Linux Sysmon transfer to Windows Sysmon, and back?
Process level, whole process (age inf), two feature sets:
  paper  : the 32 paper features, lab harness kept (as in the submitted paper)
  clean  : harness dropped + 21 b_* behaviour features + launcher unwrap (replay_detect.py)
Directions: linux->windows, windows->linux, plus same-OS references (lineage-grouped 5-fold CV).
Detectors (thresholds from the SOURCE OS only, target labels never used to tune):
  rf@0.5, rf@fpr5 (95th pct of out-of-fold scores of source benign), lof (fit on source benign)
Baseline: all-positive F1 on the target. AUC is threshold-free -> the fairest transfer number.

usage: python host/cross_platform_eval.py [--merged merged_dataset_v2.csv]
"""
import argparse, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, StratifiedGroupKFold
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import revised_experiments as rx
import replay_detect as rd
from zeroday_eval import q

OUT = os.path.join(os.path.dirname(_HERE), "reference", "cross_platform")
RF = lambda: dict(rx.supervised())["Random Forest"]


def run_fold(X, y, run, tr, te, tag):
    rf = RF().fit(X[tr], y[tr])
    oof = np.zeros(len(tr))
    for a, b in GroupKFold(5).split(X[tr], y[tr], run[tr]):
        oof[b] = RF().fit(X[tr][a], y[tr][a]).predict_proba(X[tr][b])[:, 1]
    thr = q(oof[y[tr] == 0])
    ben = tr[y[tr] == 0]
    fi, ci = next(GroupShuffleSplit(1, test_size=0.2, random_state=rx.SEED).split(ben, groups=run[ben]))
    sc = StandardScaler().fit(X[ben[fi]])
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(sc.transform(X[ben[fi]]))
    thr_lof = q(-lof.score_samples(sc.transform(X[ben[ci]])))
    p = rf.predict_proba(X[te])[:, 1]
    s_lof = -lof.score_samples(sc.transform(X[te]))
    yt = y[te]
    rows = []
    for name, flag, score in (("rf@0.5", p >= 0.5, p), ("rf@fpr5", p >= thr, p), ("lof", s_lof > thr_lof, s_lof),
                              ("all-positive", np.ones_like(yt, bool), None)):
        rows.append(dict(tag, detector=name, n_test=len(te), mal_share=yt.mean(),
                         recall=flag[yt == 1].mean(), fpr=flag[yt == 0].mean(), f1=f1_score(yt, flag),
                         auc=roc_auc_score(yt, score) if score is not None else np.nan))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--merged", default="merged_dataset_v2.csv")
    a = ap.parse_args()
    rx.MERGED = a.merged
    os.makedirs(OUT, exist_ok=True)
    raw, _ = rx.load()
    rows = []
    for fset, nh, beh in (("paper", False, False), ("clean", True, True)):
        feats, meta = rd.load_features(raw, no_harness=nh, behavior=beh)
        X, y, run, plat, grp = (feats[np.inf].values, meta.label.values, meta.run.values,
                                meta.platform.values, meta.lineage.values)
        for src, dst in (("linux", "windows"), ("windows", "linux")):
            rows += run_fold(X, y, run, np.where(plat == src)[0], np.where(plat == dst)[0],
                             dict(features=fset, train=src, test=dst, fold=0))
            print("  %s %s -> %s" % (fset, src, dst), flush=True)
        for p in ("linux", "windows"):        # same-OS reference
            idx = np.where(plat == p)[0]
            for f, (tr, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=0).split(idx, y[idx], grp[idx])):
                rows += run_fold(X, y, run, idx[tr], idx[te], dict(features=fset, train=p, test=p, fold=f))
            print("  %s %s -> %s (5-fold)" % (fset, p, p), flush=True)
    d = pd.DataFrame(rows)
    d.to_csv(os.path.join(OUT, "cross_platform_folds.csv"), index=False)
    s = d.groupby(["features", "train", "test", "detector"])[["recall", "fpr", "f1", "auc"]].mean().round(3)
    s.to_csv(os.path.join(OUT, "cross_platform_summary.csv"))
    pd.set_option("display.width", 250)
    print(s.to_string())
    print("->", OUT)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""
label_sensitivity.py - how much do the lineage breaks found by label_audit.py
change the results? (reviewer comment C001)

Takes reference/label_audit/candidates_possible_fn.csv (label=0 processes inside
attack runs with attack-specific evidence), flips them to label=1, and re-runs
P1 (lineage CV, 5x5) and P2 (leave-one-run-out) with the original and the
flipped labels on the SAME folds (folds are built from the original labels).

Uses revised_experiments.py as-is (same features, models, scalers, thresholds).
SVM / One-Class SVM are skipped (FAST=1) to keep the runtime short.

usage: python host/label_sensitivity.py
"""
import os, sys
os.environ["FAST"] = "1"
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
OUT = os.path.join(_ROOT, "reference", "label_audit")
sys.path.insert(0, _HERE)
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
import revised_experiments as rx


def main():
    raw, _ = rx.load()
    f, meta, _ = rx.aggregate(raw, "composite")
    X, y0 = f.values, meta.label.values
    cand = pd.read_csv(os.path.join(OUT, "candidates_possible_fn.csv"))
    flip = meta.index.isin(cand["_k"])
    y1 = y0.copy()
    y1[flip] = 1
    print("flipped %d of %d candidates (rest are in P4 runs, not in the main dataset)" % (flip.sum(), len(cand)))
    groups = meta.lineage.values
    plat = meta.platform.values

    rows = []
    for rep in range(5):
        skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=rep)
        for fo, (tr, te) in enumerate(skf.split(X, y0, groups)):
            for name, y in (("original", y0), ("flipped", y1)):
                rows += rx.evaluate(X, y, groups, tr, te, dict(Protocol="P1", Labels=name, Repeat=rep, Fold=fo), plat=plat)
        print("  P1 repeat %d" % rep, flush=True)
    for run in sorted(meta.run.unique()):
        if meta.session[meta.run == run].iloc[0].startswith("benign"):
            continue
        te, tr = np.where(meta.run.values == run)[0], np.where(meta.run.values != run)[0]
        for name, y in (("original", y0), ("flipped", y1)):
            rows += rx.evaluate(X, y, groups, tr, te, dict(Protocol="P2", Labels=name, HeldOut=run), plat=plat)
    d = pd.DataFrame(rows)
    d.to_csv(os.path.join(OUT, "sensitivity_folds.csv"), index=False)

    s = (d.groupby(["Protocol", "Platform", "Model", "Labels"])[["F1", "FPR", "AUC"]]
           .agg(["mean", "std"]).round(3))
    s.columns = ["%s_%s" % c for c in s.columns]
    s = s.reset_index()
    s.to_csv(os.path.join(OUT, "sensitivity_summary.csv"), index=False)
    w = s.pivot_table(index=["Protocol", "Platform", "Model"], columns="Labels", values=["F1_mean", "AUC_mean"])
    w[("F1_delta", "")] = w[("F1_mean", "flipped")] - w[("F1_mean", "original")]
    w[("AUC_delta", "")] = w[("AUC_mean", "flipped")] - w[("AUC_mean", "original")]
    print(w.round(3).to_string())
    print("->", os.path.join(OUT, "sensitivity_summary.csv"))


if __name__ == "__main__":
    main()

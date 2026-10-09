# -*- coding: utf-8 -*-
"""
zeroday_eval.py - can a never-seen attack type be caught, per OS? (process level)

Same data as replay_detect.py --no-harness --behavior (merged_dataset_v2, 32 paper + 21 b_* features,
whole process). Folds:
  ZD   leave one attack scenario out (both OS at once) -> the held-out type was never seen
  BEN  leave one benign run out                         -> false positives on unseen clean activity
Detectors, every threshold chosen from training data only:
  rf@0.5       Random Forest, fixed 0.5
  rf@fpr5      Random Forest, per-OS threshold = 95th pct of out-of-fold scores of that OS's
               benign training processes (GroupKFold by run) -> target FPR 5%
  lof          Local Outlier Factor per OS, fit on that OS's benign training processes only,
               own scaler, threshold = 95th pct on a held-out benign calibration split (by run)
  rf|lof       alert if either fires
Output: reference/zeroday/zeroday_folds.csv + summary printed.

usage: python host/zeroday_eval.py [--merged merged_dataset_v2.csv]
"""
import argparse, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import revised_experiments as rx
import replay_detect as rd

OUT = os.path.join(os.path.dirname(_HERE), "reference", "zeroday")
FPR = 0.05


def q(scores, fpr=FPR):
    """threshold so that a share `fpr` of these (benign) scores is above it."""
    return float(np.quantile(scores, 1 - fpr))


def fit_fold(X, y, plat, run, tr):
    rf = dict(rx.supervised())["Random Forest"].fit(X[tr], y[tr])
    # out-of-fold RF scores on the training set, grouped by run, for the per-OS threshold
    oof = np.zeros(len(tr))
    for a, b in GroupKFold(5).split(X[tr], y[tr], run[tr]):
        oof[b] = dict(rx.supervised())["Random Forest"].fit(X[tr][a], y[tr][a]).predict_proba(X[tr][b])[:, 1]
    det = {}
    for p in np.unique(plat):
        ben = tr[(plat[tr] == p) & (y[tr] == 0)]
        thr_rf = q(oof[(plat[tr] == p) & (y[tr] == 0)])
        fi, ci = next(GroupShuffleSplit(1, test_size=0.2, random_state=rx.SEED).split(ben, groups=run[ben]))
        sc = StandardScaler().fit(X[ben[fi]])
        lof = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(sc.transform(X[ben[fi]]))
        s_cal = -lof.score_samples(sc.transform(X[ben[ci]]))
        det[p] = dict(thr_rf=thr_rf, lof=lof, sc=sc, thr_lof=q(s_cal))
        # calibration really targets FPR 5% (quantile interpolation can overshoot by one sample)
        assert (s_cal > det[p]["thr_lof"]).mean() <= FPR + 1.0 / len(s_cal), (p, len(s_cal))
    return rf, det


def evaluate(X, y, plat, rf, det, te, tag):
    rows = []
    p_rf = rf.predict_proba(X[te])[:, 1]
    for p in np.unique(plat[te]):
        k = plat[te] == p
        d = det[p]
        s_lof = -d["lof"].score_samples(d["sc"].transform(X[te][k]))
        yt = y[te][k]
        flags = {"rf@0.5": p_rf[k] >= 0.5, "rf@fpr5": p_rf[k] >= d["thr_rf"],
                 "lof": s_lof > d["thr_lof"]}
        flags["rf|lof"] = flags["rf@fpr5"] | flags["lof"]
        score = {"rf@0.5": p_rf[k], "rf@fpr5": p_rf[k], "lof": s_lof, "rf|lof": None}
        for m, f in flags.items():
            rows.append(dict(tag, platform=p, detector=m, n=int(k.sum()), n_mal=int(yt.sum()),
                             recall=f[yt == 1].mean() if yt.any() else np.nan,
                             fpr=f[yt == 0].mean() if (yt == 0).any() else np.nan,
                             f1=f1_score(yt, f, zero_division=0) if yt.any() else np.nan,
                             auc=roc_auc_score(yt, score[m]) if score[m] is not None and 0 < yt.mean() < 1 else np.nan,
                             thr=d["thr_rf"] if m == "rf@fpr5" else (d["thr_lof"] if m == "lof" else np.nan)))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--merged", default="merged_dataset_v2.csv")
    a = ap.parse_args()
    rx.MERGED = a.merged
    os.makedirs(OUT, exist_ok=True)
    raw, _ = rx.load()
    feats, meta = rd.load_features(raw, no_harness=True, behavior=True)
    X = feats[np.inf].values
    y, plat, run, sc = meta.label.values, meta.platform.values, meta.run.values, meta.scenario.values
    rows = []
    folds = [("ZD", s, sc == s) for s in sorted(set(sc)) if not s.startswith("benign")]
    folds += [("BEN", r, run == r) for r in sorted(set(run[pd.Series(sc).str.startswith("benign").values]))]
    for proto, held, mask in folds:
        tr, te = np.where(~mask)[0], np.where(mask)[0]
        rf, det = fit_fold(X, y, plat, run, tr)
        rows += evaluate(X, y, plat, rf, det, te, dict(protocol=proto, held_out=held))
        print("  %s %s" % (proto, held), flush=True)
    d = pd.DataFrame(rows)
    d.to_csv(os.path.join(OUT, "zeroday_folds.csv"), index=False)
    pd.set_option("display.width", 250)
    zd = d[d.protocol == "ZD"]
    print("\nunseen attack type - mean over held-out scenarios:")
    print(zd.groupby(["platform", "detector"])[["recall", "fpr", "f1", "auc"]].mean().round(3).to_string())
    print("\nfalse-positive rate on unseen benign runs:")
    print(d[d.protocol == "BEN"].groupby(["platform", "detector"]).fpr.mean().round(3).unstack().to_string())
    print("\nrecall per held-out scenario (linux):")
    print(zd[zd.platform == "linux"].pivot_table(index="held_out", columns="detector", values="recall").round(3).to_string())
    print("->", OUT)


if __name__ == "__main__":
    main()

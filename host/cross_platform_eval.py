# -*- coding: utf-8 -*-
"""
cross_platform_eval.py - train on one OS, test on the other (reviewer C007, advisor's suggestion).

Does what a model learns from Linux Sysmon transfer to Windows Sysmon, and back?
Process level, whole process (age inf), two feature sets:
  paper    : the 32 paper features, lab harness kept (as in the submitted paper)
  clean    : harness dropped + 21 b_* behaviour features + launcher unwrap (replay_detect.py)
  semantic : clean, minus everything tied to one OS (command length/entropy, event types only one
             Sysmon has, /dev/tcp), plus per-process counts of ATT&CK *tactics* from the evidence
             regexes - an OS-neutral description of behaviour, to test whether transfer is possible
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
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import revised_experiments as rx
import replay_detect as rd
from zeroday_eval import q
from compare_nlme import classify

OUT = os.path.join(os.path.dirname(_HERE), "reference", "cross_platform")
RF = lambda: dict(rx.supervised())["Random Forest"]

TACTIC = {"T1005": "collection", "T1074": "collection", "T1016": "discovery", "T1033": "discovery",
          "T1057": "discovery", "T1082": "discovery", "T1083": "discovery", "T1087": "discovery",
          "T1027": "defense_evasion", "T1036": "defense_evasion", "T1070": "defense_evasion",
          "T1112": "defense_evasion", "T1222": "defense_evasion", "T1053": "persistence",
          "T1543": "persistence", "T1546": "persistence", "T1547": "persistence",
          "T1059": "execution", "T1105": "command_and_control", "T1548": "privilege_escalation",
          "T1552": "credential_access", "T1496": "impact"}
# kept from the clean set: behaviour that exists the same way on both OS
NEUTRAL = ["n_events", "dur_s", "rate", "ev_1", "ev_3", "ev_5", "ev_11", "ev_23", "n_files", "n_dst_ip",
           "n_dst_port", "b_sensitive", "b_fname_ent_mean", "b_fname_ent_max", "b_n_ext", "b_ext_conn",
           "b_create_then_delete", "b_children", "b_pipes", "b_redirects", "b_url", "b_ip_literal", "b_b64",
           "b_exec_writable", "b_sib_spawned", "b_sib_same_image", "b_sib_images", "b_sib_period_cv",
           "b_sib_period_s"]


def tactic_counts(raw, index):
    """per process: how many events carry DIRECT evidence of each ATT&CK tactic."""
    df = raw[raw.ProcessGuid.notna() & (raw.ProcessGuid != rx.NULL_GUID)]
    key = (df.platform + "|" + df.run_id + "|" + df.ProcessGuid).values
    cols = ["Image", "CommandLine", "ParentCommandLine", "TargetFilename", "TargetObject"]
    tac = []
    for r in df[cols].fillna("").astype(str).to_dict("records"):
        h = classify(r)
        tac.append(TACTIC.get(h[1][:5], "other") if h and h[0] == "DIRECT" else None)
    t = pd.DataFrame(dict(k=key, t=tac)).dropna()
    c = pd.crosstab(t.k, t.t).add_prefix("t_")
    return c.reindex(index).fillna(0)


def proba(m, X):
    """P(malicious); a model that only saw one class still answers (0 or 1)."""
    p = m.predict_proba(X)
    return p[:, list(m.classes_).index(1)] if 1 in m.classes_ else np.zeros(len(X))


def run_fold(X, y, run, tr, te, tag):
    rf = RF().fit(X[tr], y[tr])
    # out-of-fold by run; stratified so every training split keeps both classes
    # (the matched dataset has only 3 attack + 3 benign runs per OS)
    oof = np.zeros(len(tr))
    k = min(5, len(set(run[tr][y[tr] == 1])), len(set(run[tr][y[tr] == 0])))
    for a, b in StratifiedGroupKFold(max(k, 2), shuffle=True, random_state=0).split(X[tr], y[tr], run[tr]):
        oof[b] = proba(RF().fit(X[tr][a], y[tr][a]), X[tr][b])
    thr = q(oof[y[tr] == 0])
    ben = tr[y[tr] == 0]
    fi, ci = next(GroupShuffleSplit(1, test_size=0.2, random_state=rx.SEED).split(ben, groups=run[ben]))
    sc = StandardScaler().fit(X[ben[fi]])
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(sc.transform(X[ben[fi]]))
    thr_lof = q(-lof.score_samples(sc.transform(X[ben[ci]])))
    p = proba(rf, X[te])
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
    for fset, nh, beh in (("paper", False, False), ("clean", True, True), ("semantic", True, True)):
        feats, meta = rd.load_features(raw, no_harness=nh, behavior=beh)
        F = feats[np.inf]
        if fset == "semantic":
            F = pd.concat([F[NEUTRAL], tactic_counts(raw, F.index)], axis=1)
            print("  semantic: %d features (%s)" % (F.shape[1], ", ".join(c for c in F.columns if c.startswith("t_"))))
        X, y, run, plat, grp = (F.values, meta.label.values, meta.run.values,
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

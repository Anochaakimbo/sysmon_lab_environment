# Derived from revised_experiments.py; OS reporting does not change training.
# Scaler is intentionally fitted on all outer training samples, as in the source.
# -*- coding: utf-8 -*-
"""
revised_experiments.py - re-run the NCCY paper experiments with the revised protocol.

Changes relative to host/ml_train.py (reviewer items C001-C003, step 4, step 6):
  * process samples keyed by a composite key (platform, run_id, ProcessGuid);
    all-zero / missing ProcessGuid events are excluded (they are not a process id)
  * lineage group = top-most observed ancestor of a process inside the same run;
    all processes of one lineage tree always fall in the same fold
  * P1 lineage-grouped stratified 5-fold CV x 5 repeats  -> mean +/- SD
    P2 leave-one-attack-run-out (10 folds), test = the whole held-out run
       (its attack lineages + its own background benign processes)
    P3 leave-one-scenario-out across both OSes (5 folds)
    P4 independent-run test: train on the 12 original runs, test on the
       2 Linux runs collected on a later day (ransomware, trojan)
  * anomaly detectors are trained on benign training processes only, and the
    alarm threshold is the 95th percentile of scores on a held-out *benign-only*
    validation subset (target FPR 5%); no malicious label is used anywhere
  * key-impact experiment: ProcessGuid-only vs composite key under the same
    single process split used in the original draft and under P1
Outputs: results/*.csv and results/summary.json
"""
import json, os, sys, time, warnings
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")
SEED = 0
_HERE = os.path.dirname(os.path.abspath(__file__))
NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
EXTRA_RUNS = ["ransomware_dash_213312_20260825_213312", "trojan_dash_211024_20260825_211024"]
EVENT_IDS = [1, 2, 3, 4, 5, 8, 9, 11, 12, 13, 23]
TARGET_FPR = 0.05
SVM_MAX = 8000
FAST = False
PREDICTION_FILE = None


# ----------------------------------------------------------------- data

def aggregate(df, key="composite"):
    """32 process-level features (img_len, depth, enriched removed as in the draft)."""
    raw_n = len(df)
    if key == "composite":
        df = df[df.ProcessGuid.notna() & (df.ProcessGuid != NULL_GUID)].copy()
        df["_k"] = df.platform + "|" + df.run_id + "|" + df.ProcessGuid
        pg = df.ParentProcessGuid.astype("string")
        ok = pg.notna() & (pg != NULL_GUID)
        df["_pk"] = np.where(ok, df.platform + "|" + df.run_id + "|" + pg.fillna(""), None)
    else:  # the draft's aggregation: ProcessGuid only
        df = df[df.ProcessGuid.notna()].copy()
        df["_k"] = df.ProcessGuid
        df["_pk"] = df.ParentProcessGuid
    dropped = raw_n - len(df)
    df["_ts"] = pd.to_datetime(df.UtcTime, errors="coerce")
    g = df.groupby("_k", sort=True)
    f = pd.DataFrame(index=g.size().index)
    f["n_events"] = g.size()
    cnt = df.pivot_table(index="_k", columns="EventID", values="_ts",
                         aggfunc="size").reindex(f.index).fillna(0)
    for e in EVENT_IDS:
        f["ev_%d" % e] = cnt[e] if e in cnt.columns else 0.0
        f["frac_%d" % e] = f["ev_%d" % e] / f["n_events"]
    f["n_files"] = g.TargetFilename.nunique()
    f["n_dst_ip"] = g.DestinationIp.nunique()
    f["n_dst_port"] = g.DestinationPort.nunique()
    f["n_regobj"] = g.TargetObject.nunique()
    f["n_device"] = g.Device.nunique()
    f["dur_s"] = (g._ts.max() - g._ts.min()).dt.total_seconds()
    f["rate"] = f.n_events / f.dur_s.fillna(0).clip(lower=1)
    f["cmd_len"] = g.CommandLine.first().astype(str).str.len()
    f["pcmd_len"] = g.ParentCommandLine.first().astype(str).str.len()
    f = f.fillna(0).replace([np.inf, -np.inf], 0).astype(float)

    m = pd.DataFrame(index=f.index)
    m["label"] = g.label.max().astype(int)
    m["run"] = g.run_id.first()
    m["platform"] = g.platform.first()
    m["session"] = g.session.first()
    m["scenario"] = m.session.str.replace("_win", "", regex=False)
    m["n_runs"] = g.run_id.nunique()
    m["pkey"] = g._pk.agg(lambda s: s.dropna().iloc[0] if s.notna().any() else None)
    m["lineage"] = lineage_roots(m)
    return f, m, dropped


def lineage_roots(m):
    known = set(m.index)
    par = m.pkey.to_dict()
    out = []
    for k in m.index:
        seen = set()
        while par.get(k) in known and k not in seen:
            seen.add(k)
            k = par[k]
        out.append(k)
    return out


# ----------------------------------------------------------------- models
def supervised():
    return [
        ("Naive Bayes", GaussianNB(var_smoothing=1e-8)),
        ("Decision Tree", DecisionTreeClassifier(random_state=SEED, class_weight="balanced",
            criterion="entropy", max_depth=17, min_samples_split=14,
            min_samples_leaf=5, max_features="log2")),
        ("Random Forest", RandomForestClassifier(random_state=SEED, n_jobs=-1,
            class_weight="balanced", n_estimators=70, min_samples_leaf=9,
            max_features="sqrt", bootstrap=False)),
        ("SVM", SVC(random_state=SEED, class_weight="balanced", C=10, gamma="scale")),
    ]


def anomaly(benign):
    rs = np.random.RandomState(SEED)
    sub = benign[rs.choice(len(benign), min(6000, len(benign)), replace=False)]
    return [
        ("Isolation Forest", IsolationForest(n_estimators=200, random_state=SEED,
                                             n_jobs=-1).fit(benign)),
        ("Local Outlier Factor", LocalOutlierFactor(n_neighbors=20, novelty=True).fit(benign)),
        ("One-Class SVM", OneClassSVM(kernel="rbf", gamma="scale", nu=0.1).fit(sub)),
    ]


def scores(yte, pred, s=None):
    r = dict(Accuracy=accuracy_score(yte, pred),
             Precision=precision_score(yte, pred, zero_division=0),
             Recall=recall_score(yte, pred, zero_division=0),
             F1=f1_score(yte, pred, zero_division=0),
             FPR=float(np.mean(pred[yte == 0])) if (yte == 0).any() else np.nan)
    r["AUC"] = roc_auc_score(yte, s) if s is not None and len(np.unique(yte)) > 1 else np.nan
    return r


def evaluate(X, y, groups, tr, te, tag, models=("sup", "anom"), meta=None):
    """Fit on tr, test on te. Scaler and all thresholds come from training data only."""
    sc = StandardScaler().fit(X[tr])
    A, B = sc.transform(X[tr]), sc.transform(X[te])
    ytr, yte = y[tr], y[te]
    rows = []
    if "sup" in models:
        for name, m in supervised():
            if FAST and name == "SVM":
                continue
            idx = np.arange(len(ytr))
            if name == "SVM" and len(idx) > SVM_MAX:
                idx = np.random.RandomState(SEED).choice(idx, SVM_MAX, replace=False)
            m.fit(A[idx], ytr[idx])
            s = m.predict_proba(B)[:, 1] if hasattr(m, "predict_proba") else m.decision_function(B)
            rows.extend(os_scores(meta.iloc[te], yte, m.predict(B), s, tag, "Supervised", name))
    if "anom" in models:
        # benign-only training set, split by lineage into fit (80%) / threshold-calibration (20%)
        ben = np.where(ytr == 0)[0]
        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
        fit_i, cal_i = next(gss.split(ben, groups=groups[tr][ben]))
        for name, m in anomaly(A[ben[fit_i]]):
            if FAST and name == "One-Class SVM":
                continue
            thr = np.quantile(-m.score_samples(A[ben[cal_i]]), 1 - TARGET_FPR)
            s = -m.score_samples(B)
            rows.extend(os_scores(meta.iloc[te], yte, (s > thr).astype(int), s, tag, "Anomaly", name, thr))
    rows.extend(os_scores(meta.iloc[te], yte, np.ones_like(yte), None, tag, "Baseline", "All-positive"))
    return rows


def os_scores(meta, y, pred, score, tag, kind, name, threshold=None):
    """Slice predictions only: identical model and threshold for all OS subsets."""
    platforms = meta.platform.astype(str).str.strip().str.lower().to_numpy()
    rows = []
    for os_name in ["ALL"] + sorted(set(platforms)):
        mask = np.ones(len(y), dtype=bool) if os_name == "ALL" else platforms == os_name
        yt, pt = y[mask], pred[mask]
        tn = int(((yt == 0) & (pt == 0)).sum())
        fp = int(((yt == 0) & (pt == 1)).sum())
        fn = int(((yt == 1) & (pt == 0)).sum())
        tp = int(((yt == 1) & (pt == 1)).sum())
        row = dict(tag, Type=kind, Model=name, OS=os_name, Threshold=threshold,
                   N=len(yt), N0=int((yt == 0).sum()), N1=int((yt == 1).sum()),
                   TN=tn, FP=fp, FN=fn, TP=tp,
                   **scores(yt, pt, score[mask] if score is not None else None))
        rows.append(row)
    if PREDICTION_FILE:
        trace=meta[['platform','run','session','lineage','label']].copy()
        trace['process_key']=meta.index
        trace['prediction']=pred
        trace['score']=score if score is not None else np.nan
        for key,value in dict(tag,Type=kind,Model=name,Threshold=threshold).items():
            trace[key]=value
        trace.to_csv(PREDICTION_FILE,mode='a',header=not os.path.exists(PREDICTION_FILE),index=False)
    return rows


def summarize(df, by=("Type", "Model")):
    agg = df.groupby(list(by))[["Accuracy", "Precision", "Recall", "F1", "FPR", "AUC"]].agg(["mean", "std"])
    agg.columns = ["%s_%s" % c for c in agg.columns]
    return agg.reset_index()


# ----------------------------------------------------------------- protocols
def p1_lineage_cv(X, y, meta, repeats=5, k=5, models=("sup", "anom")):
    rows = []
    groups = meta.lineage.values
    for rep in range(repeats):
        skf = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=rep)
        for f, (tr, te) in enumerate(skf.split(X, y, groups)):
            assert not set(groups[tr]) & set(groups[te])
            tag = dict(Protocol="P1_lineage_cv", Repeat=rep, Fold=f, n_test=len(te),
                       test_mal=float(y[te].mean()),
                       test_benign_from_benign_runs=int(((y[te] == 0) & meta.session.str.startswith("benign").values[te]).sum()),
                       test_benign_from_attack_runs=int(((y[te] == 0) & ~meta.session.str.startswith("benign").values[te]).sum()))
            rows += evaluate(X, y, groups, tr, te, tag, models, meta=meta)
        print("  P1 repeat %d done" % rep, flush=True)
    return pd.DataFrame(rows)


def p2_leave_one_run_out(X, y, meta):
    rows = []
    groups = meta.lineage.values
    for run in sorted(meta.run.unique()):
        if meta.session[meta.run == run].iloc[0].startswith("benign"):
            continue
        te = np.where(meta.run.values == run)[0]
        tr = np.where(meta.run.values != run)[0]
        tag = dict(Protocol="P2_leave_one_run_out", HeldOut=meta.platform.iloc[te[0]] + "|" + meta.scenario.iloc[te[0]],
                   n_test=len(te), n_test_mal=int(y[te].sum()), n_test_benign=int((y[te] == 0).sum()))
        rows += evaluate(X, y, groups, tr, te, tag, meta=meta)
        print("  P2", tag["HeldOut"], flush=True)
    return pd.DataFrame(rows)


def p3_leave_one_scenario_out(X, y, meta):
    rows = []
    groups = meta.lineage.values
    for sc in sorted(set(meta.scenario) - {"benign"}):
        te = np.where(meta.scenario.values == sc)[0]
        tr = np.where(meta.scenario.values != sc)[0]
        tag = dict(Protocol="P3_leave_one_scenario_out", HeldOut=sc, n_test=len(te),
                   n_test_mal=int(y[te].sum()), n_test_benign=int((y[te] == 0).sum()))
        rows += evaluate(X, y, groups, tr, te, tag, meta=meta)
        print("  P3", sc, flush=True)
    return pd.DataFrame(rows)


def p4_independent_runs(raw, extra):
    f, m, _ = aggregate(pd.concat([raw, extra], ignore_index=True))
    X, y = f.values, m.label.values
    new = m.run.isin(EXTRA_RUNS).values
    rows = []
    for name, te_mask in [("both new runs", new)] + [(r.split("_")[0] + " (linux, new run)", (m.run == r).values) for r in EXTRA_RUNS]:
        tr, te = np.where(~new)[0], np.where(te_mask)[0]
        tag = dict(Protocol="P4_independent_run", HeldOut=name, n_test=len(te),
                   n_test_mal=int(y[te].sum()), n_test_benign=int((y[te] == 0).sum()))
        rows += evaluate(X, y, m.lineage.values, tr, te, tag, meta=m)
    return pd.DataFrame(rows), m[new].groupby("run").label.agg(["size", "sum"])



def main():
    import argparse
    import hashlib
    import importlib.metadata
    from pathlib import Path
    global PREDICTION_FILE, EXTRA_RUNS
    ap=argparse.ArgumentParser(description="NCCY revised protocols with per-OS reporting")
    ap.add_argument('--csv',default=str(Path(__file__).resolve().parents[1]/'FINAL_DATASET.csv'))
    ap.add_argument('--out',default=str(Path(__file__).resolve().parents[1]/'reference/revised_by_os'))
    ap.add_argument('--protocols',nargs='+',choices=['p1','p2','p3','p4'],default=['p1'])
    ap.add_argument('--repeats',type=int,default=5)
    ap.add_argument('--folds',type=int,default=5)
    ap.add_argument('--extra',nargs='*',default=[],help='P4 labeled CSVs with run_id; both new runs are required')
    ap.add_argument('--save-predictions',action='store_true')
    a=ap.parse_args()
    if a.repeats<1 or a.folds<2:ap.error('repeats >= 1 and folds >= 2 required')
    if 'p4' in a.protocols and len(a.extra)!=2:ap.error('P4 requires two --extra labeled CSV files')
    out=Path(a.out)
    if out.exists() and any(out.iterdir()):ap.error('Output directory is not empty; choose a new --out')
    raw=pd.read_csv(a.csv,low_memory=False)
    if 'run_id' not in raw or raw.run_id.isna().any():
        ap.error('Dataset must contain complete original run_id values; use FINAL_DATASET.csv')
    extra=[]
    for path in a.extra:
        e=pd.read_csv(path,low_memory=False)
        if 'run_id' not in e or e.run_id.isna().any() or e.run_id.nunique()!=1:
            ap.error('Each extra file must have one complete run_id')
        extra.append(e)
    if extra:
        EXTRA_RUNS=[e.run_id.iloc[0] for e in extra]
        if len(set(EXTRA_RUNS))!=2 or set(EXTRA_RUNS)&set(raw.run_id):
            ap.error('Extra run IDs must be distinct and absent from training data')
    f,meta,dropped=aggregate(raw)
    out.mkdir(parents=True,exist_ok=True)
    X,y=f.values,meta.label.values
    manifest=dict(arguments=vars(a),dataset_sha256=hashlib.sha256(Path(a.csv).read_bytes()).hexdigest(),
                  script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  events=len(raw),events_dropped=dropped,processes=len(f),lineages=int(meta.lineage.nunique()),
                  features=list(f.columns),versions={n:importlib.metadata.version(n) for n in ['numpy','pandas','scikit-learn','scipy','joblib']},
                  caveat='Reproduces source scaler fit on all outer training data; only detector fit and threshold calibration are benign-only. OS metrics slice the same test predictions; not cross-OS transfer. Fold SD is not a confidence interval.')
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    for protocol in a.protocols:
        PREDICTION_FILE=str(out/(protocol+'_predictions.csv')) if a.save_predictions else None
        if protocol=='p1':df=p1_lineage_cv(X,y,meta,repeats=a.repeats,k=a.folds)
        elif protocol=='p2':df=p2_leave_one_run_out(X,y,meta)
        elif protocol=='p3':df=p3_leave_one_scenario_out(X,y,meta)
        else:
            df,counts=p4_independent_runs(raw,pd.concat(extra,ignore_index=True))
            counts.to_csv(out/'p4_run_counts.csv')
        df.to_csv(out/(protocol+'_by_os.csv'),index=False)
        # P4 includes pooled and individual runs: keep them separate, never average together.
        by=('Type','Model','OS','HeldOut') if protocol=='p4' else ('Type','Model','OS')
        summary=summarize(df,by=by)
        summary.to_csv(out/(protocol+'_summary_by_os.csv'),index=False)
        print(summary.to_string(index=False),flush=True)
    print('Results:',out.resolve())


if __name__=='__main__':
    main()

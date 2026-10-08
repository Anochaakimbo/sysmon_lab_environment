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
    validation subset (target FPR 5%); no malicious label is used anywhere,
    and the anomaly detectors get their own StandardScaler fitted on that same
    benign fit subset (the supervised scaler sees the whole training fold)
  * anomaly score = -score_samples(X) for every detector (higher = more anomalous)
  * SVM trains on the full training fold like every other model (no subsample cap;
    set env SVM_MAX=N to restore a cap)
  * every metric row is reported pooled (Platform=all) and per platform;
    per-platform rows go to *_by_platform.csv, the main CSVs keep pooled rows only
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
# usage: python host/revised_experiments.py [dataset_dir] [output_dir]
DATA = os.path.join(_HERE, "dataset")
OUT = os.path.join(os.path.dirname(_HERE), "reference", "revised_results")
MERGED = "merged_dataset.csv"        # file name inside DATA; other scripts may point it elsewhere
NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
EXTRA_RUNS = ["ransomware_dash_213312_20260825_213312", "trojan_dash_211024_20260825_211024"]
EVENT_IDS = [1, 2, 3, 4, 5, 8, 9, 11, 12, 13, 23]
TARGET_FPR = 0.05
SVM_MAX = int(os.environ.get("SVM_MAX", "0"))  # 0 = no cap
FAST = os.environ.get("FAST") == "1"


# ----------------------------------------------------------------- data
def load():
    d = pd.read_csv(os.path.join(DATA, MERGED), low_memory=False)
    extra = []
    for r in EXTRA_RUNS:
        e = pd.read_csv(os.path.join(DATA, r + "_labeled.csv"), low_memory=False)
        e["run_id"] = r
        extra.append(e)
    return d, pd.concat(extra, ignore_index=True)


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


def evaluate(X, y, groups, tr, te, tag, models=("sup", "anom"), plat=None):
    """Fit on tr, test on te. Scalers and all thresholds come from training data only.
    plat: platform label per sample -> extra rows per platform of the test set."""
    sc = StandardScaler().fit(X[tr])
    A, B = sc.transform(X[tr]), sc.transform(X[te])
    ytr, yte = y[tr], y[te]
    pte = plat[te] if plat is not None else None
    rows = []

    def emit(typ, name, pred, s=None):
        rows.append(dict(tag, Platform="all", Type=typ, Model=name, **scores(yte, pred, s)))
        if pte is None:
            return
        for p in np.unique(pte):
            k = pte == p
            rows.append(dict(tag, Platform=p, n_test_platform=int(k.sum()), Type=typ, Model=name,
                             **scores(yte[k], pred[k], None if s is None else s[k])))
    if "sup" in models:
        for name, m in supervised():
            if FAST and name == "SVM":
                continue
            idx = np.arange(len(ytr))
            if name == "SVM" and SVM_MAX and len(idx) > SVM_MAX:
                idx = np.random.RandomState(SEED).choice(idx, SVM_MAX, replace=False)
            m.fit(A[idx], ytr[idx])
            s = m.predict_proba(B)[:, 1] if hasattr(m, "predict_proba") else m.decision_function(B)
            emit("Supervised", name, m.predict(B), s)
    if "anom" in models:
        # benign-only training set, split by lineage into fit (80%) / threshold-calibration (20%)
        ben = np.where(ytr == 0)[0]
        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
        fit_i, cal_i = next(gss.split(ben, groups=groups[tr][ben]))
        Xtr = X[tr]
        asc = StandardScaler().fit(Xtr[ben[fit_i]])          # benign fit subset only
        Afit, Acal, Bte = asc.transform(Xtr[ben[fit_i]]), asc.transform(Xtr[ben[cal_i]]), asc.transform(X[te])
        for name, m in anomaly(Afit):
            if FAST and name == "One-Class SVM":
                continue
            thr = np.quantile(-m.score_samples(Acal), 1 - TARGET_FPR)
            s = -m.score_samples(Bte)
            emit("Anomaly", name, (s > thr).astype(int), s)
    emit("Baseline", "All-positive", np.ones_like(yte))
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
            rows += evaluate(X, y, groups, tr, te, tag, models, meta.platform.values)
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
        rows += evaluate(X, y, groups, tr, te, tag, plat=meta.platform.values)
        print("  P2", tag["HeldOut"], flush=True)
    return pd.DataFrame(rows)


def p3_leave_one_scenario_out(X, y, meta):
    rows = []
    groups = meta.lineage.values
    for sc in sorted(s for s in set(meta.scenario) if not s.startswith("benign")):
        te = np.where(meta.scenario.values == sc)[0]
        tr = np.where(meta.scenario.values != sc)[0]
        tag = dict(Protocol="P3_leave_one_scenario_out", HeldOut=sc, n_test=len(te),
                   n_test_mal=int(y[te].sum()), n_test_benign=int((y[te] == 0).sum()))
        rows += evaluate(X, y, groups, tr, te, tag, plat=meta.platform.values)
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
        rows += evaluate(X, y, m.lineage.values, tr, te, tag, plat=m.platform.values)
    return pd.DataFrame(rows), m[new].groupby("run").label.agg(["size", "sum"])


def key_impact(raw):
    out = {}
    res = []
    for key in ("guid", "composite"):
        f, m, dropped = aggregate(raw, key)
        X, y = f.values, m.label.values
        out[key] = dict(samples=len(f), malicious=int(y.sum()), benign=int((y == 0).sum()),
                        events_dropped=int(dropped),
                        keys_spanning_runs=int((m.n_runs > 1).sum()),
                        )
        # the draft's protocol: random 70:30 split by process id, now repeated with 5 seeds
        grp = m.lineage.values if key == "composite" else m.index.values
        for rep in range(5):
            gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=rep)
            tr, te = next(gss.split(X, y, groups=m.index.values))
            res += evaluate(X, y, grp, tr, te, dict(Protocol="random_process_split", Key=key, Repeat=rep))
        print("  key", key, "done", flush=True)
    return out, pd.DataFrame(res)


def split_strategy_rf(X, y, meta, repeats=5):
    """RF only: random process split vs lineage CV (from P1) - shows split sensitivity."""
    rows = []
    for rep in range(repeats):
        gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=rep)
        tr, te = next(gss.split(X, y, groups=meta.index.values))
        sc = StandardScaler().fit(X[tr])
        m = dict(supervised())["Random Forest"]
        m.fit(sc.transform(X[tr]), y[tr])
        B = sc.transform(X[te])
        rows.append(dict(Protocol="random_process_split", Repeat=rep, **scores(y[te], m.predict(B), m.predict_proba(B)[:, 1])))
    return pd.DataFrame(rows)


def main():
    global DATA, OUT
    DATA = sys.argv[1] if len(sys.argv) > 1 else DATA
    OUT = sys.argv[2] if len(sys.argv) > 2 else OUT
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    raw, extra = load()
    summary = {}
    def cached(name, fn):
        """Main CSV = pooled rows; per-platform rows (if any) -> *_by_platform.csv."""
        p = os.path.join(OUT, name)
        pp = p.replace(".csv", "_by_platform.csv")
        if os.path.exists(p):
            return pd.read_csv(p)
        df = fn()
        if "Platform" in df.columns:
            df[df.Platform != "all"].to_csv(pp, index=False)
            df = df[df.Platform == "all"].drop(columns=["Platform", "n_test_platform"], errors="ignore")
        df.to_csv(p, index=False)
        return df
    print("key impact ...", flush=True)
    kstats = {}
    def _ki():
        s_, df_ = key_impact(raw)
        kstats.update(s_)
        return df_
    ki = cached("key_impact.csv", _ki)
    if not kstats:
        for key in ("guid", "composite"):
            f_, m_, d_ = aggregate(raw, key)
            kstats[key] = dict(samples=len(f_), malicious=int(m_.label.sum()), benign=int((m_.label == 0).sum()),
                               events_dropped=int(d_), keys_spanning_runs=int((m_.n_runs > 1).sum()))
    summary["key_impact"] = kstats

    f, meta, dropped = aggregate(raw, "composite")
    X, y = f.values, meta.label.values
    summary["dataset"] = dict(
        events=len(raw), events_used=int(len(raw) - dropped), processes=len(f),
        malicious=int(y.sum()), benign=int((y == 0).sum()),
        lineage_groups=int(meta.lineage.nunique()),
        by_platform=meta.groupby("platform").label.agg(["size", "sum"]).to_dict(),
        benign_in_benign_runs=int(((y == 0) & meta.session.str.startswith("benign")).sum()),
        benign_in_attack_runs=int(((y == 0) & ~meta.session.str.startswith("benign")).sum()),
        lineages_per_run=meta.groupby("run").lineage.nunique().to_dict(),
        features=list(f.columns))
    json.dump(summary, open(os.path.join(OUT, "summary.json"), "w"), indent=2, default=str)

    print("split strategy (RF) ...", flush=True)
    cached("rf_random_process_split.csv", lambda: split_strategy_rf(X, y, meta))
    print("P4 ...", flush=True)
    p4n = {}
    def _p4():
        a_, b_ = p4_independent_runs(raw, extra)
        p4n.update(b_.to_dict())
        return a_
    p4 = cached("p4_independent_runs.csv", _p4)
    summary["p4_new_runs"] = p4n
    print("P3 ...", flush=True)
    p3 = cached("p3_leave_one_scenario_out.csv", lambda: p3_leave_one_scenario_out(X, y, meta))
    print("P2 ...", flush=True)
    p2 = cached("p2_leave_one_run_out.csv", lambda: p2_leave_one_run_out(X, y, meta))
    print("P1 ...", flush=True)
    p1 = cached("p1_lineage_cv.csv", lambda: p1_lineage_cv(X, y, meta))

    for name, df in [("p1", p1), ("p2", p2), ("p3", p3)]:
        summarize(df).to_csv(os.path.join(OUT, name + "_summary.csv"), index=False)
    bp = {n: os.path.join(OUT, f) for n, f in [("p1", "p1_lineage_cv_by_platform.csv"),
          ("p2", "p2_leave_one_run_out_by_platform.csv"), ("p3", "p3_leave_one_scenario_out_by_platform.csv"),
          ("p4", "p4_independent_runs_by_platform.csv")]}
    for name, path in bp.items():
        if os.path.exists(path):
            d = pd.read_csv(path)
            by = ["Platform", "Type", "Model"] + (["HeldOut"] if name == "p4" else [])
            summarize(d, by).to_csv(os.path.join(OUT, name + "_summary_by_platform.csv"), index=False)
    summary["runtime_s"] = round(time.time() - t0)
    json.dump(summary, open(os.path.join(OUT, "summary.json"), "w"), indent=2, default=str)
    print("done in %ds" % summary["runtime_s"])


if __name__ == "__main__":
    main()

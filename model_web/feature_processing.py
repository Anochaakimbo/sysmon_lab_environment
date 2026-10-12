"""Web feature processing: copied without algorithm changes from host/revised_experiments.py."""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
SEED = 0
NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
EVENT_IDS = [1, 2, 3, 4, 5, 8, 9, 11, 12, 13, 23]


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

def scores(yte, pred, s=None):
    r = dict(Accuracy=accuracy_score(yte, pred),
             Precision=precision_score(yte, pred, zero_division=0),
             Recall=recall_score(yte, pred, zero_division=0),
             F1=f1_score(yte, pred, zero_division=0),
             FPR=float(np.mean(pred[yte == 0])) if (yte == 0).any() else np.nan)
    r["AUC"] = roc_auc_score(yte, s) if s is not None and len(np.unique(yte)) > 1 else np.nan
    return r

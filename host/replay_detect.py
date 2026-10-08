# -*- coding: utf-8 -*-
"""
replay_detect.py - can the process-level detector raise alerts *while* an attack
is running? Offline replay of the collected logs, no VM needed.

Problem: the models are trained on finished processes, but a live detector only
sees the events a process has produced so far (n_events, dur_s, ev_* still growing).

Replay: every process is cut at age a seconds after its first event
(a in AGES; inf = whole process) and the same 32 features of
revised_experiments.aggregate() are computed on that prefix. A process is
"detected at age a" if it is flagged at a. A live detector that rescans every
CHECK_S seconds therefore alerts at most CHECK_S later than the replay says.

Folds (trained on finished processes of the training runs, as in the paper):
  P3  leave-one-attack-scenario-out across both OS  -> unseen attack (zero-day)
  P2  leave-one-attack-run-out                       -> seen attack, new run
  BEN hold out both benign runs                      -> false alarms on clean activity
Training variants:
  full     train on finished processes only (the paper's models)
  prefix   train on the prefixes of every age (augmentation for early detection)

Outputs (reference/replay/):
  process_by_age.csv   recall / FPR per fold, model, variant, age
  incidents.csv        per attack lineage tree: detected?, time-to-detect
  false_alarms.csv     benign-only lineage trees alerted, per run, per hour
  summary.csv          one row per protocol x model x variant

usage: python host/replay_detect.py [--k 1]
"""
import argparse, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
OUT = os.path.join(_ROOT, "reference", "replay")
# revised_experiments reads its data/output dirs from argv at import time
_argv = sys.argv[:]
sys.argv = [sys.argv[0], os.path.join(_HERE, "dataset"), os.path.join(OUT, "_rx_tmp")]
sys.path.insert(0, _HERE)
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import revised_experiments as rx
sys.argv = _argv
try:
    os.rmdir(os.path.join(OUT, "_rx_tmp"))
except OSError:
    pass

AGES = [0, 1, 2, 5, 10, 30, 60, 300, np.inf]
CHECK_S = 5
RF_THR = 0.5


def prefix_features(raw):
    """features of every process cut at each age; index = composite key."""
    df = raw[raw.ProcessGuid.notna() & (raw.ProcessGuid != rx.NULL_GUID)].copy()
    ts = pd.to_datetime(df.UtcTime, errors="coerce")
    key = df.platform + "|" + df.run_id + "|" + df.ProcessGuid
    start = ts.groupby(key).transform("min")
    age = (ts - start).dt.total_seconds()
    feats = {}
    for a in AGES:
        f, _, _ = rx.aggregate(df[age <= a], "composite")
        feats[a] = f
        print("  features at age %s: %d processes" % (a, len(f)), flush=True)
    _, meta, _ = rx.aggregate(df, "composite")
    meta["start"] = ts.groupby(key).min().reindex(meta.index)
    run_span = ts.groupby(df.run_id).agg(["min", "max"])
    meta["run_hours"] = meta.run.map((run_span["max"] - run_span["min"]).dt.total_seconds() / 3600)
    for a in AGES:   # same rows, same order at every age
        feats[a] = feats[a].reindex(meta.index).fillna(0)
    return feats, meta


def folds(meta):
    att_runs = sorted(r for r in meta.run.unique() if not meta.session[meta.run == r].iloc[0].startswith("benign"))
    for sc in sorted(s for s in set(meta.scenario) if not s.startswith("benign")):
        yield "P3", sc, meta.scenario.values == sc
    for r in att_runs:
        yield "P2", meta.platform[meta.run == r].iloc[0] + "|" + meta.scenario[meta.run == r].iloc[0], meta.run.values == r
    yield "BEN", "benign runs", meta.scenario.str.startswith("benign").values


def fit_models(feats, y, groups, tr, variant):
    ages = AGES if variant == "prefix" else [np.inf]
    X = np.vstack([feats[a].values[tr] for a in ages])
    Y = np.concatenate([y[tr]] * len(ages))
    rf = dict(rx.supervised())["Random Forest"].fit(X, Y)
    # LOF: benign only, own scaler, threshold = 95th pct of a benign calibration split (as in the paper)
    ben = np.where(y[tr] == 0)[0]
    fit_i, cal_i = next(GroupShuffleSplit(1, test_size=0.2, random_state=rx.SEED).split(ben, groups=groups[tr][ben]))
    Xb = np.vstack([feats[a].values[tr][ben[fit_i]] for a in ages])
    sc = StandardScaler().fit(Xb)
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(sc.transform(Xb))
    Xc = np.vstack([feats[a].values[tr][ben[cal_i]] for a in ages])
    thr = np.quantile(-lof.score_samples(sc.transform(Xc)), 1 - rx.TARGET_FPR)
    return {"Random Forest": lambda Z: rf.predict_proba(Z)[:, 1] >= RF_THR,
            "Local Outlier Factor": lambda Z: -lof.score_samples(sc.transform(Z)) > thr}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1, help="alert a lineage tree once >= k of its processes are flagged")
    ap.add_argument("--thr", type=float, default=0.5, help="Random Forest probability threshold")
    ap.add_argument("--tag", default="", help="suffix for output files")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    global RF_THR
    RF_THR = a.thr
    sfx = a.tag or "_k%d_thr%g" % (a.k, a.thr)
    raw, _ = rx.load()
    feats, meta = prefix_features(raw)
    y, groups = meta.label.values, meta.lineage.values

    by_age, incidents, fas = [], [], []
    for proto, held, te_mask in folds(meta):
        tr, te = np.where(~te_mask)[0], np.where(te_mask)[0]
        for variant in ("full", "prefix"):
            for model, predict in fit_models(feats, y, groups, tr, variant).items():
                flags = np.column_stack([predict(feats[ag].values[te]) for ag in AGES])  # (n_te, n_ages)
                yt = y[te]
                for j, ag in enumerate(AGES):
                    by_age.append(dict(Protocol=proto, HeldOut=held, Variant=variant, Model=model, Age=ag,
                                       Recall=flags[yt == 1, j].mean() if (yt == 1).any() else np.nan,
                                       FPR=flags[yt == 0, j].mean() if (yt == 0).any() else np.nan))
                # first age a process is flagged (inf if never) -> wall-clock detection time
                first = np.array([AGES[np.argmax(r)] if r.any() else np.nan for r in flags])
                # age inf = flagged only once the whole process is seen -> use its last event time
                end = meta.start.iloc[te] + pd.to_timedelta(feats[np.inf].dur_s.values[te], unit="s")
                det = meta.start.iloc[te] + pd.to_timedelta(np.where(np.isfinite(first), first, 0), unit="s")
                m = meta.iloc[te].assign(hit=~np.isnan(first), det=det.where(~np.isinf(first), end))
                # attack incidents = label-1 processes grouped by lineage tree
                for (run, lin), g in m[m.label == 1].groupby(["run", "lineage"]):
                    hit = g[g.hit]
                    ok = len(hit) >= a.k
                    ttd = (hit.det.sort_values().iloc[a.k - 1] - g.start.min()).total_seconds() if ok else np.nan
                    incidents.append(dict(Protocol=proto, HeldOut=held, Variant=variant, Model=model, run=run,
                                          platform=g.platform.iloc[0], scenario=g.scenario.iloc[0],
                                          n_proc=len(g), detected=int(ok), ttd_s=ttd))
                # false alarms = lineage trees with no attack process that still get >= k flags
                trees = m.groupby(["run", "lineage"]).agg(mal=("label", "max"), hits=("hit", "sum"))
                for run, g in trees[trees.mal == 0].groupby(level=0):
                    hours = meta.run_hours[meta.run == run].iloc[0]
                    n_fa = int((g.hits >= a.k).sum())
                    fas.append(dict(Protocol=proto, HeldOut=held, Variant=variant, Model=model, run=run,
                                    benign_trees=len(g), false_alarms=n_fa, hours=hours,
                                    fa_per_hour=n_fa / hours if hours else np.nan))
        print("  %s %s done" % (proto, held), flush=True)

    ba, inc, fa = pd.DataFrame(by_age), pd.DataFrame(incidents), pd.DataFrame(fas)
    ba.to_csv(os.path.join(OUT, "process_by_age%s.csv" % sfx), index=False)
    inc.to_csv(os.path.join(OUT, "incidents%s.csv" % sfx), index=False)
    fa.to_csv(os.path.join(OUT, "false_alarms%s.csv" % sfx), index=False)

    keys = ["Protocol", "Model", "Variant"]
    s = inc.groupby(keys).agg(incidents=("detected", "size"), detected=("detected", "mean"),
                              ttd_median_s=("ttd_s", "median"), ttd_p90_s=("ttd_s", lambda v: v.quantile(0.9)))
    s = s.join(fa.groupby(keys).agg(false_alarms=("false_alarms", "sum"), hours=("hours", "sum")), how="outer")
    s["fa_per_hour"] = s.false_alarms / s.hours
    for ag in (0, 5, 30, np.inf):
        r = ba[ba.Age == ag].groupby(keys)[["Recall", "FPR"]].mean()
        s["recall@%s" % ag], s["fpr@%s" % ag] = r.Recall, r.FPR
    s = s.reset_index()
    s.to_csv(os.path.join(OUT, "summary%s.csv" % sfx), index=False)
    pd.set_option("display.width", 250)
    print(s.round(3).to_string(index=False))
    print("(live detector adds up to %ds scan delay to every ttd) -> %s" % (CHECK_S, OUT))


if __name__ == "__main__":
    main()

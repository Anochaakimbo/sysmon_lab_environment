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
  host_alerts.csv      per run: host-level alerts for every (threshold, W, N)
  host_summary.csv     host-level detection / time-to-detect / false alarms per hour

Two alert units:
  lineage tree  (--k)   alert once >= k processes of one lineage tree are flagged
  host window   (W, N)  alert once >= N processes of one host are flagged within
                        W seconds; then stay quiet for W seconds (one alert per burst).
                        An alert is a true alert if any flagged process in its window
                        has label 1; otherwise it is a false alarm. This is how a SOC
                        sees it: one alert per host per burst, not one per process.

usage: python host/replay_detect.py [--k 1] [--thr 0.5]
"""
import argparse, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
OUT = os.path.join(_ROOT, "reference", "replay")
sys.path.insert(0, _HERE)
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import revised_experiments as rx

AGES = [0, 1, 2, 5, 10, 30, 60, 300, np.inf]
CHECK_S = 5
RF_THR = 0.5
RF_THRS = (0.5, 0.7, 0.9, 0.95, 0.98, 0.99)   # host-window grid
WINDOWS = (60, 300)
MIN_PROCS = (1, 2, 3)


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
    for r in sorted(r for r in meta.run.unique() if meta.session[meta.run == r].iloc[0].startswith("benign")):
        yield "BEN", meta.platform[meta.run == r].iloc[0] + "|" + meta.session[meta.run == r].iloc[0], meta.run.values == r


def benign_curve(feats, meta, W=60, N=2, thr=0.9, seed=0):
    """false alarms on one held-out benign run vs how many other benign runs the
    model was trained on (attack runs always in training). RF, prefix variant."""
    y, groups = meta.label.values, meta.lineage.values
    is_ben = meta.session.str.startswith("benign").values
    ben_runs = sorted(meta.run[is_ben].unique())
    att = np.where(~is_ben)[0]
    rows = []
    for held in ben_runs:
        others = [r for r in ben_runs if r != held]
        order = list(np.random.RandomState(seed).permutation(others))
        te = np.where(meta.run.values == held)[0]
        plat = meta.platform.values[te[0]]
        for k in range(len(order) + 1):
            tr = np.concatenate([att, np.where(meta.run.isin(order[:k]).values)[0]])
            score, _ = fit_models(feats, y, groups, tr, "prefix")["Random Forest"]
            S = np.column_stack([score(feats[ag].values[te]) for ag in AGES])
            mh = detection_times(meta, feats, te, S >= thr)
            r = host_window(mh, W, N)[0]
            same = sum(meta.platform[meta.run == o].iloc[0] == plat for o in order[:k])
            rows.append(dict(held_out=held, platform=plat, benign_runs_in_train=k, same_platform_in_train=same,
                             process_fpr=float((S[:, -1] >= thr).mean()), process_fpr_age0=float((S[:, 0] >= thr).mean()),
                             false_alarms=r["false_alarms"], hours=r["hours"],
                             fa_per_hour=r["false_alarms"] / r["hours"]))
            print("  curve %s k=%d  fpr=%.3f  fa/h=%.1f" % (held, k, rows[-1]["process_fpr"], rows[-1]["fa_per_hour"]), flush=True)
    return pd.DataFrame(rows)


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
    # (score function, thresholds to sweep); flagged = score >= threshold
    return {"Random Forest": (lambda Z: rf.predict_proba(Z)[:, 1], RF_THRS),
            "Local Outlier Factor": (lambda Z: -lof.score_samples(sc.transform(Z)) - thr + 1e-12, (0.0,))}


def detection_times(meta, feats, te, flags):
    """wall-clock time each test process is first flagged (NaT if never)."""
    first = np.array([AGES[np.argmax(r)] if r.any() else np.nan for r in flags])
    # age inf = flagged only once the whole process is seen -> use its last event time
    end = meta.start.iloc[te] + pd.to_timedelta(feats[np.inf].dur_s.values[te], unit="s")
    det = meta.start.iloc[te] + pd.to_timedelta(np.where(np.isfinite(first), first, 0), unit="s")
    return meta.iloc[te].assign(hit=~np.isnan(first), det=det.where(~np.isinf(first), end))


def host_window(m, W, N):
    """one row per run: alerts raised by the (W, N) rule over the flagged processes of that host."""
    rows = []
    for run, g in m.groupby("run"):
        f = g[g.hit].sort_values("det")
        t = (f.det - g.start.min()).dt.total_seconds().values
        lab = f.label.values
        alerts, tp, first_tp, last = 0, 0, np.nan, -np.inf
        for i in range(len(t)):
            lo = np.searchsorted(t, t[i] - W, side="right")
            if i - lo + 1 >= N and t[i] - last >= W:
                last = t[i]
                alerts += 1
                if lab[lo:i + 1].any():
                    tp += 1
                    if np.isnan(first_tp):
                        first_tp = t[i]
        att = g[g.label == 1]
        a0 = (att.start.min() - g.start.min()).total_seconds() if len(att) else np.nan
        rows.append(dict(run=run, platform=g.platform.iloc[0], scenario=g.scenario.iloc[0],
                         attack_run=int(len(att) > 0), alerts=alerts, true_alerts=tp, false_alarms=alerts - tp,
                         detected=int(tp > 0) if len(att) else np.nan,
                         ttd_s=first_tp - a0 if len(att) else np.nan,
                         hours=g.run_hours.iloc[0]))
    return rows


def _selftest():
    """burst of 3 benign flags at 0-2 s, attack starts at 100 s, flagged at 100 and 101 s."""
    t0 = pd.Timestamp("2026-01-01")
    m = pd.DataFrame(dict(run="r", platform="linux", scenario="x", run_hours=1.0,
                          start=[t0 + pd.Timedelta(seconds=s) for s in (0, 1, 2, 100, 101, 500)],
                          label=[0, 0, 0, 1, 1, 1], hit=[True, True, True, True, True, False]))
    m["det"] = m.start
    r = host_window(m, W=60, N=2)[0]
    assert (r["alerts"], r["true_alerts"], r["false_alarms"], r["ttd_s"]) == (2, 1, 1, 1.0), r
    r = host_window(m, W=60, N=3)[0]
    assert (r["alerts"], r["true_alerts"], r["detected"]) == (1, 0, 0), r
    print("selftest ok")


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1, help="alert a lineage tree once >= k of its processes are flagged")
    ap.add_argument("--thr", type=float, default=0.5, help="Random Forest probability threshold")
    ap.add_argument("--tag", default="", help="suffix for output files")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--merged", default=rx.MERGED, help="merged CSV inside host/dataset")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--benign-curve", action="store_true",
                    help="only the false-alarm learning curve over the number of benign runs")
    a = ap.parse_args()
    if a.selftest:
        return _selftest()
    OUT = a.out
    rx.MERGED = a.merged
    os.makedirs(OUT, exist_ok=True)
    if a.benign_curve:
        raw, _ = rx.load()
        feats, meta = prefix_features(raw)
        c = benign_curve(feats, meta)
        c.to_csv(os.path.join(OUT, "benign_curve.csv"), index=False)
        s = c.groupby("benign_runs_in_train")[["process_fpr", "process_fpr_age0", "fa_per_hour"]].agg(["mean", "std"])
        s.round(3).to_csv(os.path.join(OUT, "benign_curve_summary.csv"))
        print(s.round(3).to_string())
        return
    global RF_THR
    RF_THR = a.thr
    sfx = a.tag or "_k%d_thr%g" % (a.k, a.thr)
    raw, _ = rx.load()
    feats, meta = prefix_features(raw)
    y, groups = meta.label.values, meta.lineage.values

    by_age, incidents, fas, hosts = [], [], [], []
    for proto, held, te_mask in folds(meta):
        tr, te = np.where(~te_mask)[0], np.where(te_mask)[0]
        for variant in ("full", "prefix"):
            for model, (score, thrs) in fit_models(feats, y, groups, tr, variant).items():
                S = np.column_stack([score(feats[ag].values[te]) for ag in AGES])  # (n_te, n_ages)
                for th in thrs:
                    mh = detection_times(meta, feats, te, S >= th)
                    for W in WINDOWS:
                        for N in MIN_PROCS:
                            for r in host_window(mh, W, N):
                                hosts.append(dict(Protocol=proto, HeldOut=held, Variant=variant, Model=model,
                                                  thr=th, W=W, N=N, **r))
                flags = S >= (RF_THR if model == "Random Forest" else 0.0)
                yt = y[te]
                for j, ag in enumerate(AGES):
                    by_age.append(dict(Protocol=proto, HeldOut=held, Variant=variant, Model=model, Age=ag,
                                       Recall=flags[yt == 1, j].mean() if (yt == 1).any() else np.nan,
                                       FPR=flags[yt == 0, j].mean() if (yt == 0).any() else np.nan))
                m = detection_times(meta, feats, te, flags)
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
    h = pd.DataFrame(hosts)
    h.to_csv(os.path.join(OUT, "host_alerts.csv"), index=False)
    hk = ["Model", "Variant", "thr", "W", "N"]
    att = h[h.attack_run == 1].groupby(["Protocol"] + hk).agg(
        attack_runs=("detected", "size"), detected=("detected", "mean"),
        ttd_median_s=("ttd_s", "median"), ttd_max_s=("ttd_s", "max"),
        fa_attack_runs=("false_alarms", "sum"), h_attack_runs=("hours", "sum"))
    ben = h[(h.Protocol == "BEN")].groupby(hk).agg(fa_benign=("false_alarms", "sum"), h_benign=("hours", "sum"))
    hs = att.reset_index().merge(ben.reset_index(), on=hk, how="left")
    hs["fa_per_hour_attack_runs"] = hs.fa_attack_runs / hs.h_attack_runs
    hs["fa_per_hour_unseen_benign"] = hs.fa_benign / hs.h_benign
    hs.to_csv(os.path.join(OUT, "host_summary.csv"), index=False)
    best = hs[(hs.Protocol == "P3")].sort_values(["fa_per_hour_unseen_benign", "detected"], ascending=[True, False])
    print("\nhost-window alerts, P3 (unseen attack) - lowest false alarms on unseen benign first:")
    print(best.round(2).head(15).to_string(index=False))
    print("(live detector adds up to %ds scan delay to every ttd) -> %s" % (CHECK_S, OUT))


if __name__ == "__main__":
    main()

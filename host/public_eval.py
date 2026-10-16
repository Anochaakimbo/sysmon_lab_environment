"""public_eval.py - the lab-trained Random Forest on public Sysmon datasets.

BarongTrace (github.com/bazz-066/linux-malware-dataset, Dataset/Original_Linux/<n>result.zip, Linux, Cuckoo):
  each file is labelled per analysis run, so background OS processes carry the run's label. Only processes
  launched from the submitted sample (/tmp/<name>) and their descendants are kept. Malware samples are named
  /tmp/VirusShare_<md5>, which cmd_len and string entropy read as the label, so every /tmp/<name> path is
  replaced with /tmp/SAMPLE before features are built.
NLME (reference/NLME.csv, Windows): no CommandLine / ParentCommandLine / Device; groups = host_name.

Feature sets: paper32 (revised_experiments.aggregate), clean (replay_detect behaviour features, lab harness
processes dropped from training), neutral (cross_platform_eval.NEUTRAL). Thresholds: 0.5; 95th percentile of
benign scores from the OTHER groups; 95th percentile of benign scores from the first half of the same group
(scored on the second half only). BarongTrace also gets leave-one-file-out RF trained on BarongTrace itself.

usage: python host/public_eval.py --barong DIR [--nlme reference/NLME.csv] [--data host/dataset]
       DIR = folder tree holding the extracted <n>result.csv files (read as data, never executed)
       writes reference/public_eval/results.csv
"""
import argparse, glob, os, re, gc
import numpy as np, pandas as pd
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, recall_score
import revised_experiments as R, replay_detect as rd
from cross_platform_eval import NEUTRAL

COLS = ["EventID", "UtcTime", "ProcessGuid", "ParentProcessGuid", "Image", "CommandLine", "ParentCommandLine",
        "TargetFilename", "DestinationIp", "DestinationPort", "TargetObject", "Device", "label"]
NO_CMD = ["cmd_len", "pcmd_len"]


def sample_lineage(d):
    """ProcessGuids whose image is /tmp/<name> (the submitted sample) plus all their descendants."""
    img = d.dropna(subset=["Image"]).drop_duplicates("ProcessGuid").set_index("ProcessGuid").Image
    par = d.dropna(subset=["ParentProcessGuid"]).drop_duplicates("ProcessGuid").set_index("ProcessGuid").ParentProcessGuid
    keep = set(img.index[img.str.match(r"^/tmp/[^/]+$")])
    while True:
        new = set(par.index[par.isin(keep)]) - keep
        if not new:
            return keep
        keep |= new


def barong(root):
    files = sorted(glob.glob(os.path.join(root, "**", "*result.csv"), recursive=True),
                   key=lambda p: int(re.match(r"\d+", os.path.basename(p)).group()))
    assert files, "no <n>result.csv under " + root
    out = []
    for path in files:
        d = pd.read_csv(path, low_memory=False, usecols=lambda c: c in COLS)
        d = d[d.ProcessGuid.isin(sample_lineage(d))].copy()
        d["platform"], d["run_id"] = "linux", os.path.basename(path)
        out.append(d); gc.collect()
        print("%-14s sample-lineage events %d" % (os.path.basename(path), len(d)), flush=True)
    d = pd.concat(out, ignore_index=True)
    for c in ("Image", "CommandLine", "ParentCommandLine", "TargetFilename"):
        d[c] = d[c].astype("string").str.replace(r"/tmp/[^/\s'\"]+", "/tmp/SAMPLE", regex=True)
    return d


def nlme(path):
    d = pd.read_csv(path, low_memory=False)
    d["platform"], d["run_id"] = "windows", d.host_name.astype(str)
    return d


def feats(raw, harness_drop):
    raw = raw.copy()
    for c in COLS:
        if c not in raw:
            raw[c] = np.nan
    raw["session"] = raw.get("session", "x")
    f, m = rd.prefix_features(raw, behavior=True, ages=[np.inf], quiet=True)
    f = f[np.inf]
    return (f[~m.harness.values], m[~m.harness.values]) if harness_drop else (f, m)


def metrics(y, p, thr):
    yh = p > thr   # strict: many benign processes share one score, >= flags the whole tie
    return dict(acc=accuracy_score(y, yh), recall=recall_score(y, yh, zero_division=0),
                f1=f1_score(y, yh, zero_division=0), fpr=yh[y == 0].mean())


def calibrated(y, p, grp, st):
    """thr_other: per group, from benign scores of the other groups. thr_early / late: per group, from benign
    scores of processes that started in the first half; `late` marks the second half that is scored."""
    thr, thr2, late = np.zeros(len(y)), np.zeros(len(y)), np.zeros(len(y), bool)
    st = st.astype("int64")
    for g in np.unique(grp):
        on = grp == g
        thr[on] = np.quantile(p[(grp != g) & (y == 0)], 0.95)
        early = on & (st <= np.quantile(st[on], 0.5))
        late |= on & ~early
        thr2[on] = np.quantile(p[early & (y == 0)], 0.95)
    return thr, thr2, late


def run(name, osn, raw, lab, rows, lofo):
    p32, m32, lab_f, lab_m = lab
    for c in COLS:
        if c not in raw:
            raw[c] = np.nan
    if "session" not in raw:
        raw["session"] = "x"
    tf, tm = feats(raw, False)
    tp32 = R.aggregate(raw.copy())[0].reindex(tm.index).fillna(0)
    y, grp = tm.label.values, tm.run.values
    base = dict(acc=max(y.mean(), 1 - y.mean()), f1=f1_score(y, np.ones_like(y)))
    print("\n=== %s: %d processes in %d groups, label=1 %.3f | baseline acc %.3f, F1(all-attack) %.3f"
          % (name, len(y), len(np.unique(grp)), y.mean(), base["acc"], base["f1"]))
    sets = {"paper32": (p32, m32, tp32, list(p32.columns)), "clean": (lab_f, lab_m, tf, list(lab_f.columns)),
            "neutral": (lab_f, lab_m, tf, NEUTRAL)}
    for sname, (Xl, ml, Xt, cols) in sets.items():
        on = (ml.platform == osn).values
        rf = dict(R.supervised())["Random Forest"].fit(Xl[cols].values[on], ml.label.values[on])
        p = rf.predict_proba(Xt[cols].values)[:, 1]
        thr, thr2, late = calibrated(y, p, grp, tm.start.values)
        auc = roc_auc_score(y, p)
        for how, mask, t in (("0.5", slice(None), 0.5), ("other-group benign", slice(None), thr),
                             ("same-group earlier benign", late, thr2[late])):
            r = metrics(y[mask], p[mask], t)
            rows.append(dict(dataset=name, train="lab", features=sname, threshold=how, processes=len(y[mask]),
                             auc=auc if how != "same-group earlier benign" else roc_auc_score(y[late], p[late]),
                             base_acc=max(y[mask].mean(), 1 - y[mask].mean()),
                             base_f1=f1_score(y[mask], np.ones_like(y[mask])), **r))
            print("  %-8s %-26s acc %.3f rec %.3f F1 %.3f FPR %.3f" % (sname, how, r["acc"], r["recall"], r["f1"], r["fpr"]))
        print("  %-8s AUC %.3f" % (sname, auc))
    if lofo:   # RF trained on the other public files, no command-length features
        cols = [c for c in p32.columns if c not in NO_CMD]
        P = np.zeros(len(y))
        for g in np.unique(grp):
            te = grp == g
            P[te] = dict(R.supervised())["Random Forest"].fit(tp32[cols].values[~te], y[~te]).predict_proba(
                tp32[cols].values[te])[:, 1]
        r = metrics(y, P, 0.5)
        rows.append(dict(dataset=name, train="leave-one-file-out", features="paper32 - cmd_len/pcmd_len",
                         threshold="0.5", processes=len(y), auc=roc_auc_score(y, P),
                         base_acc=base["acc"], base_f1=base["f1"], **r))
        print("  LOFO 30  acc %.3f rec %.3f F1 %.3f FPR %.3f AUC %.3f" % (r["acc"], r["recall"], r["f1"], r["fpr"],
                                                                         roc_auc_score(y, P)))


def selftest():
    d = pd.DataFrame(dict(ProcessGuid=["a", "b", "c", "x", "y"], ParentProcessGuid=["dash", "a", "b", "dash", "x"],
                          Image=["/tmp/VirusShare_1", "/bin/sh", "/usr/bin/curl", "/usr/sbin/cron", "/bin/sh"]))
    assert sample_lineage(d) == {"a", "b", "c"}


if __name__ == "__main__":
    selftest()
    ap = argparse.ArgumentParser()
    ap.add_argument("--barong", help="folder with extracted BarongTrace <n>result.csv files")
    ap.add_argument("--nlme", help="path to NLME.csv")
    ap.add_argument("--events", nargs=3, action="append", default=[], metavar=("CSV", "NAME", "OS"),
                    help="a labelled CSV already in the lab event schema (see host/public_sets/), e.g. APT29")
    ap.add_argument("--data", default=R.DATA)
    ap.add_argument("--lab", help="lab training CSV instead of --data, e.g. data/FINAL_DATASET_50runs.csv.gz")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(R._HERE), "reference", "public_eval"))
    a = ap.parse_args()
    assert a.barong or a.nlme or a.events, "give --barong, --nlme and/or --events"
    R.DATA = a.data
    lab_raw = pd.read_csv(a.lab, low_memory=False) if a.lab else R.load()[0]
    p32, m32, _ = R.aggregate(lab_raw.copy())
    lab = (p32, m32) + feats(lab_raw, True)
    rows = []
    if a.barong:
        run("BarongTrace sample-lineage, names masked", "linux", barong(a.barong), lab, rows, lofo=True)
    if a.nlme:
        run("NLME", "windows", nlme(a.nlme), lab, rows, lofo=False)
    for path, name, osn in a.events:
        d = pd.read_csv(path, low_memory=False)
        d["platform"] = osn
        if "run_id" not in d:
            d["run_id"] = d.host_name.astype(str)
        run(name, osn, d, lab, rows, lofo=False)
    os.makedirs(a.out, exist_ok=True)
    pd.DataFrame(rows).round(4).to_csv(os.path.join(a.out, "results.csv"), index=False)
    print("->", os.path.join(a.out, "results.csv"))

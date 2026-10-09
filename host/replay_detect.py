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
import argparse, os, re, sys
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


# ---- lab harness: processes of the test framework, not of the attack -------------------
# Atomic Red Team engine and its Windows Start-Job worker, the orchestrator/_lib launchers,
# ART prerequisite checks and empty executor wrappers, and pacing/setup helpers.
# They exist in benign and attack runs alike but get the label of the run they are in,
# so a model can score high by recognising the framework (replay_v2/harness_probe.csv).
ENGINE = re.compile(r"Invoke-AtomicRedTeam|Invoke-AtomicTest|run_atomic\.sh|ATOMIC_TIMEOUT"
                    r"|lab_sandbox[\\/][\w.-]+\.(sh|ps1)\b|_lib\.(sh|ps1)"
                    r"|powershell\.exe\"? -Version 5\.1 -s -NoLogo -NoProfile"
                    r"|New-Item -ItemType Directory -Path C:\\lab_sandbox"
                    # vagrant ssh delivery of the scenario: login-session motd scripts and the copy step
                    r"|/vagrant/scenarios/|update-motd|landscape-sysinfo|^/usr/sbin/sshd -D -R$", re.I)
HELPER = re.compile(r"^(sleep \d+|tail -\d+|true|locale|/usr/bin/locale-check \S+|setsid --wait true"
                    # scenario work-dir setup: attack uses /tmp/lab_sandbox/*, benign /tmp/benign_* -> path-only signal
                    r"|date -u \+%Y-%m-%dT%H:%M:%SZ|(sudo )?mkdir -p /tmp/(lab_sandbox|benign_\w+)(/\S*)?"
                    r"|\"(powershell|cmd)\.exe\" (& \{\}|/c))\s*$"
                    r"|\{\s*exit 0\s*\}\s*else\s*\{\s*exit 1\s*\}|\(\s*EXIT 0\s*\)\s*ELSE\s*\(\s*EXIT 1\s*\)", re.I)
SHELLS = {"sh", "bash", "dash", "cmd.exe", "powershell.exe", "pwsh"}


def harness_mask(img, cmd, pcmd):
    """True for lab-harness processes. Children of the ART engine that are not a shell are its
    own bookkeeping (hostname/id/whoami for the log); shells under it run the test -> kept."""
    base = img.fillna("").str.split(r"[\\/]").str[-1].str.lower()
    cmd, pcmd = cmd.fillna(""), pcmd.fillna("")
    return (cmd.str.contains(ENGINE) | cmd.str.contains(HELPER) | (base == "conhost.exe")
            | (pcmd.str.contains(r"Invoke-AtomicRedTeam|-Version 5\.1 -s -NoLogo", case=False) & ~base.isin(SHELLS)))


# ---- behaviour features (--behavior) -----------------------------------------------------
# What the process does, not how long its command is: sensitive paths, file churn, outbound
# traffic, children, command-line structure. No label, lineage or lab path is used.
SENSITIVE = re.compile(r"/etc/(passwd|shadow|sudoers|crontab|cron\.|systemd/)|/\.ssh/|/\.(bashrc|profile|bash_profile)\b"
                       r"|/var/spool/cron|lsass|\\SAM\b|\\CurrentVersion\\Run|\\Startup\\|\\Tasks\\"
                       r"|\\Winlogon\\|\\Image File Execution Options\\", re.I)
WRITABLE = re.compile(r"^(/tmp/|/var/tmp/|/dev/shm/)|\\(Temp|AppData|Downloads)\\", re.I)
PRIVATE = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|fe80:|0\.0\.0\.0)")
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _entropy(s):
    if not s:
        return 0.0
    _, c = np.unique(list(s), return_counts=True)
    p = c / c.sum()
    return float(-(p * np.log2(p)).sum())


def behavior_rows(df, key, ts):
    """per-event indicators, computed once on the full log."""
    tf = df.TargetFilename.fillna("").astype(str)
    fc = (df.EventID == 11) & (tf != "")
    base = tf.str.split(r"[\\/]").str[-1]
    r = pd.DataFrame(dict(_k=key.values, _ts=ts.values, eid=df.EventID.values), index=df.index)
    r["sens"] = (tf.str.contains(SENSITIVE) | df.TargetObject.fillna("").astype(str).str.contains(SENSITIVE)).astype(int)
    r["fname_ent"] = np.where(fc, base.map(_entropy), np.nan)
    r["ext"] = np.where(fc, base.str.extract(r"\.([A-Za-z0-9]{1,8})$", expand=False).str.lower(), None)
    r["tf"] = np.where(df.EventID.isin([11, 23]) & (tf != ""), tf.str.lower(), None)
    ip = df.DestinationIp.fillna("").astype(str)
    r["ext_conn"] = ((df.EventID == 3) & (ip != "") & ~ip.str.contains(PRIVATE)).astype(int)
    pg = df.ParentProcessGuid.astype("string")
    r["_pk"] = np.where((df.EventID == 1) & pg.notna() & (pg != rx.NULL_GUID),
                        df.platform + "|" + df.run_id + "|" + pg.fillna(""), None)
    return r


def behavior_static(meta, img, cmd):
    """per-process features fixed at ProcessCreate (command line + image path)."""
    c = cmd.fillna("").astype(str)
    return pd.DataFrame({
        "b_pipes": c.str.count(r"\|"), "b_redirects": c.str.count(r"\d?>>?"),
        "b_chain": c.str.count(r"&&|;|\s&\s"), "b_url": c.str.contains(r"https?://|ftp://", case=False).astype(int),
        "b_ip_literal": c.str.contains(r"\b\d{1,3}(\.\d{1,3}){3}\b").astype(int),
        "b_b64": c.str.contains(B64).astype(int), "b_devtcp": c.str.contains(r"/dev/(tcp|udp)/").astype(int),
        "b_cmd_entropy": c.map(_entropy),
        "b_exec_writable": img.fillna("").astype(str).str.contains(WRITABLE).astype(int),
    }, index=meta.index)


def behavior_at(r, start, a, index):
    """aggregate per-event indicators over the first `a` seconds of each process."""
    age = (r._ts - r._k.map(start)).dt.total_seconds()
    x = r[age <= a]
    g = x.groupby("_k")
    f = pd.DataFrame(index=index)
    f["b_sensitive"] = g.sens.sum()
    f["b_fname_ent_mean"] = g.fname_ent.mean()
    f["b_fname_ent_max"] = g.fname_ent.max()
    f["b_n_ext"] = g.ext.nunique()
    f["b_ext_conn"] = g.ext_conn.sum()
    cr = x[x.eid == 11].dropna(subset=["tf"]).groupby(["_k", "tf"]).size()
    de = x[x.eid == 23].dropna(subset=["tf"]).groupby(["_k", "tf"]).size()
    both = cr.index.intersection(de.index)
    f["b_create_then_delete"] = pd.Series(1, index=both).groupby(level=0).sum() if len(both) else 0
    # children spawned within `a` seconds of this process's own start
    ch = r[r._pk.notna()]
    ch_age = (ch._ts - ch._pk.map(start)).dt.total_seconds()
    f["b_children"] = ch[ch_age <= a].groupby("_pk").size()
    return f.reindex(index).fillna(0)


def behavior_parent(meta, img, a):
    """siblings: what this process's parent had spawned by (own start + a).
    Linux scenarios spread one behaviour over many tiny processes (one openssl + one rm per file),
    so the per-process view misses it; the parent's spawn burst does not."""
    m = pd.DataFrame(dict(pk=meta.pkey.values, s=meta.start.values,
                          img=img.fillna("").astype(str).str.split(r"[\\/]").str[-1].str.lower().values), index=meta.index)
    m = m[m.pk.notna()]
    out = pd.DataFrame(0.0, index=meta.index, columns=["b_sib_spawned", "b_sib_same_image", "b_sib_images",
                                                       "b_sib_period_cv", "b_sib_period_s"])
    out[["b_sib_period_cv", "b_sib_period_s"]] = -1.0     # fewer than 3 same-image siblings: no period
    for _, g in m.groupby("pk"):
        g = g.sort_values("s")
        t = g.s.values
        lim = t + np.timedelta64(int(min(a, 1e7) * 1000), "ms")
        out.loc[g.index, "b_sib_spawned"] = np.searchsorted(t, lim, side="right")
        same = np.zeros(len(g))
        cv, per = np.full(len(g), -1.0), np.full(len(g), -1.0)
        for _, gi in g.groupby("img"):
            pos = g.index.get_indexer(gi.index)
            n = np.searchsorted(gi.s.values, lim[pos], side="right")
            same[pos] = n
            # beacon = same child image re-spawned at a steady interval (one curl/ping process per beat)
            d = np.diff(gi.s.values).astype("timedelta64[ms]").astype(float) / 1000
            for j, k in zip(pos, n):
                if k >= 3:
                    w = d[:k - 1]
                    per[j] = w.mean()
                    cv[j] = w.std() / w.mean() if w.mean() > 0 else 0.0
        out.loc[g.index, "b_sib_same_image"] = same
        out.loc[g.index, "b_sib_period_cv"] = cv
        out.loc[g.index, "b_sib_period_s"] = per
        imgs = g.img.values
        out.loc[g.index, "b_sib_images"] = [len(set(imgs[:n])) for n in np.searchsorted(t, lim, side="right")]
    return out


def prefix_features(raw, behavior=False):
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
    g = df.groupby(key)
    first = lambda c: g[c].agg(lambda v: v.dropna().iloc[0] if v.notna().any() else None).reindex(meta.index)
    meta["harness"] = harness_mask(first("Image"), first("CommandLine"), first("ParentCommandLine")).values
    run_span = ts.groupby(df.run_id).agg(["min", "max"])
    meta["run_hours"] = meta.run.map((run_span["max"] - run_span["min"]).dt.total_seconds() / 3600)
    for a in AGES:   # same rows, same order at every age
        feats[a] = feats[a].reindex(meta.index).fillna(0)
    if behavior:
        r = behavior_rows(df, key, ts)
        st = behavior_static(meta, first("Image"), first("CommandLine"))
        for a in AGES:
            feats[a] = pd.concat([feats[a], behavior_at(r, meta.start, a, meta.index), st,
                                  behavior_parent(meta, first("Image"), a)], axis=1)
        print("  + %d behaviour features" % (feats[np.inf].shape[1] - 32), flush=True)
    return feats, meta


def load_features(raw, no_harness=False, behavior=False):
    feats, meta = prefix_features(raw, behavior)
    h = meta.harness.values
    print("harness processes: %d of %d (label 1: %d, label 0: %d)%s"
          % (h.sum(), len(h), (h & (meta.label == 1)).sum(), (h & (meta.label == 0)).sum(),
             " -> dropped" if no_harness else ""), flush=True)
    if no_harness:
        feats = {a: f[~h] for a, f in feats.items()}
        meta = meta[~h]
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
    H = lambda img, c, pc="": bool(harness_mask(pd.Series([img]), pd.Series([c]), pd.Series([pc]))[0])
    assert H("/usr/bin/pwsh", "pwsh -NoProfile -Command Import-Module '/opt/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1'")
    assert H("/usr/bin/bash", "bash /tmp/lab_sandbox/run_atomic.sh T1082 3")
    assert H("/usr/bin/hostname", "hostname", "pwsh -NoProfile -Command Import-Module Invoke-AtomicRedTeam")
    assert H(r"C:\Windows\System32\cmd.exe", r'"C:\Windows\system32\cmd.exe" /c IF EXIST "%temp%\x" ( EXIT 0 ) ELSE ( EXIT 1 )')
    assert H(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile')
    assert not H(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 r'"powershell.exe" & {Compress-Archive -Path C:\x -DestinationPath $env:TEMP\a.zip}')
    assert H("/usr/bin/sudo", "sudo cp /vagrant/scenarios/botnet.sh /tmp/lab_sandbox/")
    assert H("/usr/bin/dash", "/bin/sh /etc/update-motd.d/00-header")
    assert H("/usr/bin/mkdir", "mkdir -p /tmp/lab_sandbox/trojan") and H("/usr/bin/sudo", "sudo mkdir -p /tmp/lab_sandbox")
    assert H("/usr/bin/mkdir", "mkdir -p /tmp/benign_admin/reports")
    assert not H("/usr/bin/sh", "sh -c whoami", "pwsh -NoProfile -Command Import-Module Invoke-AtomicRedTeam")
    assert not H("/usr/bin/openssl", "openssl enc -aes-256-cbc -in /tmp/lab_sandbox/victim_files/a.txt")
    mm = pd.DataFrame(dict(pkey=["p", "p", "p", None], start=[t0 + pd.Timedelta(seconds=s) for s in (0, 1, 50, 0)]),
                      index=["a", "b", "c", "d"])
    bp = behavior_parent(mm, pd.Series(["/bin/rm", "/bin/rm", "/bin/ls", "/bin/x"], index=mm.index), 5)
    assert bp.b_sib_spawned.tolist() == [2, 2, 3, 0], bp
    assert bp.b_sib_same_image.tolist() == [2, 2, 1, 0] and bp.b_sib_images.tolist() == [1, 1, 2, 0], bp
    assert (bp.b_sib_period_cv == -1).all(), bp
    bm = pd.DataFrame(dict(pkey="p", start=[t0 + pd.Timedelta(seconds=s) for s in (0, 10, 20, 30)]), index=list("wxyz"))
    bb = behavior_parent(bm, pd.Series(["/usr/bin/curl"] * 4, index=bm.index), 1e9)
    assert bb.b_sib_period_cv.tolist() == [0.0] * 4 and bb.b_sib_period_s.tolist() == [10.0] * 4, bb
    assert _entropy("aaaa") == 0.0 and abs(_entropy("ab") - 1.0) < 1e-9
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
    ap.add_argument("--no-harness", action="store_true",
                    help="drop lab-harness processes (ART engine, launchers, helpers) from training and test")
    ap.add_argument("--behavior", action="store_true", help="add the b_* behaviour features to the 32 paper features")
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
        feats, meta = load_features(raw, a.no_harness, a.behavior)
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
    feats, meta = load_features(raw, a.no_harness, a.behavior)
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

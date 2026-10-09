# -*- coding: utf-8 -*-
r"""
live_detector.py - raise alerts while an attack is running.

    Linux  : VM -> Sysmon -> rsyslog            -> TCP 5514 -> log_receiver.py -> logs/<session>.log
    Windows: VM -> Sysmon -> stream_sysmon.ps1  -> TCP 5514 -> log_receiver.py -> logs/<session>.log
                                                                  |
                                                     live_detector.py (tails the file)

Every CHECK_S seconds of event time it recomputes, for what each process has done so far,
the same features replay_detect.py uses (32 paper features + 21 b_* behaviour features),
skips lab-harness processes (replay_detect.harness_mask), scores the changed processes with
a Random Forest trained on process prefixes, and applies the host-window rule:
    alert once >= N processes are flagged within W seconds, then stay quiet W seconds
Alerts are printed and appended to logs/alerts.jsonl (one JSON object per alert).

usage:
    python host/live_detector.py --train                               # models/live_rf.joblib
    python host/live_detector.py --train --exclude-run trojan_win_120449   # hold runs out for a fair test
    python host/live_detector.py --follow latest --platform windows    # newest log in host/logs, live
    python host/live_detector.py --replay host/logs_win/<run>.xml --platform windows   # offline

Windows live feed: start the forwarder inside the VM as SYSTEM (WinRM kills its children), e.g.
    vagrant winrm wintarget -c "schtasks /create /tn LabSysmonStream /sc once /st 00:00 /ru SYSTEM /f /tr 'powershell -ExecutionPolicy Bypass -File C:\vagrant\scenarios_win\stream_sysmon.ps1'; schtasks /run /tn LabSysmonStream"
with python host/log_receiver.py --session <name> running on the host.

Default thresholds per OS come from reference/replay_v2_final (no harness + behaviour, P3 = unseen
scenario, W 300 s, N 1): Windows thr 0.99 -> 5/5 detected, 3.8 false alarms/h on unseen benign;
Linux thr 0.90 -> 3/5, 7.4 false alarms/h. Linux detection is weak - see progression.csv there.
"""
import argparse, glob, json, os, re, sys, time
from collections import defaultdict
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
import joblib
import numpy as np
import pandas as pd
import revised_experiments as rx
import replay_detect as rd
from compare_nlme import classify
from parse_sysmon import parse_line

MODEL = os.path.join(_ROOT, "models", "live_rf.joblib")
ALERTS = os.path.join(_HERE, "logs", "alerts.jsonl")
CHECK_S = 5
DEFAULT_THR = {"windows": 0.99, "linux": 0.90}
KEEP = ["EventID", "UtcTime", "ProcessGuid", "ParentProcessGuid", "Image", "CommandLine",
        "ParentImage", "ParentCommandLine", "TargetFilename", "DestinationIp", "DestinationPort",
        "TargetObject", "Device"]


def train(platforms, exclude):
    raw, _ = rx.load()
    raw = raw[raw.platform.isin(platforms) & ~raw.run_id.str.contains("|".join(exclude) if exclude else "^$")]
    feats, meta = rd.load_features(raw, no_harness=True, behavior=True)
    X = np.vstack([feats[a].values for a in rd.AGES])
    y = np.concatenate([meta.label.values] * len(rd.AGES))
    rf = dict(rx.supervised())["Random Forest"].fit(X, y)
    os.makedirs(os.path.dirname(MODEL), exist_ok=True)
    joblib.dump(dict(rf=rf, columns=list(feats[np.inf].columns), platforms=platforms, behavior=True,
                     trained_on=sorted(meta.run.unique())), MODEL)
    print("saved %s  (%d processes x %d ages, %d runs, excluded: %s)"
          % (MODEL, len(meta), len(rd.AGES), meta.run.nunique(), ", ".join(exclude) or "none"))


class Detector:
    def __init__(self, model, platform, thr, window, min_procs, out):
        self.rf, self.cols, self.behavior = model["rf"], model["columns"], model.get("behavior", False)
        self.platform, self.thr, self.W, self.N, self.out = platform, thr, window, min_procs, out
        self.rows = []                 # ponytail: keeps every event; recompute is O(events) per scan,
        self.dirty = set()             # fine for one run (~20k events). Drop finished processes if it runs for hours.
        self.flagged = {}              # key -> info of first flag
        self.recent = []               # (t, key) flags, for the window rule
        self.clock = None
        self.next_scan = None
        self.last_alert = -np.inf
        self.alerts = 0

    def add(self, row):
        r = {k: row.get(k, "") for k in KEEP}
        if not r["ProcessGuid"] or r["ProcessGuid"] == rx.NULL_GUID:
            return
        t = pd.Timestamp(r["UtcTime"]) if r["UtcTime"] else None
        if t is None or pd.isna(t):
            return
        self.rows.append(r)
        self.dirty.add(r["ProcessGuid"])
        self.clock = t if self.clock is None else max(self.clock, t)
        if self.next_scan is None:
            self.next_scan = self.clock + pd.Timedelta(seconds=CHECK_S)
        if self.clock >= self.next_scan:
            self.scan()
            self.next_scan = self.clock + pd.Timedelta(seconds=CHECK_S)

    def scan(self):
        if not self.dirty:
            return
        df = pd.DataFrame(self.rows).replace("", np.nan)
        df["EventID"] = pd.to_numeric(df.EventID, errors="coerce")
        df = df.assign(platform=self.platform, run_id="live", session="live", label=0)
        fs, meta = rd.prefix_features(df, behavior=self.behavior, ages=[np.inf], quiet=True)
        feats = fs[np.inf]
        keys = ["%s|live|%s" % (self.platform, g) for g in self.dirty - set(self.flagged)]
        keys = [k for k in keys if k in feats.index and not meta.harness[k]]   # never alert on the lab harness
        self.dirty.clear()
        if not keys:
            return
        p = self.rf.predict_proba(feats.loc[keys, self.cols].values)[:, 1]
        img = df.groupby("ProcessGuid").Image.first()
        img.index = "%s|live|" % self.platform + img.index
        par, img = meta.pkey.to_dict(), img.to_dict()
        now = (self.clock - pd.Timestamp(0)).total_seconds()
        for k, s in zip(keys, p):
            if s < self.thr:
                continue
            guid = k.split("|", 2)[2]
            ev = df[df.ProcessGuid == guid]
            first = ev.iloc[0]
            hit = None
            for r in ev.fillna("").astype(str).to_dict("records"):
                hit = classify(r)
                if hit:
                    break
            self.flagged[guid] = dict(time=str(self.clock), score=round(float(s), 3),
                                      image=_first(ev.Image), cmd=_first(ev.CommandLine)[:200],
                                      parent=_first(ev.ParentImage), lineage=_chain(par, img, k),
                                      evidence=("%s: %s" % hit[1:]) if hit else "")
            self.recent.append((now, guid))
        self.recent = [(t, g) for t, g in self.recent if t > now - self.W]
        if len(self.recent) >= self.N and now - self.last_alert >= self.W:
            self.last_alert = now
            self.alert([self.flagged[g] for _, g in self.recent])

    def alert(self, procs):
        self.alerts += 1
        a = dict(alert=self.alerts, time=str(self.clock), platform=self.platform,
                 rule="%d+ processes flagged within %ds (thr %.2f)" % (self.N, self.W, self.thr),
                 n_flagged=len(procs), processes=sorted(procs, key=lambda d: -d["score"])[:10])
        print("\n\033[91m[ALERT %d] %s  %s\033[0m" % (a["alert"], a["time"], a["rule"]))
        for d in a["processes"][:5]:
            print("   %.2f  %-28s %s" % (d["score"], d["image"][-28:], d["cmd"][:90]))
            if d["evidence"]:
                print("         evidence: %s" % d["evidence"][:110])
            print("         lineage : %s" % d["lineage"])
        with open(self.out, "a", encoding="utf-8") as f:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")


def _first(s):
    s = s.dropna()
    return str(s.iloc[0]) if len(s) else ""


def _chain(par, img, k, n=6):
    """process < parent < grandparent ... by image name"""
    out = []
    while k in img and len(out) < n:
        out.append(re.split(r"[\\/]", str(img[k]))[-1] or "?")
        k = par.get(k)
    return " < ".join(out)


def lines(path, follow):
    with open(path, encoding="utf-8", errors="replace") as f:
        while True:
            line = f.readline()
            if line:
                yield line
            elif not follow:
                return
            else:
                time.sleep(0.5)


def main():
    sys.stdout.reconfigure(line_buffering=True)   # alerts must show up live when stdout is a file/pipe
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true", help="train models/live_rf.joblib and exit")
    ap.add_argument("--train-platforms", default="linux,windows")
    ap.add_argument("--exclude-run", nargs="*", default=[], help="run_id substrings left out of --train")
    ap.add_argument("--merged", default="merged_dataset_v2.csv", help="merged CSV inside host/dataset used by --train")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--follow", help="log file to tail, or 'latest'")
    g.add_argument("--replay", help="log file to read once, as fast as possible")
    ap.add_argument("--platform", default="linux", choices=["linux", "windows"])
    ap.add_argument("--thr", type=float, help="RF probability to flag a process (default per OS, see docstring)")
    ap.add_argument("--window", type=int, default=300, help="W seconds")
    ap.add_argument("--min-procs", type=int, default=1, help="N flagged processes within W")
    ap.add_argument("--out", default=ALERTS)
    a = ap.parse_args()
    rx.MERGED = a.merged
    if a.train:
        return train(a.train_platforms.split(","), a.exclude_run)
    if not os.path.exists(MODEL):
        sys.exit("no model at %s - run with --train first" % MODEL)
    path = a.follow or a.replay
    if not path:
        ap.error("--follow or --replay is required")
    if a.thr is None:
        a.thr = DEFAULT_THR[a.platform]
    if path == "latest":
        path = max(glob.glob(os.path.join(_HERE, "logs", "*.log")), key=os.path.getmtime)
    model = joblib.load(MODEL)
    session = os.path.splitext(os.path.basename(path))[0]
    if any(session in r or r in session for r in model["trained_on"]):
        print("!! %s is in the model's training data - alerts on it say nothing about detection" % session)
    det = Detector(model, a.platform, a.thr, a.window, a.min_procs, a.out)
    print("[live] %s  model=%s  rule: %d+ flagged in %ds, thr %.2f  -> %s"
          % (path, os.path.basename(MODEL), a.min_procs, a.window, a.thr, a.out))
    n = 0
    src = lines(path, follow=bool(a.follow))
    if a.replay:
        # exported Windows XML is newest-first; replay in event-time order
        src = sorted(src, key=lambda l: (parse_line(l, session, a.platform) or {}).get("UtcTime", ""))
    try:
        for line in src:
            row = parse_line(line, session, a.platform)
            if row:
                det.add(row)
                n += 1
    except KeyboardInterrupt:
        pass
    det.scan()
    print("\n[live] %d events, %d processes flagged, %d alerts" % (n, len(det.flagged), det.alerts))


if __name__ == "__main__":
    main()

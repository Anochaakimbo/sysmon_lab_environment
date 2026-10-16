"""usage: python host/public_sets/splunk_rank.py <folder> models/paper_rf_linux.pkl
Lab Linux model on Splunk attack_data (no labels): per file, rank processes by score and show the top ones,
so we can see whether the attack command is what the model ranks first; plus the flag rate on the Splunk
forwarder / systemd background (processes we know are not the attack)."""
import sys, os, joblib, numpy as np, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import revised_experiments as R
S = sys.argv[1]   # folder with splunk_events.csv; writes splunk_scores.csv there
b = joblib.load(sys.argv[2])  # models/paper_rf_linux.pkl from export_model.py
d = pd.read_csv(os.path.join(S, "splunk_events.csv"), low_memory=False, dtype=str)
d["EventID"] = pd.to_numeric(d.EventID)
d["label"] = 0
for c in ("TargetObject", "Device", "session"):
    if c not in d:
        d[c] = np.nan
d["session"] = "splunk"
f, m, _ = R.aggregate(d)
p = b["model"].predict_proba(f[b["columns"]].values)[:, 1]
first = d.drop_duplicates(["run_id", "ProcessGuid"]).set_index(["run_id", "ProcessGuid"])
key = m.index.str.split("|", n=2)
info = first.reindex(pd.MultiIndex.from_arrays([key.str[1], key.str[2]]))
r = pd.DataFrame(dict(run=m.run.values, score=p, img=info.Image.values, cmd=info.CommandLine.fillna("").str[:110].values))
bg = r.img.fillna("").str.contains(r"^/opt/splunkforwarder|^/usr/lib/systemd|^/lib/systemd|journald|/usr/sbin/rsyslogd|/usr/bin/dbus", regex=True)
print("processes", len(r), "background", bg.sum(), "flagged at 0.5: all %.3f, background %.3f" % ((r.score > .5).mean(), (r[bg].score > .5).mean()))
pd.set_option("display.width", 260); pd.set_option("display.max_colwidth", 115)
for run, g in r.groupby("run", sort=False):
    g = g.sort_values("score", ascending=False)
    print("\n## %s  (%d processes, flagged %d)" % (run.replace("attack_techniques__", ""), len(g), (g.score > .5).sum()))
    print(g.head(3)[["score", "cmd"]].to_string(index=False, header=False))
r.to_csv(os.path.join(S, "splunk_scores.csv"), index=False)

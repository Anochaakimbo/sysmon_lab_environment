"""usage: python host/public_sets/rank_unlabelled.py <events.csv> models/paper_rf_<os>.pkl <scores.csv>
Lab model on an unlabelled public set (Splunk attack_data, OTRF atomic): per file (run_id), rank processes by score
and show the top ones, so we can see whether the attack is what the model ranks first; on Linux also the flag rate
on the Splunk forwarder / systemd background (processes we know are not the attack)."""
import sys, os, joblib, numpy as np, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import revised_experiments as R
b = joblib.load(sys.argv[2])  # models/paper_rf_linux.pkl from export_model.py
d = pd.read_csv(sys.argv[1], low_memory=False, dtype=str)
d["EventID"] = pd.to_numeric(d.EventID)
d["label"] = 0
for c in ("TargetObject", "Device", "session"):
    if c not in d:
        d[c] = np.nan
d["session"] = "public"
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
    top = g.head(3).assign(img=g.img.fillna("").str.split(r"[\/]").str[-1])
    print(top[["score", "img", "cmd"]].to_string(index=False, header=False))
r.to_csv(sys.argv[3], index=False)

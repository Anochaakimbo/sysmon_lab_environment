"""Splunk attack_data Linux Sysmon XML logs -> one lab-schema CSV via the lab parser (parse_sysmon.parse_line)."""
import sys, os, glob, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import parse_sysmon as ps
src, out = sys.argv[1], sys.argv[2]
frames = []
for f in sorted(glob.glob(os.path.join(src, "*.log"))):
    name = os.path.basename(f)[:-4]
    with open(f, encoding="utf-8", errors="replace") as fh:
        rows = [r for r in (ps.parse_line(l, name) for l in fh) if r]
    d = pd.DataFrame(rows)
    if d.empty:
        print("EMPTY", name); continue
    d["run_id"] = name
    frames.append(d)
    pc = d[d.EventID == "1"]
    print("%-75s events %7d procs %6d create %5d hosts %d" % (name[:75], len(d), d.ProcessGuid.nunique(), len(pc), d.computer.nunique()))
d = pd.concat(frames, ignore_index=True)
d["platform"] = "linux"
d.to_csv(out, index=False)
print("total", len(d))

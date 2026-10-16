"""OTRF Security-Datasets atomic Windows host zips (JSON lines, Mordor format) -> one lab-schema CSV.
usage: python host/public_sets/otrf_atomic_convert.py <folder with the downloaded *.zip> <out.csv>
Only the Sysmon channel is kept; run_id = zip name. No labels (the datasets only describe the simulated technique)."""
import sys, os, glob, json, zipfile
import pandas as pd

KEEP = ["EventID", "UtcTime", "ProcessGuid", "ParentProcessGuid", "Image", "CommandLine", "ParentCommandLine",
        "ParentImage", "TargetFilename", "DestinationIp", "DestinationPort", "TargetObject", "Device", "User", "Hostname"]
src, out = sys.argv[1], sys.argv[2]
frames = []
for zp in sorted(glob.glob(os.path.join(src, "*.zip"))):
    rows = []
    with zipfile.ZipFile(zp) as z:
        for name in z.namelist():
            if name.endswith("/") or ".." in name:
                continue
            with z.open(name) as fh:   # read in memory, nothing extracted to disk
                for line in fh:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if "Sysmon" not in str(r.get("Channel", r.get("SourceName", ""))):
                        continue
                    rows.append({k: r.get(k) for k in KEEP})
    d = pd.DataFrame(rows, columns=KEEP)
    d = d[pd.to_numeric(d.EventID, errors="coerce").notna()]
    d["EventID"] = pd.to_numeric(d.EventID).astype(int)
    d = d[d.EventID != 255]
    d["run_id"] = os.path.basename(zp)[:-4]
    print("%-75s sysmon events %7d processes %5d" % (d.run_id.iloc[0][:75] if len(d) else os.path.basename(zp), len(d), d.ProcessGuid.nunique()), flush=True)
    if len(d):
        frames.append(d)
d = pd.concat(frames, ignore_index=True)
d["platform"] = "windows"
d.to_csv(out, index=False)
print("total", d.run_id.nunique(), "files", len(d), "events")

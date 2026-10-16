"""Windows-APT 2025 (Wazuh export) -> lab event schema; label = lineage from the Caldera agents.
label 1: descendant of a Caldera agent; 0: ProcessCreate chain fully visible and never through an agent;
-1 (dropped): no ProcessCreate, or the chain leaves the data through a shell / script host."""
import sys, glob, os, pandas as pd, numpy as np
D, OUT = sys.argv[1], sys.argv[2]
E = "_source.data.win.eventdata."
MAP = dict(processGuid="ProcessGuid", parentProcessGuid="ParentProcessGuid", utcTime="UtcTime", image="Image",
           commandLine="CommandLine", parentCommandLine="ParentCommandLine", parentImage="ParentImage",
           targetFilename="TargetFilename", destinationIp="DestinationIp", destinationPort="DestinationPort",
           targetObject="TargetObject", device="Device", user="User", integrityLevel="IntegrityLevel",
           currentDirectory="CurrentDirectory", hashes="Hashes", eventType="EventType")
fs = sorted(f for f in glob.glob(os.path.join(D, "*.csv")) if "manifest" not in f and "validation" not in f)
d = pd.concat([pd.read_csv(f, low_memory=False, dtype=str) for f in fs], ignore_index=True)
d = d[d["_source.data.win.system.providerName"] == "Microsoft-Windows-Sysmon"]
o = pd.DataFrame({v: d[E + k] if E + k in d else np.nan for k, v in MAP.items()})
o["EventID"] = pd.to_numeric(d["_source.data.win.system.eventID"], errors="coerce")
o["host_name"] = d["_source.agent.name"].values
for c in o.columns:   # Wazuh JSON escaping doubles every backslash
    if c != "EventID" and o[c].notna().any():
        o[c] = o[c].str.replace("\\\\", "\\", regex=False)
o = o[o.EventID != 255].drop_duplicates()
print("sysmon events (no 255, deduplicated)", len(o), o.EventID.value_counts().to_dict())

img = o.Image.str.lower().fillna("")
agent = img.str.endswith("\\users\\public\\splunkd.exe") | img.str.contains(r"\\caldera-agent[^\\]*\.exe$", regex=True)
pi = o.ParentImage.str.lower().fillna("")
pagent = pi.str.endswith("\\users\\public\\splunkd.exe") | pi.str.contains(r"\\caldera-agent[^\\]*\.exe$", regex=True)
roots = set(o.ProcessGuid[agent]) | set(o.ParentProcessGuid[pagent])  # agents seen only as a parent count too
pc = o[o.EventID == 1].drop_duplicates("ProcessGuid").set_index("ProcessGuid")
par, pimg = pc.ParentProcessGuid, pc.ParentImage.str.lower().fillna("")
mal = set(roots)
while True:
    new = set(par.index[par.isin(mal)]) - mal
    if not new:
        break
    mal |= new
SHELL = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
known = set(pc.index)
def status(g, depth=0):
    if g in mal:
        return 1
    if g not in known or depth > 60:
        return -1
    p = par.get(g)
    if p in known:
        return status(p, depth + 1)
    return -1 if pimg.get(g, "").endswith(SHELL) or pimg.get(g, "") == "" else 0
st = {g: status(g) for g in set(o.ProcessGuid.dropna())}
o["label"] = o.ProcessGuid.map(st).fillna(-1).astype(int)
procs = o.drop_duplicates("ProcessGuid")
print("processes", len(procs), "agent roots", len(roots), "label counts", procs.label.value_counts().to_dict())
o = o[o.label >= 0]
procs = procs[procs.label >= 0]
print("kept", len(procs), "processes, label=1 share %.3f" % procs.label.mean())
print(procs.groupby("host_name").label.agg(["size", "mean"]).round(3).to_string())
print("label=0 top images"); print(procs[procs.label == 0].Image.value_counts().head(12).to_string())
print("label=0 top parents"); print(procs[procs.label == 0].ParentImage.value_counts().head(8).to_string())
o.to_csv(OUT, index=False)

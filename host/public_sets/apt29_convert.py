"""OTRF APT29 evals JSON lines -> lab event schema CSV (Sysmon channel only, label not set yet)."""
import sys, json, pandas as pd
src, out = sys.argv[1], sys.argv[2]
KEEP = ["EventID", "UtcTime", "ProcessGuid", "ParentProcessGuid", "Image", "CommandLine", "ParentCommandLine",
        "ParentImage", "TargetFilename", "DestinationIp", "DestinationPort", "TargetObject", "Device", "User",
        "IntegrityLevel", "CurrentDirectory", "Hashes", "EventType", "Hostname"]
rows = []
with open(src, encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        if r.get("Channel") != "Microsoft-Windows-Sysmon/Operational":
            continue
        rows.append({k: r.get(k) for k in KEEP})
d = pd.DataFrame(rows)
d = d[d.EventID != 255]
print(src, "sysmon events", len(d), d.EventID.value_counts().head(12).to_dict())
d.to_csv(out, index=False)

"""Label OTRF APT29 day1/day2 by lineage from the emulation plan's entry points; write one lab-schema CSV.
Roots (MITRE ATT&CK Evals round 2 emulation plan, matched on Image / CommandLine / ParentImage):
day1 RTLO payload cod.3aka3.scr, stego PowerShell (System.Drawing.Bitmap), PsExec service + C:\\Windows\\Temp tools on
NASHUA, persistence javamtsup.exe / hostui; day2 the .lnk PowerShell (2016_United_States_presidential_election),
UAC-bypass PowerShell under control.exe, WMI-persistence PowerShell under WmiPrvSE.exe, kxwn.lock DLL; both days
WinRM wsmprovhost.exe (lateral movement)."""
import sys, pandas as pd
S = sys.argv[1]
IMG = r"3aka3\.scr|\\windows\\temp\\(python|sdelete64|rar)\.exe|psexesvc\.exe|javamtsup\.exe|hostui\.(exe|bat)|wsmprovhost\.exe"
CMD = r"system\.drawing\.bitmap|2016_united_states_presidential_election|kxwn\.lock|hostui\.(exe|bat)"
out = []
for day in (1, 2):
    d = pd.read_csv(f"{S}/apt29_day{day}.csv", low_memory=False)
    d["platform"] = "windows"
    d["run_id"] = "day%d_" % day + d.Hostname.str.split(".").str[0]
    img, cmd = d.Image.str.lower().fillna(""), d.CommandLine.str.lower().fillna("")
    pim = d.ParentImage.str.lower().fillna("")
    ps = img.str.endswith("powershell.exe")
    root = (img.str.contains(IMG, regex=True) | cmd.str.contains(CMD, regex=True)
            | (ps & pim.str.endswith(("\\control.exe", "\\wmiprvse.exe"))))
    roots = set(d.ProcessGuid[root])
    pc = d[d.EventID == 1].drop_duplicates("ProcessGuid").set_index("ProcessGuid").ParentProcessGuid
    mal = set(roots)
    while True:
        new = set(pc.index[pc.isin(mal)]) - mal
        if not new:
            break
        mal |= new
    d["label"] = d.ProcessGuid.isin(mal).astype(int)
    p = d.drop_duplicates("ProcessGuid")
    print("day%d processes %d, roots %d, attack %d (%.3f)" % (day, len(p), len(roots), p.label.sum(), p.label.mean()))
    print(p[p.label == 1].groupby("run_id").Image.apply(lambda s: s.str.rsplit("\\", n=1).str[-1].value_counts().head(6).to_dict()).to_string())
    out.append(d)
pd.concat(out, ignore_index=True).to_csv(f"{S}/apt29_events.csv", index=False)

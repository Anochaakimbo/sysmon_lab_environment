"""
compare_nlme.py - เทียบ dataset ที่เราเก็บกับ NLME.csv ของเปเปอร์อ้างอิง
(Achmad et al., Cyber Security and Applications 3, 2025, 100110)

ตอบ 3 คำถามที่ต้องอ้างอิงได้ในธีสิส:

  1. องค์ประกอบ event ของเราใกล้เปเปอร์แค่ไหน  (EventID x สัดส่วน)
  2. event ชนิดไหนแบก signal มัลแวร์  (malicious rate ต่อ EventID เทียบกัน)
  3. event ที่ติด label malicious ของเรา "เป็นพฤติกรรมมัลแวร์จริง" พิสูจน์จากอะไร
     -> map แต่ละแถวกลับไปหา ATT&CK technique ด้วย artifact ที่ test ทิ้งไว้
        (Run key, Scheduled Task, ไฟล์ที่ staging ฯลฯ) แล้วนับให้ดู

ใช้งาน:
    python host/compare_nlme.py host/dataset/<ชื่อ>_labeled.csv
    python host/compare_nlme.py host/dataset/<ชื่อ>_labeled.csv --nlme reference/NLME.csv
"""
import argparse
import collections
import csv
import io
import os
import re
import sys

csv.field_size_limit(10 ** 8)

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

EVENT_NAMES = {
    "1": "ProcessCreate", "2": "FileCreateTime", "3": "NetworkConnect",
    "5": "ProcessTerminate", "8": "CreateRemoteThread", "9": "RawAccessRead",
    "11": "FileCreate", "12": "RegistryAddDelete", "13": "RegistrySetValue",
    "14": "RegistryRename", "23": "FileDelete",
}

# ---------------------------------------------------------------------------
# หลักฐานว่าแถวนี้เกิดจาก technique ไหน
#
# ⚠️ ต้องแมตช์ "แยกคอลัมน์" ห้ามเอาทุกคอลัมน์มาต่อกันแล้วยิง regex เดียว
#    ถ้าต่อกัน คำว่า -ExecutionPolicy ใน CommandLine จะไปโดน regex ของ registry
#    แล้วรายงานว่า RegistrySetValue แถวนั้นเป็น T1112 ทั้งที่มันคือ BAM ของ Windows
#    (พลาดมาแล้ว 23 ส.ค. 2026: T1112 ได้ 549 แถวปลอม)
#
# แบ่งความแรงของหลักฐาน 3 ระดับ:
#   DIRECT  = artifact อยู่ในคอลัมน์ของ event นั้นเอง -> อ้างอิงได้เต็มปาก
#   PARENT  = ตัว event ไม่มี artifact แต่ ParentCommandLine เป็นของ test
#             (เช่น conhost.exe ที่ cmd ของ test spawn ขึ้นมา) -> อ้างได้แบบมีเงื่อนไข
#   OSBOOK  = OS จดของมันเอง เพราะ process เรารัน (BAM, Prefetch, CIT)
#             ไม่ใช่พฤติกรรมมัลแวร์ แต่ก็ไม่ใช่ noise ที่ไม่เกี่ยวข้อง -> ต้องแยกรายงาน
# ---------------------------------------------------------------------------

# (technique, คอลัมน์ที่ยอมรับ, regex)
DIRECT = [
    ("T1547.001 Registry Run Keys", ("TargetObject",),
     r"\\CurrentVersion\\Run(Once)?\\|\\Explorer\\User Shell Folders|\\Winlogon\\(Shell|Userinit)"),
    ("T1053.005 Scheduled Task", ("TargetObject",), r"\\Schedule\\TaskCache\\"),
    ("T1053.005 Scheduled Task", ("CommandLine",), r"\bschtasks(\.exe)?\b"),
    ("T1112 Modify Registry", ("TargetObject",),
     r"\\Policies\\|\\Internet Settings\\|\\PowerShell\\1\\ShellIds|NetWire|Ursnif|\\Zone(Map|s)\\"),
    ("T1036.003 Masquerading", ("TargetFilename", "Image"),
     r"\\(Temp|Roaming|lab_sandbox)\\.*\\?(lsass|taskhostw|svchost|notepad|LSM)\.exe$"),
    ("T1036.003 Masquerading", ("CommandLine",),
     r"copy\s+\S+\s+\S*(lsass|taskhostw|svchost|notepad|LSM)\.exe"),
    ("T1027 Obfuscated Files", ("CommandLine",),
     r"FromBase64String|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|\[Text\.Encoding\]"),
    ("T1074.001 Local Data Staging", ("TargetFilename",),
     r"\\(lab_sandbox|Temp)\\.*\.(zip|7z|rar)$|Discovery\.bat$"),
    ("T1087.001 Account Discovery", ("CommandLine",),
     r"\bnet1?(\.exe)?\s+(user|localgroup|accounts)\b|Get-LocalUser|query\s+user"),
    ("T1082 System Info Discovery", ("Image", "CommandLine"),
     r"\\(systeminfo|hostname|ver)\.exe$|\bsysteminfo\b|\bhostname\b|wmic\s+(os|bios|computersystem)"),
    ("T1057 Process Discovery", ("Image", "CommandLine"),
     r"\\tasklist\.exe$|\btasklist\b|wmic\s+process|Get-Process"),
    ("T1083 File Discovery", ("Image", "CommandLine"),
     r"\\findstr\.exe$|\bdir\b.*\s/s|Get-ChildItem.*-Recurse"),
    ("T1059.001 PowerShell", ("CommandLine",),
     r"powershell(\.exe)?[^\r\n]*\s-(Command|nop|noni|w\s+hidden)|\bIEX\b|Invoke-Expression"),
    ("T1005 Data from Local System", ("CommandLine",), r"Copy-Item[^\r\n]*(Documents|Desktop)"),
]

OSBOOK = [
    ("BAM (Background Activity Moderator)", ("TargetObject",), r"\\Services\\bam\\State\\UserSettings\\"),
    ("Compatibility Assistant / CIT", ("TargetObject",),
     r"\\AppCompatFlags\\|\\Software\\Microsoft\\CIT\\"),
    ("PowerShell startup profile", ("TargetFilename",),
     r"StartupProfileData|__PSScriptPolicyTest_|ModuleAnalysisCache"),
    ("Prefetch", ("TargetFilename",), r"\\Prefetch\\.*\.pf$"),
]

DIRECT = [(n, cols, re.compile(rx, re.I)) for n, cols, rx in DIRECT]
OSBOOK = [(n, cols, re.compile(rx, re.I)) for n, cols, rx in OSBOOK]

# regex ชุดเดียวกันแต่ยิงใส่ ParentCommandLine (หลักฐานระดับ PARENT)
PARENT_RX = [(n, re.compile(rx.pattern, re.I)) for n, cols, rx in DIRECT if "CommandLine" in cols]


def classify(row):
    """คืน (ระดับ, ชื่อ, ข้อความหลักฐาน) หรือ None"""
    for name, cols, rx in DIRECT:
        for c in cols:
            v = row.get(c) or ""
            if v and rx.search(v):
                return ("DIRECT", name, f"{c}={v[:88]}")
    for name, cols, rx in OSBOOK:
        for c in cols:
            v = row.get(c) or ""
            if v and rx.search(v):
                return ("OSBOOK", name, f"{c}={v[:88]}")
    pc = row.get("ParentCommandLine") or ""
    if pc:
        for name, rx in PARENT_RX:
            if rx.search(pc):
                return ("PARENT", name, f"ParentCommandLine={pc[:80]}")
    return None


def load(path, is_nlme=False):
    eid = collections.Counter()
    cross = collections.Counter()
    rows = []
    with io.open(path, encoding="utf-8", errors="replace", newline="") as f:
        for r in csv.DictReader(f):
            e = (r.get("EventID") or "").strip()
            l = (r.get("label") or "").strip()
            if not e:
                continue
            eid[e] += 1
            cross[(e, l)] += 1
            if not is_nlme:
                rows.append(r)
    return eid, cross, rows


def pct(a, b):
    return (a * 100.0 / b) if b else 0.0


def table(title, eid, cross, total):
    print(f"\n{title}")
    print(f"  {'ID':>4}  {'event':<20} {'รวม':>9} {'%':>6}   {'mal':>8} {'%mal':>6}")
    print("  " + "-" * 62)
    for e, n in sorted(eid.items(), key=lambda x: -x[1]):
        m = cross[(e, "1")]
        print(f"  {e:>4}  {EVENT_NAMES.get(e, '?'):<20} {n:>9,} {pct(n,total):>5.1f}%"
              f"   {m:>8,} {pct(m,n):>5.1f}%")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("labeled", help="*_labeled.csv ของเรา")
    ap.add_argument("--nlme", default="reference/NLME.csv")
    ap.add_argument("--top", type=int, default=6, help="จำนวนตัวอย่างหลักฐานต่อ technique")
    args = ap.parse_args()

    if not os.path.exists(args.nlme):
        print(f"[!] ไม่พบ {args.nlme} (reference/ ถูก gitignore - ต้องมีไฟล์เอง)")
        return 1

    print("=" * 66)
    print("  เทียบ dataset ของเรา กับ NLME.csv (เปเปอร์อ้างอิง)")
    print("=" * 66)

    n_eid, n_cross, _ = load(args.nlme, is_nlme=True)
    o_eid, o_cross, o_rows = load(args.labeled)
    n_tot, o_tot = sum(n_eid.values()), sum(o_eid.values())

    table(f"[เปเปอร์] {args.nlme}  ({n_tot:,} แถว)", n_eid, n_cross, n_tot)
    table(f"[ของเรา]  {os.path.basename(args.labeled)}  ({o_tot:,} แถว)", o_eid, o_cross, o_tot)

    # ---- 1) องค์ประกอบต่างกันแค่ไหน ----
    print("\n" + "=" * 66)
    print("  1) องค์ประกอบ event ต่างกันกี่จุดเปอร์เซ็นต์")
    print("=" * 66)
    diff = 0.0
    for e in sorted(set(n_eid) | set(o_eid), key=lambda x: -(o_eid[x] + n_eid[x])):
        a, b = pct(n_eid[e], n_tot), pct(o_eid[e], o_tot)
        diff += abs(a - b)
        flag = "  <<" if abs(a - b) >= 10 else ""
        print(f"  {e:>4} {EVENT_NAMES.get(e,'?'):<20} เปเปอร์ {a:>5.1f}%   เรา {b:>5.1f}%"
              f"   ต่าง {b-a:+6.1f}{flag}")
    print(f"\n  ผลรวมความต่างสัมบูรณ์ = {diff:.1f} จุด (0 = องค์ประกอบเหมือนกันเป๊ะ, 200 = ไม่ทับกันเลย)")

    # ---- 2) event ไหนแบก signal ----
    print("\n" + "=" * 66)
    print("  2) event ชนิดไหนแบก signal มัลแวร์ (malicious rate)")
    print("=" * 66)
    for e in sorted(set(n_eid) & set(o_eid), key=lambda x: -n_eid[x]):
        a = pct(n_cross[(e, "1")], n_eid[e])
        b = pct(o_cross[(e, "1")], o_eid[e])
        print(f"  {e:>4} {EVENT_NAMES.get(e,'?'):<20} เปเปอร์ {a:>5.1f}%   เรา {b:>5.1f}%")
    only_o = sorted(set(o_eid) - set(n_eid), key=lambda x: -o_eid[x])
    if only_o:
        print("\n  event ที่เรามีแต่เปเปอร์ไม่มี: "
              + ", ".join(f"{e}={EVENT_NAMES.get(e,'?')}({o_eid[e]:,})" for e in only_o))

    # ---- 3) หลักฐานว่าเป็นพฤติกรรมมัลแวร์จริง ----
    print("\n" + "=" * 66)
    print("  3) แถว malicious ของเรา พิสูจน์ได้แค่ไหนว่าเป็นพฤติกรรมมัลแวร์")
    print("=" * 66)

    tier = collections.Counter()
    hit = collections.Counter()
    samples = collections.defaultdict(list)
    mal = 0
    for r in o_rows:
        if r.get("label") != "1":
            continue
        mal += 1
        res = classify(r)
        if res is None:
            tier["LINEAGE"] += 1
            continue
        lvl, name, ev = res
        tier[lvl] += 1
        hit[(lvl, name)] += 1
        if len(samples[(lvl, name)]) < args.top:
            samples[(lvl, name)].append(f"[{EVENT_NAMES.get(r['EventID'],'?')}] {ev}")

    print(f"\n  แถว malicious ทั้งหมด {mal:,}\n")
    legend = {
        "DIRECT":  "artifact อยู่ในคอลัมน์ของ event นั้นเอง -> อ้างอิงได้เต็มปาก",
        "PARENT":  "ตัว event ไม่มี artifact แต่ parent เป็นคำสั่งของ test",
        "OSBOOK":  "OS จดของมันเองเพราะ process เรารัน (ไม่ใช่พฤติกรรมมัลแวร์)",
        "LINEAGE": "ไม่มีหลักฐานในตัว event ติด label เพราะสายเลือดล้วนๆ",
    }
    for k in ("DIRECT", "PARENT", "OSBOOK", "LINEAGE"):
        v = tier[k]
        print(f"  {k:<8} {v:>7,} ({pct(v, mal):5.1f}%)  {legend[k]}")

    for lvl in ("DIRECT", "PARENT", "OSBOOK"):
        rows_ = [(n, v) for (l, n), v in hit.items() if l == lvl]
        if not rows_:
            continue
        print(f"\n  ---- {lvl} ----")
        for name, v in sorted(rows_, key=lambda x: -x[1]):
            print(f"  {name:<38} {v:>6,}")
            for s in samples[(lvl, name)]:
                print(f"      {s}")

    print("\n  " + "-" * 62)
    print(f"  สรุปสำหรับธีสิส: จาก {mal:,} แถวที่ label=1")
    print(f"    {tier['DIRECT']:,} แถว ({pct(tier['DIRECT'],mal):.1f}%) ยืนยันได้จาก artifact ของ event เอง")
    print(f"    {tier['PARENT']:,} แถว ({pct(tier['PARENT'],mal):.1f}%) ยืนยันผ่าน parent command")
    print(f"    {tier['OSBOOK']:,} แถว ({pct(tier['OSBOOK'],mal):.1f}%) เป็นการจดของ OS ไม่ใช่พฤติกรรมมัลแวร์")
    print(f"    {tier['LINEAGE']:,} แถว ({pct(tier['LINEAGE'],mal):.1f}%) มาจาก lineage อย่างเดียว")
    print("  ตัวเลข 2 กลุ่มท้ายต้องรายงานตรงๆ ไม่ใช่นับรวมเป็น 'มัลแวร์' ทั้งหมด")
    return 0


if __name__ == "__main__":
    sys.exit(main())

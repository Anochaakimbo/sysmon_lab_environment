"""
parse_sysmon.py - แปลง Sysmon for Linux syslog -> CSV (แถวละ event)

รูปแบบ input (จาก log_receiver.py):
    <recv_ts>\t<host_ip>\t<14>Aug 16 16:23:18 target1 sysmon: <Event>...</Event>

ใช้งาน:
    python parse_sysmon.py logs/phase1_test.log -o dataset/events.csv
    python parse_sysmon.py logs/*.log -o dataset/events.csv --session benign_01
"""

# บังคับ utf-8 ก่อนพิมพ์อะไรก็ตาม
# console เริ่มต้นของ Windows เป็น cp1252 -> print ภาษาไทยแล้ว process ตายทันที
# 23 ส.ค. 2026: c2_server.py และ mining_pool.py ล้มด้วยเหตุนี้ พอร์ตไม่ขึ้น
# scenario เลย beacon ไม่ติดโดยดูเหมือนทำงานปกติ - ต้องมีทุกไฟล์ที่มีเอาต์พุตไทย
import os as _os
import sys as _sys

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
_os.environ.setdefault("PYTHONUTF8", "1")
for _stream in (_sys.stdout, _sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import argparse
import csv
import glob
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------- schema
# ลำดับคอลัมน์: metadata -> common -> ProcessCreate -> Network -> File -> lineage
META_COLS = [
    "recv_timestamp",   # เวลาที่ host รับ (จาก log_receiver)
    "host_ip",          # IP ของ VM ที่ส่งมา
    "session",          # ชื่อ session / scenario
    "record_id",        # EventRecordID - เรียงลำดับได้
]

COMMON_COLS = [
    "EventID",
    "event_name",
    "computer",
    "UtcTime",
    "RuleName",
    "ProcessGuid",
    "ProcessId",
    "Image",
    "User",
]

PROCESS_COLS = [
    "CommandLine",
    "CurrentDirectory",
    "Hashes",
    "LogonGuid",
    "LogonId",
    "TerminalSessionId",
    "IntegrityLevel",
    "FileVersion",
    "Description",
    "Product",
    "Company",
    "OriginalFileName",
    "ParentProcessGuid",
    "ParentProcessId",
    "ParentImage",
    "ParentCommandLine",
    "ParentUser",
]

NETWORK_COLS = [
    "Protocol",
    "Initiated",
    "SourceIsIpv6",
    "SourceIp",
    "SourceHostname",
    "SourcePort",
    "SourcePortName",
    "DestinationIsIpv6",
    "DestinationIp",
    "DestinationHostname",
    "DestinationPort",
    "DestinationPortName",
]

FILE_COLS = [
    "TargetFilename",
    "CreationUtcTime",
    "IsExecutable",
    "Archived",
    "Device",
]

# คอลัมน์เฉพาะ Windows (event ที่ Linux ไม่มี) - ตามเปเปอร์ NLME.csv
# Linux dataset จะเว้นว่างคอลัมน์เหล่านี้ -> ตอน merge (แนวทาง B) จะถูก drop
WINDOWS_COLS = [
    "TargetObject",           # Registry(12/13) + RawAccessRead
    "EventType",              # Registry + FileDelete
    "Details",                # RegistrySet(13)
    "NewName",                # RegistryRename
    "PreviousCreationUtcTime",  # FileCreateTime(2)
    "ImageLoaded",            # ImageLoad(7)
    "Signature",             # ImageLoad/DriverLoad
    "SignatureStatus",
    "Signed",
    "SourceImage",           # ProcessAccess(10)/CreateRemoteThread(8)
    "SourceProcessGuid",
    "TargetImage",           # ProcessAccess/CreateRemoteThread
    "TargetProcessGuid",
    "GrantedAccess",         # ProcessAccess(10)
    "CallTrace",
    "StartAddress",          # CreateRemoteThread(8)
    "StartFunction",
    "StartModule",
    "NewThreadId",
    "QueryName",             # DnsQuery(22)
    "QueryStatus",
    "QueryResults",
    "PipeName",              # PipeEvent(17/18)
]

DERIVED_COLS = [
    "parent_known",     # 1 ถ้า ParentProcessGuid ไม่ใช่ all-zero
    "label",            # 0=benign 1=malicious (เติมในขั้น labeling)
]

ALL_COLS = (META_COLS + COMMON_COLS + PROCESS_COLS + NETWORK_COLS
            + FILE_COLS + WINDOWS_COLS + DERIVED_COLS)

EVENT_NAMES = {
    "1": "ProcessCreate",
    "2": "FileCreateTime",       # Windows
    "3": "NetworkConnect",
    "5": "ProcessTerminate",
    "6": "DriverLoad",           # Windows
    "7": "ImageLoad",            # Windows
    "8": "CreateRemoteThread",   # Windows
    "9": "RawAccessRead",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "12": "RegistryAddDelete",   # Windows
    "13": "RegistrySetValue",    # Windows
    "14": "RegistryRename",      # Windows
    "15": "FileCreateStreamHash",  # Windows
    "16": "SysmonConfigChange",
    "17": "PipeCreated",         # Windows
    "18": "PipeConnected",       # Windows
    "22": "DnsQuery",
    "23": "FileDelete",
}

NULL_GUID = "{00000000-0000-0000-0000-000000000000}"

# ---------------------------------------------------------------- regex
RE_EVENTID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")  # Windows อาจมี Qualifiers attr
RE_RECORDID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
RE_COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
# Windows: <TimeCreated SystemTime='2026-...Z'/> ใช้แทน host recv time
RE_TIMECREATED = re.compile(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]")
RE_FIELD = re.compile(r'Name=["\']([^"\']+)["\']>([^<]*)</Data>')
RE_FIELD_EMPTY = re.compile(r'Name=["\']([^"\']+)["\']\s*/>')

# XML entity ที่ต้อง unescape
ENTITIES = {
    "&lt;": "<", "&gt;": ">", "&amp;": "&",
    "&quot;": '"', "&apos;": "'", "&#13;": "", "&#10;": " ",
}


def unescape(s):
    for k, v in ENTITIES.items():
        s = s.replace(k, v)
    return s


def clean(val):
    """แปลง '-' เป็นค่าว่าง เพื่อให้ pandas มองเป็น NaN ได้"""
    v = unescape(val).strip()
    return "" if v == "-" else v


def parse_line(line, session, platform="linux"):
    """แปลง 1 บรรทัด -> dict หรือ None ถ้าไม่ใช่ Sysmon event
    platform: linux = syslog (มี tab prefix) / windows = XML ตรงๆ (จาก export)"""
    line = line.lstrip("﻿")   # strip BOM (Windows export บรรทัดแรก)
    m_eid = RE_EVENTID.search(line)
    if not m_eid:
        return None

    if platform == "windows":
        # Windows export ไม่มี tab prefix - ทั้งบรรทัดคือ XML
        # ใช้ TimeCreated SystemTime แทน host recv time (ไม่มี syslog)
        payload = line
        host_ip = ""
        m_tc = RE_TIMECREATED.search(payload)
        recv_ts = m_tc.group(1) if m_tc else ""
    else:
        # Linux: <recv_ts>\t<host_ip>\t<payload>
        parts = line.split("\t", 2)
        if len(parts) >= 3:
            recv_ts, host_ip, payload = parts[0], parts[1], parts[2]
        else:
            recv_ts, host_ip, payload = "", "", line

    row = {c: "" for c in ALL_COLS}
    row["recv_timestamp"] = recv_ts
    row["host_ip"] = host_ip
    row["session"] = session

    eid = m_eid.group(1)

    # EventID 255 = ข้อความ error ภายในของ Sysmon เอง ไม่ใช่ telemetry ของเครื่อง
    # (23 ส.ค. 2026: 2,838 แถวจาก 118,796 เป็นข้อความ
    #  'The "C:\Sysmon\\" owner is not System. Archiving is disabled.' ซ้ำๆ
    #  ยิงทุกครั้งที่มี FileDelete - field อื่นว่างหมด ทำให้ dataset เพี้ยน)
    if eid == "255":
        return None

    row["EventID"] = eid
    row["event_name"] = EVENT_NAMES.get(eid, f"Unknown_{eid}")

    m = RE_RECORDID.search(payload)
    if m:
        row["record_id"] = m.group(1)
    m = RE_COMPUTER.search(payload)
    if m:
        row["computer"] = m.group(1)

    # ดึง field ทั้งหมดจาก EventData
    for name, val in RE_FIELD.findall(payload):
        if name in row:
            row[name] = clean(val)
    # field แบบ self-closing tag (<Data Name="X"/>) = ว่าง
    for name in RE_FIELD_EMPTY.findall(payload):
        if name in row and not row[name]:
            row[name] = ""

    # derived
    ppg = row.get("ParentProcessGuid", "")
    row["parent_known"] = "1" if (ppg and ppg != NULL_GUID) else "0"

    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="ไฟล์ log (รองรับ wildcard)")
    ap.add_argument("-o", "--output", default="dataset/events.csv")
    ap.add_argument("--session", default=None,
                    help="ชื่อ session (default = ใช้ชื่อไฟล์)")
    ap.add_argument("--platform", choices=["linux", "windows"], default="linux",
                    help="linux = syslog / windows = Sysmon Event XML (จาก export)")
    args = ap.parse_args()

    # ขยาย wildcard เอง (Windows shell ไม่ทำให้)
    files = []
    for pat in args.inputs:
        matched = glob.glob(pat)
        files.extend(matched if matched else [pat])

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    stats = Counter()
    field_fill = Counter()
    rows_written = 0

    with open(out_path, "w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=ALL_COLS)
        writer.writeheader()

        for fpath in files:
            p = Path(fpath)
            if not p.exists():
                print(f"[!] ไม่พบไฟล์: {fpath}", file=sys.stderr)
                continue
            session = args.session or p.stem
            print(f"[*] อ่าน {p.name}  (session={session})")

            with open(p, encoding="utf-8", errors="replace") as fin:
                for line in fin:
                    row = parse_line(line, session, args.platform)
                    if row is None:
                        stats["skipped"] += 1
                        continue
                    writer.writerow(row)
                    rows_written += 1
                    stats[row["event_name"]] += 1
                    for c in ALL_COLS:
                        if row[c] != "":
                            field_fill[c] += 1

    # ---------------- รายงาน ----------------
    print(f"\n{'='*62}")
    print(f"  เขียนแล้ว: {out_path}  ({rows_written:,} แถว x {len(ALL_COLS)} คอลัมน์)")
    print(f"{'='*62}")

    print("\nEVENT ที่พบ:")
    for name, cnt in stats.most_common():
        if name == "skipped":
            continue
        pct = cnt / rows_written * 100 if rows_written else 0
        print(f"  {name:<22} {cnt:>8,}  ({pct:5.1f}%)")
    if stats["skipped"]:
        print(f"  (ข้ามบรรทัดที่ไม่ใช่ event: {stats['skipped']:,})")

    print("\nความสมบูรณ์ของคอลัมน์ (fill rate):")
    empty_cols = []
    for c in ALL_COLS:
        n = field_fill[c]
        pct = n / rows_written * 100 if rows_written else 0
        if n == 0:
            empty_cols.append(c)
        else:
            print(f"  {c:<24} {n:>8,}  ({pct:5.1f}%)")

    if empty_cols:
        print(f"\n  คอลัมน์ที่ว่างทั้งหมด ({len(empty_cols)} ตัว) - พิจารณาตัดทิ้ง:")
        for c in empty_cols:
            print(f"    - {c}")

    usable = len(ALL_COLS) - len(empty_cols)
    print(f"\n  => คอลัมน์ที่มีข้อมูล: {usable}/{len(ALL_COLS)}")


if __name__ == "__main__":
    main()
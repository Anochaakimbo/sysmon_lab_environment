"""
merge_dataset.py - รวม *_labeled.csv ทุก session เป็นก้อนเดียวสำหรับเทรนโมเดล

ใช้งาน:
    python merge_dataset.py                          # รวมทุกไฟล์ใน dataset/
    python merge_dataset.py -o dataset/merged.csv
    python merge_dataset.py --exclude smoke_ransom   # ตัด session ที่ไม่สมบูรณ์

สิ่งที่สคริปต์นี้ตรวจให้ (กันได้ผลลัพธ์สวยแบบหลอกๆ):
  1. schema ตรงกันทุกไฟล์ไหม
  2. sensor-era mismatch - session ไหน "ไม่มี event ชนิดที่ session อื่นมี" เลย
     (เกิดตอนแก้บั๊ก sensor กลางคัน เช่น eBPF probe ค้างทำให้ FileCreate หายทั้งรอบ)
     ถ้าปล่อยไว้ โมเดลจะเรียน "ไม่มี FileCreate = รอบเก่า" แทนที่จะเรียนพฤติกรรมมัลแวร์
  3. hostname leakage - VM ไหนถือ label เดียวล้วน
  4. enrichment leakage - CommandLine ว่าง ทำนาย label ได้แค่ไหน
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
import sys
from collections import Counter, defaultdict
from pathlib import Path

DATASET_DIR = Path(__file__).resolve().parent / "dataset"

EVENT_NAMES = {
    "1": "ProcessCreate", "3": "NetworkConnect", "4": "ServiceState",
    "5": "ProcessTerminate", "9": "RawAccessRead", "10": "ProcessAccess",
    "11": "FileCreate", "16": "ConfigChange", "23": "FileDelete",
}

# ห้ามใช้เป็น feature - เก็บไว้ใน CSV เพื่อ trace ได้ แต่ต้อง drop ก่อน fit()
DROP_BEFORE_FIT = [
    "recv_timestamp", "record_id", "session", "run_id", "computer", "host_ip",
    "ProcessGuid", "LogonGuid", "ParentProcessGuid", "UtcTime",
    "CreationUtcTime", "root_image", "is_seed", "label_method", "enrich_method",
]


def load(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="*", help="ไฟล์ *_labeled.csv (ไม่ใส่ = ทุกไฟล์ใน dataset/)")
    ap.add_argument("-o", "--out", default=str(DATASET_DIR / "merged_dataset.csv"))
    ap.add_argument("--exclude", nargs="*", default=[], help="ข้าม session ที่ชื่อมีคำเหล่านี้")
    args = ap.parse_args()

    files = [Path(p) for p in args.inputs] or sorted(DATASET_DIR.glob("*_labeled.csv"))
    files = [f for f in files if not any(x in f.name for x in args.exclude)]
    if not files:
        print("[!] ไม่พบไฟล์ให้รวม"); sys.exit(1)

    # ---------- อ่าน + ตรวจ schema ----------
    sessions, header = {}, None
    for f in files:
        rows = load(f)
        if not rows:
            print(f"[!] {f.name} ว่าง - ข้าม"); continue
        cols = list(rows[0].keys())
        if header is None:
            header = cols
        elif cols != header:
            missing, extra = set(header) - set(cols), set(cols) - set(header)
            print(f"[!] schema ไม่ตรง: {f.name}")
            if missing: print(f"      ขาด: {sorted(missing)}")
            if extra:   print(f"      เกิน: {sorted(extra)}")
            sys.exit(1)
        # run_id = ชื่อไฟล์ ซึ่ง unique ต่อการกดรัน 1 ครั้ง
        # ต่างจากคอลัมน์ `session` ที่เก็บแค่ชื่อ scenario (benign/ransomware/...)
        # ถ้าไม่มีคอลัมน์นี้ การรัน ransomware 5 รอบจะกลายเป็นกลุ่มเดียวกันหมด
        # -> GroupKFold แยกไม่ออก -> รอบเดียวกันไปอยู่ทั้ง train และ test
        run_id = f.stem.replace("_labeled", "")
        for r in rows:
            r["run_id"] = run_id
        sessions[run_id] = rows

    if header is not None and "run_id" not in header:
        header = header + ["run_id"]
    print(f"[*] รวม {len(sessions)} run, schema ตรงกันทั้งหมด ({len(header)} คอลัมน์)\n")

    # ---------- ตรวจ sensor-era mismatch ----------
    ev_by_session = {k: Counter(r["EventID"] for r in v) for k, v in sessions.items()}
    all_events = set().union(*[set(c) for c in ev_by_session.values()])
    suspect = []
    for eid in sorted(all_events, key=lambda x: int(x) if x.isdigit() else 99):
        have = [s for s in sessions if ev_by_session[s].get(eid, 0) > 0]
        if 0 < len(have) < len(sessions):
            missing = [s for s in sessions if s not in have]
            suspect.append((eid, missing))

    if suspect:
        print("[!] เตือน sensor-era mismatch - บาง session ไม่มี event ชนิดนี้เลย:")
        for eid, missing in suspect:
            print(f"      EventID {eid} ({EVENT_NAMES.get(eid,'?')}) หายใน: {', '.join(missing)}")
        print("    ถ้าไม่ได้ตั้งใจ ให้ --exclude session พวกนั้นทิ้ง")
        print("    ไม่งั้นโมเดลจะเรียน 'ไม่มี event ชนิดนี้ = รอบนั้น' แทนพฤติกรรมมัลแวร์\n")
    else:
        print("[+] ทุก session เห็น event ชนิดเดียวกัน - ไม่มี sensor-era mismatch\n")

    # ---------- เขียนไฟล์รวม ----------
    merged = [r for rows in sessions.values() for r in rows]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(merged)

    # ---------- สรุป ----------
    n = len(merged)
    lab = Counter(r["label"] for r in merged)
    print(f"[+] เขียนแล้ว: {out}  ({n:,} แถว x {len(header)} คอลัมน์)\n")
    print("=== แยกตาม session ===")
    for s, rows in sessions.items():
        c = Counter(r["label"] for r in rows)
        print(f"  {s[:46]:<46} {len(rows):>6,}  mal {c['1']/len(rows)*100:5.1f}%")
    print(f"\n=== label รวม ===")
    for k in sorted(lab):
        nm = "benign" if k == "0" else "malicious"
        print(f"  {k} {nm:<10} {lab[k]:>7,}  ({lab[k]/n*100:5.1f}%)")

    print("\n=== event type x label ===")
    ct = Counter((r["EventID"], r["label"]) for r in merged)
    for eid in sorted(all_events, key=lambda x: -(ct[(x,'0')] + ct[(x,'1')])):
        print(f"  {eid:>3} {EVENT_NAMES.get(eid,'?'):<17} benign {ct[(eid,'0')]:>7,}   malicious {ct[(eid,'1')]:>7,}")

    # ---------- leakage checks ----------
    print("\n=== LEAKAGE CHECK ===")
    hosts = defaultdict(Counter)
    for r in merged:
        hosts[r["computer"]][r["label"]] += 1
    for h, c in hosts.items():
        tot = sum(c.values())
        flag = "  <-- ถือ label เดียวล้วน!" if 0 in (c['0'], c['1']) else ""
        print(f"  {h}: benign {c['0']/tot*100:5.1f}% / malicious {c['1']/tot*100:5.1f}%  ({tot:,}){flag}")

    empty = Counter(r["label"] for r in merged if r.get("CommandLine", "") in ("", "-"))
    te = sum(empty.values())
    if te:
        pct = max(empty['0'], empty['1']) / te * 100
        print(f"  CommandLine ว่าง {te:,} แถว ({te/n*100:.1f}%) -> "
              f"benign {empty['0']/te*100:.1f}% / malicious {empty['1']/te*100:.1f}%")
        if pct > 90:
            print(f"    [!] ทำนาย label ได้ {pct:.1f}% - enrichment leakage")
            print(f"        ตอนเทรนให้ลอง drop แถวพวกนี้ หรือใส่ has_commandline เป็น feature ตรงๆ แล้ววัดเทียบ")

    print(f"\n  อย่าลืม drop {len(DROP_BEFORE_FIT)} คอลัมน์นี้ก่อน fit():")
    print("   ", ", ".join(DROP_BEFORE_FIT))


if __name__ == "__main__":
    main()

"""
Explore Events - สำรวจว่า Sysmon for Linux ยิง event ID ไหนออกมาจริงบ้าง
และ field ไหนมีค่าใช้งานได้จริง (ไม่ใช่ "-")

ใช้งาน:
    python explore_events.py logs/phase1_test_20260816_230327.log
"""
import re
import sys
from collections import Counter, defaultdict

EVENT_NAMES = {
    "1": "ProcessCreate",
    "3": "NetworkConnect",
    "5": "ProcessTerminate",
    "9": "RawAccessRead",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "16": "SysmonConfigChange",
    "22": "DnsQuery",
    "23": "FileDelete",
}

# รองรับทั้ง single และ double quote
FIELD_RE = re.compile(r'Name=["\']([^"\']+)["\']>([^<]*)</Data>')
EVENTID_RE = re.compile(r"<EventID>(\d+)</EventID>")


def main(path):
    event_counts = Counter()
    fields_present = defaultdict(Counter)   # field ที่ปรากฏ (รวม "-")
    fields_useful = defaultdict(Counter)    # field ที่มีค่าจริง
    total = 0

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            total += 1
            m = EVENTID_RE.search(line)
            if not m:
                continue
            eid = m.group(1)
            event_counts[eid] += 1

            for name, val in FIELD_RE.findall(line):
                fields_present[eid][name] += 1
                v = val.strip()
                if v and v != "-":
                    fields_useful[eid][name] += 1

    print(f"\n{'='*66}")
    print(f"  ไฟล์: {path}")
    print(f"  บรรทัดทั้งหมด: {total:,}   Sysmon events: {sum(event_counts.values()):,}")
    print(f"{'='*66}\n")

    print("EVENT ID ที่ออกจริง:")
    print(f"{'ID':<5} {'ชื่อ':<22} {'จำนวน':>10}")
    print("-" * 42)
    for eid, cnt in event_counts.most_common():
        print(f"{eid:<5} {EVENT_NAMES.get(eid, 'Unknown'):<22} {cnt:>10,}")

    print("\n\nFIELD แต่ละ event  (useful = มีค่าจริง / present = ปรากฏทั้งหมด)")
    for eid, ev_cnt in event_counts.most_common():
        print(f"\n  [{eid}] {EVENT_NAMES.get(eid, 'Unknown')}   ({ev_cnt:,} events)")
        for field, p_cnt in fields_present[eid].most_common():
            u_cnt = fields_useful[eid].get(field, 0)
            pct = (u_cnt / p_cnt * 100) if p_cnt else 0
            flag = "  <-- ว่างเสมอ" if u_cnt == 0 else ""
            print(f"      {field:<26} useful {u_cnt:>5}/{p_cnt:<5} ({pct:5.1f}%){flag}")

    # ---------- สรุปรวม ----------
    all_present, all_useful, dead = set(), set(), set()
    for eid in fields_present:
        all_present.update(fields_present[eid].keys())
        all_useful.update(fields_useful[eid].keys())
    dead = all_present - all_useful

    print(f"\n\n{'='*66}")
    print(f"  สรุป FEATURE")
    print(f"{'='*66}")
    print(f"  field ทั้งหมดที่เจอ  : {len(all_present)}")
    print(f"  field ที่มีค่าใช้ได้ : {len(all_useful)}   <-- ตัวเลขนี้ใช้เขียนธีสิสได้")
    print(f"  field ที่ว่างเสมอ    : {len(dead)}")
    print(f"  (เปเปอร์อ้างอิงบน Windows: 41 คอลัมน์)")

    print(f"\n  [ใช้ได้]")
    for f_ in sorted(all_useful):
        print(f"    + {f_}")

    if dead:
        print(f"\n  [ว่างเสมอ - ตัดทิ้งได้]")
        for f_ in sorted(dead):
            print(f"    - {f_}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
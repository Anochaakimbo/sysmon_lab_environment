"""
enrich_events.py - เติมข้อมูลระดับ process เข้าไปในทุกแถว

ปัญหา: ProcessTerminate / FileCreate / NetworkConnect มี field น้อยมาก
       (ไม่มี CommandLine, Hashes, Parent*) ทำให้ ~74% ของแถวข้อมูลบาง

วิธีแก้: สร้างตาราง process จาก ProcessCreate แล้ว join กลับเข้าทุกแถว
        โดยใช้ ProcessGuid เป็นกุญแจหลัก และ ProcessId เป็น fallback

ใช้งาน:
    python enrich_events.py dataset/events.csv -o dataset/events_enriched.csv
"""
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

NULL_GUID = "{00000000-0000-0000-0000-000000000000}"

# field ที่ยืมมาจาก ProcessCreate ของ process เดียวกัน
INHERIT_COLS = [
    "CommandLine",
    "CurrentDirectory",
    "Hashes",
    "LogonGuid",
    "LogonId",
    "TerminalSessionId",
    "IntegrityLevel",
    "ParentProcessGuid",
    "ParentProcessId",
    "ParentImage",
    "ParentCommandLine",
    "ParentUser",
]

# คอลัมน์ใหม่ที่เพิ่มเข้ามา
NEW_COLS = [
    "platform",         # linux / windows  (เตรียมไว้ merge dataset)
    "enriched",         # 1 = ค่าถูกเติมมาจาก ProcessCreate
    "enrich_method",    # guid / pid / none
    "ancestor_depth",   # ความลึกในสายพันธุ์ process
    "root_image",       # ต้นสายที่ตามได้ไกลสุด
]


def build_process_table(rows):
    """สร้าง lookup: guid -> ข้อมูล process, และ pid -> guid"""
    by_guid = {}
    by_pid = {}
    for r in rows:
        if r.get("EventID") != "1":
            continue
        guid = r.get("ProcessGuid", "").strip()
        pid = r.get("ProcessId", "").strip()
        info = {c: r.get(c, "") for c in INHERIT_COLS}
        info["Image"] = r.get("Image", "")
        info["User"] = r.get("User", "")
        if guid and guid != NULL_GUID:
            by_guid[guid] = info
        if pid:
            # PID ซ้ำได้ (reuse) - เก็บตัวล่าสุดที่เจอ
            by_pid[pid] = info
    return by_guid, by_pid


def resolve_lineage(by_guid, max_depth=20):
    """ไล่สายพันธุ์ process: guid -> (depth, root_image)"""
    lineage = {}

    def walk(guid, seen):
        if guid in lineage:
            return lineage[guid]
        info = by_guid.get(guid)
        if not info:
            return (0, "")
        pguid = info.get("ParentProcessGuid", "").strip()
        if (not pguid or pguid == NULL_GUID or pguid in seen
                or len(seen) >= max_depth):
            # ถึงต้นสายแล้ว (หรือ lineage ขาด)
            res = (0, info.get("Image", ""))
        else:
            seen.add(guid)
            pdepth, proot = walk(pguid, seen)
            res = (pdepth + 1, proot or info.get("Image", ""))
        lineage[guid] = res
        return res

    for g in list(by_guid.keys()):
        walk(g, set())
    return lineage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="dataset/events_enriched.csv")
    ap.add_argument("--platform", default="linux", choices=["linux", "windows"])
    ap.add_argument("--no-pid-fallback", action="store_true",
                    help="ใช้เฉพาะ ProcessGuid ไม่ใช้ PID (แม่นกว่าแต่ครอบคลุมน้อยกว่า)")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("[!] ไฟล์ว่าง")
        return

    in_cols = list(rows[0].keys())
    out_cols = in_cols + [c for c in NEW_COLS if c not in in_cols]

    by_guid, by_pid = build_process_table(rows)
    lineage = resolve_lineage(by_guid)
    print(f"[*] สร้างตาราง process: {len(by_guid)} guid, {len(by_pid)} pid")

    stats = Counter()
    fill_before = Counter()
    fill_after = Counter()

    for r in rows:
        for c in INHERIT_COLS:
            if r.get(c, "").strip():
                fill_before[c] += 1

        r["platform"] = args.platform
        r["enriched"] = "0"
        r["enrich_method"] = "none"
        r["ancestor_depth"] = ""
        r["root_image"] = ""

        guid = r.get("ProcessGuid", "").strip()
        pid = r.get("ProcessId", "").strip()

        # ---- หา process ต้นทาง ----
        info, method = None, "none"
        if guid and guid != NULL_GUID and guid in by_guid:
            info, method = by_guid[guid], "guid"
        elif not args.no_pid_fallback and pid and pid in by_pid:
            info, method = by_pid[pid], "pid"

        if info:
            filled_any = False
            for c in INHERIT_COLS:
                if not r.get(c, "").strip() and info.get(c, "").strip():
                    r[c] = info[c]
                    filled_any = True
            # ProcessCreate เองไม่นับว่าถูก enrich
            if filled_any and r.get("EventID") != "1":
                r["enriched"] = "1"
                r["enrich_method"] = method
                stats[f"enriched_by_{method}"] += 1
            # ถ้า Image ว่าง เติมจาก process table ด้วย
            if not r.get("Image", "").strip() and info.get("Image", "").strip():
                r["Image"] = info["Image"]

        # ---- lineage ----
        if guid in lineage:
            d, root = lineage[guid]
            r["ancestor_depth"] = str(d)
            r["root_image"] = root

        for c in INHERIT_COLS:
            if r.get(c, "").strip():
                fill_after[c] += 1

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=out_cols)
        w.writeheader()
        w.writerows(rows)

    # ---------------- รายงาน ----------------
    n = len(rows)
    print(f"\n{'='*64}")
    print(f"  เขียนแล้ว: {out_path}  ({n:,} แถว x {len(out_cols)} คอลัมน์)")
    print(f"{'='*64}")

    print("\nการ enrich:")
    tot = sum(v for k, v in stats.items() if k.startswith("enriched_by"))
    print(f"  แถวที่ถูกเติมข้อมูล : {tot:,} / {n:,}  ({tot/n*100:.1f}%)")
    for k, v in stats.most_common():
        print(f"    {k:<22} {v:>6,}")

    print(f"\n{'คอลัมน์':<22} {'ก่อน':>12} {'หลัง':>14}")
    print("-" * 52)
    for c in INHERIT_COLS:
        b, a = fill_before[c], fill_after[c]
        arrow = "  ^" if a > b else ""
        print(f"  {c:<20} {b:>5} ({b/n*100:4.1f}%) -> {a:>5} ({a/n*100:5.1f}%){arrow}")


if __name__ == "__main__":
    main()
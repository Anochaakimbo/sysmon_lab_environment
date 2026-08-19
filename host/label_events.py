"""
label_events.py - ติด label ให้ Sysmon events

2 โหมด:
  session : ทั้งไฟล์/session = label เดียว  (ง่าย แต่ mislabel background noise)
  lineage : label เฉพาะ process ที่สืบสายจากมัลแวร์ + activity ของมัน (แนะนำ)

ใช้งาน:
  # โหมด session
  python label_events.py data.csv -o out.csv --mode session --label 1

  # โหมด lineage (ระบุ seed ด้วย path หรือ keyword ใน CommandLine)
  python label_events.py data.csv -o out.csv --mode lineage \
      --seed-image /tmp/malware.sh --seed-cmd "curl attacker"

  # เปรียบเทียบทั้งสองโหมด (ไม่เขียนไฟล์)
  python label_events.py data.csv --compare --seed-image /tmp/malware.sh
"""
import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

NULL_GUID = "{00000000-0000-0000-0000-000000000000}"

# คอลัมน์ที่ห้ามใช้เป็น feature (ระบุตัว VM/session ได้ -> โมเดลโกง)
LEAKY_COLS = [
    "computer", "host_ip", "session", "recv_timestamp", "record_id",
    "ProcessGuid", "LogonGuid", "ParentProcessGuid", "UtcTime",
    "CreationUtcTime", "root_image",
]


def matches_seed(row, seed_images, seed_cmds, seed_dirs):
    """เช็คว่า row นี้คือ process ต้นทางของมัลแวร์หรือไม่"""
    img = row.get("Image", "")
    cmd = row.get("CommandLine", "")
    cwd = row.get("CurrentDirectory", "")

    for s in seed_images:
        if s and s in img:
            return True
    for s in seed_cmds:
        if s and s.lower() in cmd.lower():
            return True
    for s in seed_dirs:
        if s and (cwd.startswith(s) or img.startswith(s)):
            return True
    return False


def label_lineage(rows, seed_images, seed_cmds, seed_dirs):
    """
    1. หา seed process
    2. แพร่ label ไปยัง descendant (ผ่าน ParentProcessGuid, fallback ParentProcessId)
    3. ติด label ให้ทุก event ของ process ที่ติดธง
    """
    # ---- map ความสัมพันธ์ ----
    guid_of_pid = {}
    parent_guid = {}
    parent_pid = {}
    row_guid = defaultdict(list)

    for r in rows:
        g = r.get("ProcessGuid", "").strip()
        p = r.get("ProcessId", "").strip()
        if g and g != NULL_GUID:
            row_guid[g].append(r)
            if p:
                guid_of_pid[p] = g
        if r.get("EventID") == "1" and g:
            pg = r.get("ParentProcessGuid", "").strip()
            pp = r.get("ParentProcessId", "").strip()
            if pg and pg != NULL_GUID:
                parent_guid[g] = pg
            if pp:
                parent_pid[g] = pp

    # ---- หา seed ----
    malicious = set()
    seeds = set()
    for r in rows:
        g = r.get("ProcessGuid", "").strip()
        if not g or g == NULL_GUID:
            continue
        if matches_seed(r, seed_images, seed_cmds, seed_dirs):
            seeds.add(g)
            malicious.add(g)

    # ---- แพร่ลงลูกหลาน (วนจนไม่มีอะไรเพิ่ม) ----
    changed = True
    rounds = 0
    while changed and rounds < 50:
        changed = False
        rounds += 1
        for g in list(row_guid.keys()):
            if g in malicious:
                continue
            pg = parent_guid.get(g)
            if pg and pg in malicious:
                malicious.add(g)
                changed = True
                continue
            # fallback: ตาม PID เมื่อ GUID ขาด
            pp = parent_pid.get(g)
            if pp:
                pg2 = guid_of_pid.get(pp)
                if pg2 and pg2 in malicious:
                    malicious.add(g)
                    changed = True

    # ---- ติด label ----
    n_mal = 0
    for r in rows:
        g = r.get("ProcessGuid", "").strip()
        is_mal = g in malicious
        r["label"] = "1" if is_mal else "0"
        r["label_method"] = "lineage"
        r["is_seed"] = "1" if g in seeds else "0"
        if is_mal:
            n_mal += 1

    return {"seeds": len(seeds), "mal_processes": len(malicious),
            "mal_events": n_mal, "rounds": rounds}


def label_session(rows, value):
    for r in rows:
        r["label"] = str(value)
        r["label_method"] = "session"
        r["is_seed"] = ""
    return {"mal_events": sum(1 for r in rows if r["label"] == "1")}


# world-writable path ที่มัลแวร์ชอบวาง payload - ใช้กรอง false positive ของ baseline
SUSPECT_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"]


def load_baseline_images(paths):
    """อ่าน benign labeled csv -> set ของ Image ที่ยืนยันว่าปกติ"""
    imgs = set()
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                im = (r.get("Image") or "").strip()
                if im:
                    imgs.add(im)
    return imgs


def label_baseline(rows, baseline_imgs, suspect_only=True):
    """
    Differential baseline (opt-in): process ที่ Image ไม่เคยปรากฏใน benign baseline
    = น่าสงสัย -> label malicious แล้วแพร่ไปลูกหลานเหมือน lineage

    ใช้ได้ดีกับ 'distinct binary' (xmrig, exploit PoC) ที่ benign ไม่มีทางมี
    ระวัง 'dual-use' (crontab/chmod): ถ้า baseline ไม่ครอบคลุมจะ false positive
    suspect_only=True จำกัดเฉพาะ Image ที่รันจาก world-writable path เพื่อลด FP

    หมายเหตุ: เรียกหลัง label_lineage เท่านั้น (เสริม ไม่ทับของที่ lineage จับแล้ว)
    """
    # เก็บ ProcessGuid ที่ baseline จับได้ใหม่ แล้วแพร่ลงลูกด้วย parent map
    guid_of_pid, parent_guid, parent_pid, row_guid = {}, {}, {}, defaultdict(list)
    for r in rows:
        g = r.get("ProcessGuid", "").strip()
        p = r.get("ProcessId", "").strip()
        if g and g != NULL_GUID:
            row_guid[g].append(r)
            if p:
                guid_of_pid[p] = g
        if r.get("EventID") == "1" and g:
            pg = r.get("ParentProcessGuid", "").strip()
            pp = r.get("ParentProcessId", "").strip()
            if pg and pg != NULL_GUID:
                parent_guid[g] = pg
            if pp:
                parent_pid[g] = pp

    mal = set(r.get("ProcessGuid", "").strip()
              for r in rows if r.get("label") == "1")
    seeded = set()
    for r in rows:
        if r.get("label") == "1":
            continue
        im = (r.get("Image") or "").strip()
        if not im or im in baseline_imgs:
            continue
        if suspect_only and not any(im.startswith(s) for s in SUSPECT_PATHS):
            continue
        g = r.get("ProcessGuid", "").strip()
        if g and g != NULL_GUID:
            mal.add(g); seeded.add(g)

    # แพร่ลงลูกหลาน
    changed, rounds = True, 0
    while changed and rounds < 50:
        changed = False; rounds += 1
        for g in list(row_guid.keys()):
            if g in mal:
                continue
            pg = parent_guid.get(g)
            if (pg and pg in mal) or (parent_pid.get(g) and
                                      guid_of_pid.get(parent_pid[g]) in mal):
                mal.add(g); changed = True

    n_new = 0
    for r in rows:
        if r.get("label") == "1":
            continue
        g = r.get("ProcessGuid", "").strip()
        if g in mal:
            r["label"] = "1"
            r["label_method"] = "baseline"
            n_new += 1
    return {"seeded": len(seeded), "new_events": n_new}


def leak_report(rows):
    """เตือนคอลัมน์ที่ correlate กับ label แบบสมบูรณ์ (สัญญาณโกง)"""
    labels = set(r.get("label", "") for r in rows)
    if len(labels) < 2:
        return
    print(f"\n{'='*64}")
    print("  ตรวจ LEAKAGE: คอลัมน์ที่ทำนาย label ได้ 100%")
    print(f"{'='*64}")
    cols = [c for c in rows[0].keys() if c not in ("label", "label_method", "is_seed")]
    flagged = []
    for c in cols:
        by_val = defaultdict(set)
        for r in rows:
            by_val[r.get(c, "")].add(r.get("label"))
        vals = [v for v in by_val if v != ""]
        if not vals or len(vals) > 200:
            continue
        # ถ้าทุกค่าของคอลัมน์นี้ map ไป label เดียวเสมอ -> โกงได้
        if all(len(by_val[v]) == 1 for v in vals):
            flagged.append((c, len(vals)))
    if flagged:
        for c, k in flagged:
            mark = "  [!! ตัดทิ้งก่อนเทรน]" if c in LEAKY_COLS else "  [ตรวจสอบ]"
            print(f"  {c:<24} ({k} ค่าไม่ซ้ำ){mark}")
    else:
        print("  ไม่พบคอลัมน์ที่ทำนาย label ได้สมบูรณ์ — ดี")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    ap.add_argument("--mode", choices=["session", "lineage"], default="lineage")
    ap.add_argument("--label", type=int, default=1, help="ค่า label สำหรับโหมด session")
    ap.add_argument("--seed-image", action="append", default=[],
                    help="ระบุ path/ชื่อไฟล์ของมัลแวร์ (ใส่ซ้ำได้)")
    ap.add_argument("--seed-cmd", action="append", default=[],
                    help="keyword ใน CommandLine (ใส่ซ้ำได้)")
    ap.add_argument("--seed-dir", action="append", default=[],
                    help="โฟลเดอร์ที่มัลแวร์ทำงาน เช่น /tmp/mal")
    ap.add_argument("--compare", action="store_true",
                    help="เทียบผล 2 โหมด ไม่เขียนไฟล์")
    ap.add_argument("--baseline", action="append", default=[],
                    help="benign labeled csv สำหรับ differential baseline (ใส่ซ้ำได้) "
                         "- process ที่ Image ไม่เคยเห็นใน benign = malicious")
    ap.add_argument("--baseline-all-paths", action="store_true",
                    help="baseline จับทุก path ไม่ใช่แค่ world-writable (เสี่ยง FP สูง)")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("[!] ไฟล์ว่าง")
        return
    n = len(rows)

    for c in ("label", "label_method", "is_seed"):
        for r in rows:
            r.setdefault(c, "")

    if args.mode == "lineage" or args.compare:
        if not (args.seed_image or args.seed_cmd or args.seed_dir):
            print("[!] โหมด lineage ต้องระบุ --seed-image / --seed-cmd / --seed-dir")
            sys.exit(1)
        info = label_lineage(rows, args.seed_image, args.seed_cmd, args.seed_dir)
        print(f"\n[lineage] seed process : {info['seeds']}")
        print(f"[lineage] process ที่ติดธง: {info['mal_processes']}  (แพร่ {info['rounds']} รอบ)")
        print(f"[lineage] events = 1    : {info['mal_events']:,}/{n:,} ({info['mal_events']/n*100:.1f}%)")
        if info["seeds"] == 0:
            print("  [!] ไม่เจอ seed เลย - ตรวจ --seed-* ว่าตรงกับข้อมูลจริงไหม")

    if args.compare:
        print(f"[session] events = 1    : {n:,}/{n:,} (100.0%)")
        print(f"\n  => session labeling จะ mislabel background noise "
              f"~{n - info['mal_events']:,} events")
        return

    if args.mode == "session":
        info = label_session(rows, args.label)
        print(f"\n[session] label={args.label} ให้ทุกแถว ({n:,} events)")

    # differential baseline (opt-in, เสริมหลัง lineage)
    if args.baseline:
        bimgs = load_baseline_images(args.baseline)
        binfo = label_baseline(rows, bimgs, suspect_only=not args.baseline_all_paths)
        scope = "ทุก path" if args.baseline_all_paths else "เฉพาะ world-writable"
        print(f"\n[baseline] อ่าน {len(bimgs)} benign images จาก {len(args.baseline)} ไฟล์ ({scope})")
        print(f"[baseline] จับเพิ่ม {binfo['seeded']} process -> +{binfo['new_events']:,} events")

    dist = Counter(r["label"] for r in rows)
    print(f"\nสัดส่วน label: " + "  ".join(f"{k}={v:,} ({v/n*100:.1f}%)"
                                          for k, v in sorted(dist.items())))

    leak_report(rows)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        cols = list(rows[0].keys())
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        print(f"\n[+] เขียนแล้ว: {out}  ({n:,} แถว x {len(cols)} คอลัมน์)")
        print(f"\n  อย่าลืมตัดคอลัมน์เหล่านี้ก่อนเทรน:")
        print("   ", ", ".join(c for c in LEAKY_COLS if c in cols))


if __name__ == "__main__":
    main()
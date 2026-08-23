"""
rebuild_dataset.py - สร้าง CSV ใหม่จาก raw log ที่เก็บไว้ ไม่ต้องรัน VM ซ้ำ

raw log คือแหล่งความจริงของโปรเจคนี้:
    Linux   -> host/logs/<session>.log        (syslog ที่ log_receiver.py รับมา)
    Windows -> host/logs_win/<session>.xml    (EVTX ที่ export_sysmon_win.ps1 ดึงมา)

CSV ใน host/dataset/ เป็นของที่ derive มาทั้งหมด ถ้าหาย/เสีย/อยากเปลี่ยนวิธี label
ให้สร้างใหม่จากตรงนี้ ไม่ต้องเก็บข้อมูลใหม่ (ซึ่งจะได้ข้อมูลคนละชุด เทียบกับของเก่าไม่ได้)

label spec อ่านจาก *_meta.json ที่ orchestrator เขียนไว้คู่กับ log
seed_dir/seed_cmd อ่านจาก SCENARIOS ของ orchestrator ตัวที่ตรงแพลตฟอร์ม

ใช้งาน:
    python host/rebuild_dataset.py --platform linux            # ทำใหม่ทุก log ที่ยังไม่มี CSV
    python host/rebuild_dataset.py --platform linux --force    # ทำใหม่ทั้งหมด ทับของเดิม
    python host/rebuild_dataset.py --platform windows
    python host/rebuild_dataset.py --platform linux --only ransomware,botnet
    python host/rebuild_dataset.py --platform linux --list     # ดูว่ามีอะไรให้ทำบ้าง
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parent
LAB_DIR = HOST_DIR.parent
DATASET_DIR = HOST_DIR / "dataset"

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

PLATFORMS = {
    "linux": {
        "log_dir": HOST_DIR / "logs",
        "pattern": "*.log",
        "orchestrator": "orchestrator",
        "raw_key": "raw_log",
    },
    "windows": {
        "log_dir": HOST_DIR / "logs_win",
        "pattern": "*.xml",
        "orchestrator": "orchestrator_win",
        "raw_key": "raw_xml",
    },
}


def load_scenarios(module_name):
    """ดึง SCENARIOS ออกมาจาก orchestrator โดยไม่รัน main()"""
    sys.path.insert(0, str(HOST_DIR))
    mod = __import__(module_name)
    return mod.SCENARIOS


def find_jobs(platform, only=None):
    """จับคู่ meta.json -> raw log -> spec"""
    cfg = PLATFORMS[platform]
    scenarios = load_scenarios(cfg["orchestrator"])
    jobs = []
    for meta_path in sorted(cfg["log_dir"].glob("*_meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"  [!] อ่าน {meta_path.name} ไม่ได้: {e}")
            continue

        name = meta.get("scenario")
        if only and name not in only:
            continue

        raw = meta.get(cfg["raw_key"])
        raw_path = Path(raw) if raw else None
        # meta เก็บ path แบบเต็มของเครื่องที่เก็บ - ถ้าย้ายโปรเจคแล้วให้หาในโฟลเดอร์ log แทน
        if not raw_path or not raw_path.exists():
            cand = list(cfg["log_dir"].glob(f"{name}_*{cfg['pattern'][1:]}"))
            raw_path = cand[-1] if cand else None
        if not raw_path or not raw_path.exists():
            print(f"  [!] {name}: ไม่พบ raw log (meta อ้าง {raw})")
            continue

        spec = scenarios.get(name)
        if not spec:
            # label_spec ใน meta ยังใช้ได้ แม้ scenario จะถูกลบออกจาก orchestrator แล้ว
            spec = {"label": meta.get("label_spec", "lineage")}
            if spec["label"] != "session:0":
                spec["seed_dir"] = r"C:\lab_sandbox" if platform == "windows" else "/tmp/lab_sandbox"
                spec["seed_cmd"] = "lab_sandbox"
            print(f"  [~] {name}: ไม่มีใน SCENARIOS ของ {cfg['orchestrator']} - ใช้ label_spec จาก meta")

        jobs.append({"name": name, "raw": raw_path, "spec": spec, "meta": meta_path})
    return jobs


def rebuild(job, platform, force):
    name, raw, spec = job["name"], job["raw"], job["spec"]
    stem = raw.stem
    events = DATASET_DIR / f"{stem}_events.csv"
    enriched = DATASET_DIR / f"{stem}_enriched.csv"
    labeled = DATASET_DIR / f"{stem}_labeled.csv"

    if labeled.exists() and not force:
        print(f"  [ข้าม] {name}: มี {labeled.name} อยู่แล้ว (ใช้ --force เพื่อทับ)")
        return None

    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\n{'='*62}\n  {name}  <- {raw.name}\n{'='*62}")

    subprocess.run(["python", str(HOST_DIR / "parse_sysmon.py"),
                    str(raw), "-o", str(events),
                    "--session", name, "--platform", platform], check=True)
    subprocess.run(["python", str(HOST_DIR / "enrich_events.py"),
                    str(events), "-o", str(enriched),
                    "--platform", platform], check=True)

    cmd = ["python", str(HOST_DIR / "label_events.py"), str(enriched), "-o", str(labeled)]
    label_spec = spec["label"]
    if label_spec.startswith("session:"):
        cmd += ["--mode", "session", "--label", label_spec.split(":", 1)[1]]
    else:
        cmd += ["--mode", "lineage"]
        for key, flag in (("seed_dir", "--seed-dir"), ("seed_cmd", "--seed-cmd"),
                          ("seed_image", "--seed-image")):
            if spec.get(key):
                cmd += [flag, spec[key]]
    subprocess.run(cmd, check=True)
    return labeled


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", choices=list(PLATFORMS), required=True)
    ap.add_argument("--only", help="ชื่อ scenario คั่นด้วย comma")
    ap.add_argument("--force", action="store_true", help="ทับ CSV เดิม")
    ap.add_argument("--list", action="store_true", help="แค่ดูว่ามีอะไรให้ทำ")
    args = ap.parse_args()

    only = set(x.strip() for x in args.only.split(",")) if args.only else None
    jobs = find_jobs(args.platform, only)

    if not jobs:
        print(f"[!] ไม่พบ raw log ที่ทำได้ใน {PLATFORMS[args.platform]['log_dir']}")
        return 1

    if args.list:
        print(f"raw log ที่ทำใหม่ได้ ({args.platform}):\n")
        for j in jobs:
            stem = j["raw"].stem
            done = (DATASET_DIR / f"{stem}_labeled.csv").exists()
            size = j["raw"].stat().st_size / 1048576
            print(f"  {j['name']:<16} {j['raw'].name:<50} {size:>6.1f} MB"
                  f"   {'มี CSV แล้ว' if done else 'ยังไม่มี CSV'}")
        return 0

    made = []
    for j in jobs:
        try:
            out = rebuild(j, args.platform, args.force)
            if out:
                made.append(out)
        except subprocess.CalledProcessError as e:
            print(f"  [!] {j['name']} ล้ม: {e}")

    print(f"\n{'='*62}")
    print(f"  สร้างใหม่ {len(made)} ชุด")
    for m in made:
        print(f"    {m.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
orchestrator.py (v2) - ต้นแบบ backend สำหรับ web dashboard

หน้าที่: revert -> boot -> รัน scenario -> เก็บ log -> ปิด -> parse+enrich+label อัตโนมัติ

หลักการสำคัญ:
- ทุก VM ต้องรันทั้ง benign และ malicious (กัน hostname/VM leakage)
- แต่ละ scenario ผูก seed ไว้สำหรับ lineage labeling
- ตัว scenario script จริงอยู่ในโฟลเดอร์ scenarios/ (คุณเติมตามแนวทางที่เลือก)

ใช้งาน:
    python orchestrator.py --save-snapshot
    python orchestrator.py --scenario benign     --vm target1 --duration 3
    python orchestrator.py --scenario ransomware  --vm target1 --duration 5
    python orchestrator.py --list
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
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent      # โฟลเดอร์ที่มี Vagrantfile
HOST_DIR = Path(__file__).resolve().parent            # โฟลเดอร์ host/
SCENARIO_DIR = LAB_DIR / "scenarios"                  # สคริปต์จำลองพฤติกรรม
LOG_DIR = HOST_DIR / "logs"
DATASET_DIR = HOST_DIR / "dataset"
CLEAN_SNAPSHOT = "clean"


def preflight_ssh_key(vm):
    """OpenSSH บน Windows ปฏิเสธ private key ที่สิทธิ์ไฟล์กว้างเกินไป
    แล้วตกไปใช้ password auth -> `vagrant ssh -c` ค้างรอ password ตลอดกาล
    (เคยทำให้ทั้งรอบค้างที่ขั้น setup มาแล้ว) - ตรวจและรัดสิทธิ์ให้อัตโนมัติ"""
    if os.name != "nt":
        return
    keys = list((LAB_DIR / ".vagrant" / "machines" / vm).glob("*/private_key"))
    if not keys:
        return
    key = keys[0]
    try:
        acl = subprocess.run(["icacls", str(key)], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return
    if not any(w in acl for w in ("Authenticated Users", r"BUILTIN\Users", "Everyone")):
        return
    print(f"[preflight] private key สิทธิ์กว้างเกินไป -> รัดสิทธิ์ {key}")
    subprocess.run(["icacls", str(key), "/inheritance:r",
                    "/grant:r", f"{os.environ.get('USERNAME', '')}:(R)"],
                   capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)

# ---------------------------------------------------------------- scenarios
# แต่ละ scenario: script ที่รันใน VM + วิธี label
#   label = "session:0"           -> ทั้ง session เป็น benign
#   label = "lineage"             -> ตาม seed (แพร่ไปลูกหลาน)
#   seed_dir / seed_cmd / seed_image = ตัวชี้ seed ให้ lineage labeler
#
# NOTE: ตัวไฟล์ scenarios/*.sh คุณสร้างเองตามแนวทางที่เลือก
#   (Atomic Red Team / เขียน simulation เอง / live sample)
#   orchestrator แค่ก๊อปสคริปต์เข้า VM แล้วสั่งรัน - ไม่มี payload ฝังในนี้
SCENARIOS = {
    "benign": {
        "script": "benign.sh",
        "label": "session:0",
    },
    "ransomware": {
        "script": "ransomware.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1486,T1490,T1083,T1070.004",
    },
    "trojan": {
        "script": "trojan.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1059.004,T1543.002,T1053.003,T1005,T1027",
    },
    "botnet": {
        "script": "botnet.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1071.001,T1105,T1571,T1016,T1049",
    },
    "exploit": {
        "script": "exploit.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1548.001,T1068,T1055,T1222.002,T1552.001",
    },
    "miner": {
        "script": "miner.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1496,T1053.003,T1562.001,T1057",
    },
    "miner_real": {
        "script": "miner_real.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1496,T1105,T1053.003,T1057,T1082",
    },
    "exploit_real": {
        "script": "exploit_real.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1068,T1003.008,T1136.001,T1548,T1082,T1033",
    },
    "trojan_real": {
        "script": "trojan_real.sh",
        "label": "lineage",
        "seed_dir": "/tmp/lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1071.001,T1059.004,T1003,T1053.003,T1543.002",
    },
}


ATOMIC_TIMEOUT_DEFAULT = 240   # วินาทีต่อ atomic 1 test

# process ใน VM ที่เคยค้างรอ password/passphrase (gpg, ccrypt ใน T1486)
# ใส่ [ ] คั่นตัวอักษร ไม่ให้ pkill ฆ่า shell ที่รันคำสั่งนี้เอง
STUCK_PATTERNS = [
    "Invoke-Atomic[T]est",
    "run_atomi[c].sh",
    "pinentr[y]",
    "gpg-agen[t]",
    "ccryp[t]",
]


def run(cmd, capture=False, check=True, timeout=None):
    """stdin=DEVNULL เสมอ - process ที่ถาม password จะได้ EOF แทนที่จะค้างรอ terminal"""
    print(f"    $ {' '.join(cmd)}")
    if capture:
        r = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=timeout)
        return r.stdout + r.stderr
    r = subprocess.run(cmd, cwd=LAB_DIR, check=check,
                       stdin=subprocess.DEVNULL, timeout=timeout)
    return r.returncode


# ---- vagrant wrappers (แต่ละอันจะกลายเป็น API endpoint ของ dashboard) ----
def vm_status():          return run(["vagrant", "status"], capture=True)
def list_snapshots(vm):   return run(["vagrant", "snapshot", "list", vm], capture=True)
def snapshot_save(vm):    run(["vagrant", "snapshot", "save", vm, CLEAN_SNAPSHOT, "--force"])
def snapshot_restore(vm): run(["vagrant", "snapshot", "restore", vm, CLEAN_SNAPSHOT, "--no-provision"])
def vm_up(vm):            run(["vagrant", "up", vm])
def vm_halt(vm):          run(["vagrant", "halt", vm])


def vm_kill_stuck(vm):
    """ฆ่า process ที่ค้างรอ input ใน VM (เรียกหลัง vm_exec timeout)"""
    sweep = " ; ".join(f"sudo pkill -KILL -f '{p}'" for p in STUCK_PATTERNS)
    try:
        run(["vagrant", "ssh", vm, "-c", sweep + " ; true"], check=False, timeout=90)
    except subprocess.TimeoutExpired:
        print(f"    [!] เก็บกวาด {vm} ไม่สำเร็จ - VM จะถูก revert รอบหน้าอยู่แล้ว")


def vm_exec(vm, command, timeout=None):
    """รันคำสั่งใน VM แบบไม่มี stdin
    ถ้าค้างเกิน timeout -> ตัด ssh ทิ้ง เก็บกวาด process แล้วไปต่อ (ไม่ล้มทั้งรอบ)"""
    try:
        rc = run(["vagrant", "ssh", vm, "-c", command], check=False, timeout=timeout)
        if rc not in (0, None):
            print(f"    [i] คำสั่งจบด้วย exit {rc} (ไปต่อ)")
        return True
    except subprocess.TimeoutExpired:
        print(f"    [!] คำสั่งใน {vm} ค้างเกิน {timeout} วินาที - ตัดทิ้งแล้วเก็บกวาด")
        vm_kill_stuck(vm)
        return False


def run_pipeline(raw_log, scenario_name, spec):
    """parse -> enrich -> label อัตโนมัติหลังเก็บ log เสร็จ"""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    stem = Path(raw_log).stem
    events = DATASET_DIR / f"{stem}_events.csv"
    enriched = DATASET_DIR / f"{stem}_enriched.csv"
    labeled = DATASET_DIR / f"{stem}_labeled.csv"

    print("\n[pipeline] parse...")
    subprocess.run(["python", str(HOST_DIR / "parse_sysmon.py"),
                    str(raw_log), "-o", str(events),
                    "--session", scenario_name], check=True)

    print("[pipeline] enrich...")
    subprocess.run(["python", str(HOST_DIR / "enrich_events.py"),
                    str(events), "-o", str(enriched),
                    "--platform", "linux"], check=True)

    print("[pipeline] label...")
    label_spec = spec["label"]
    cmd = ["python", str(HOST_DIR / "label_events.py"),
           str(enriched), "-o", str(labeled)]
    if label_spec.startswith("session:"):
        value = label_spec.split(":", 1)[1]
        cmd += ["--mode", "session", "--label", value]
    else:  # lineage
        cmd += ["--mode", "lineage"]
        if spec.get("seed_dir"):
            cmd += ["--seed-dir", spec["seed_dir"]]
        if spec.get("seed_cmd"):
            cmd += ["--seed-cmd", spec["seed_cmd"]]
        if spec.get("seed_image"):
            cmd += ["--seed-image", spec["seed_image"]]
    subprocess.run(cmd, check=True)
    print(f"[pipeline] เสร็จ -> {labeled}")
    return labeled


def run_scenario(name, vm, duration_min, repeat=True, atomic_timeout=ATOMIC_TIMEOUT_DEFAULT):
    if name not in SCENARIOS:
        print(f"[!] ไม่รู้จัก scenario '{name}'  (มี: {', '.join(SCENARIOS)})")
        return
    spec = SCENARIOS[name]
    script = SCENARIO_DIR / spec["script"]

    started = datetime.now(timezone.utc)
    print(f"\n{'='*58}")
    print(f"  SCENARIO : {name}   ({spec['label']})")
    print(f"  VM       : {vm}")
    print(f"  DURATION : {duration_min} นาที")
    print(f"  ATOMIC   : timeout {atomic_timeout} วินาที/test")
    print(f"{'='*58}\n")

    preflight_ssh_key(vm)
    print("[1/6] คืนสภาพ VM -> clean snapshot")
    snapshot_restore(vm)

    print("[2/6] บูต VM")
    vm_up(vm)
    time.sleep(12)   # รอ sysmon/rsyslog พร้อม

    # snapshot restore คืน memory state มาด้วย -> rsyslogd ตื่นมาพร้อม TCP socket เก่า
    # ที่ฝั่ง host ตายไปแล้ว ส่งข้อมูลออกไปก็ไม่มีใคร ACK (Send-Q ค้าง) = log ไม่ถึง host เลย
    # ต้องบังคับให้ต่อใหม่ทุกครั้งหลังบูต
    # sysmon ก็เจอปัญหาเดียวกัน: eBPF probe ที่ถูกคืนมาจาก memory snapshot อยู่ในสภาพ stale
    # -> หยุดยิง FileCreate(11) และ RawAccessRead(9) เงียบๆ ทั้งรอบ (event อื่นยังมาปกติ)
    # ยืนยันแล้ว: restart แล้ว event 11 กลับมา 108 ตัวใน 15 วินาที
    print("    รีสตาร์ท sysmon + rsyslog (กัน eBPF/TCP socket ค้างจาก snapshot)")
    vm_exec(vm, "sudo systemctl restart sysmon", timeout=120)
    time.sleep(5)
    vm_exec(vm, "sudo systemctl restart rsyslog", timeout=120)
    time.sleep(3)

    print(f"[3/6] รัน scenario: {name}")
    if script.exists():
        # สำคัญ: ก๊อปสคริปต์เข้า /tmp/lab_sandbox ก่อนรัน
        # เพื่อให้ทุก process สืบสายจาก sandbox -> lineage labeling จับได้ครบ
        rel = script.relative_to(LAB_DIR).as_posix()
        setup = (
            "sudo mkdir -p /tmp/lab_sandbox && "
            "sudo cp /vagrant/scenarios/_lib.sh /tmp/lab_sandbox/ && "
            f"sudo cp /vagrant/{rel} /tmp/lab_sandbox/ && "
            "sudo chmod +x /tmp/lab_sandbox/*.sh"
        )
        vm_exec(vm, setup, timeout=180)

        deadline = time.time() + duration_min * 60
        loop = 0
        # วนซ้ำ scenario จนครบเวลา (ได้ event หนาแน่นกว่ารอเปล่า)
        while time.time() < deadline:
            loop += 1
            print(f"    -- รอบที่ {loop} (เหลือ {int(deadline - time.time())} วินาที) --")
            # timeout ฝั่ง VM ตัดที่ต้นทาง (ฆ่าทั้ง process group)
            # timeout ฝั่ง host เผื่อไว้อีกชั้นกรณี ssh เองค้าง
            cap = int(max(180, deadline - time.time() + 120))
            vm_exec(vm,
                    f"sudo timeout --kill-after=30s {cap}s "
                    f"env ATOMIC_TIMEOUT={atomic_timeout} "
                    f"bash /tmp/lab_sandbox/{script.name}",
                    timeout=cap + 90)
            if time.time() >= deadline:
                break
            if not repeat:
                remain = deadline - time.time()
                if remain > 0:
                    print(f"    ...ไม่ repeat, รอเก็บ log อีก {int(remain)} วินาที")
                    time.sleep(remain)
                break
        print(f"    รวม {loop} รอบ")
    else:
        print(f"    [!] ยังไม่มีสคริปต์ {script}")
        print(f"    [!] สร้างไฟล์นี้ก่อน (ตามแนวทางที่เลือก) แล้วรันใหม่")
        print(f"    [i] ระหว่างนี้เก็บ log ว่างๆ เป็น baseline {duration_min} นาที")
        time.sleep(duration_min * 60)

    print("[4/6] รอ log ไหลจนหมด")
    time.sleep(5)

    print("[5/6] ปิด VM")
    vm_halt(vm)

    ended = datetime.now(timezone.utc)

    # หา log ล่าสุด (listener สร้างไว้)
    logs = sorted(LOG_DIR.glob("*.log"), key=lambda p: p.stat().st_mtime)
    raw_log = logs[-1] if logs else None

    meta = {
        "scenario": name, "vm": vm,
        "start_utc": started.isoformat(), "end_utc": ended.isoformat(),
        "duration_min": duration_min, "label_spec": spec["label"],
        "raw_log": str(raw_log) if raw_log else None,
    }
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    meta_file = LOG_DIR / f"{name}_{vm}_{started.strftime('%Y%m%d_%H%M%S')}_meta.json"
    meta_file.write_text(json.dumps(meta, indent=2))
    print(f"[6/6] metadata -> {meta_file}")

    # ต่อ pipeline อัตโนมัติ
    if raw_log:
        try:
            run_pipeline(raw_log, name, spec)
        except subprocess.CalledProcessError as e:
            print(f"[!] pipeline ล้ม: {e}")
    else:
        print("[!] ไม่พบ log - listener เปิดอยู่ไหม?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=list(SCENARIOS))
    ap.add_argument("--vm", default="target1")
    ap.add_argument("--duration", type=float, default=3, help="นาที")
    ap.add_argument("--no-repeat", action="store_true",
                    help="รัน scenario ครั้งเดียว แล้วรอเก็บ log เฉยๆ จนครบเวลา")
    ap.add_argument("--atomic-timeout", type=int, default=ATOMIC_TIMEOUT_DEFAULT,
                    help="วินาทีสูงสุดต่อ atomic 1 test (กันค้างรอ password)")
    ap.add_argument("--save-snapshot", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.status:
        print(vm_status()); return
    if args.list:
        print("Scenarios:")
        for k, v in SCENARIOS.items():
            print(f"  {k:<12} {v['label']:<12} script=scenarios/{v['script']}")
            if v.get("attack"):
                print(f"               ATT&CK: {v['attack']}")
        return
    if args.save_snapshot:
        print(f"[*] บันทึก clean snapshot ของ {args.vm}")
        snapshot_save(args.vm); print("[+] เสร็จ"); return

    if not args.scenario:
        ap.error("ต้องระบุ --scenario หรือ --save-snapshot / --status / --list")
    run_scenario(args.scenario, args.vm, args.duration, repeat=not args.no_repeat,
                 atomic_timeout=args.atomic_timeout)


if __name__ == "__main__":
    main()
"""
orchestrator_win.py - เก็บ dataset ฝั่ง Windows (คู่ขนานกับ orchestrator.py ของ Linux)

flow: revert -> up -> reload(remount shared folder) -> run .ps1 -> export EVTX ->
      halt -> parse(--platform windows) -> enrich -> label

ต่างจาก Linux 3 จุด:
  - reload หลัง revert  : VMware HGFS shared folder หลุดตอน revert/suspend
                          (Windows equivalent ของ Linux "restart sysmon หลัง revert")
  - winrm แทน ssh       : Windows communicator
  - export EVTX แทน realtime : Windows ไม่มี syslog -> batch export ตาม start time

ใช้งาน:
    python host/orchestrator_win.py --scenario benign
    python host/orchestrator_win.py --scenario trojan_win
    python host/orchestrator_win.py --save-snapshot
    python host/orchestrator_win.py --list
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
HOST_DIR = Path(__file__).resolve().parent
LOGWIN_DIR = HOST_DIR / "logs_win"
DATASET_DIR = HOST_DIR / "dataset"
CLEAN_SNAPSHOT = "clean"
VM = "wintarget"

# บังคับ utf-8 ให้ child process (เหมือน dashboard) กัน cp1252 crash ตอน print ไทย
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# ---------------------------------------------------------------- scenarios
# label = "session:0" -> benign / "lineage" -> ตาม seed (C:\lab_sandbox)
SCENARIOS = {
    "benign": {
        "script": "benign.ps1",
        "label": "session:0",
    },
    # benign เพิ่ม 8 ต.ค. 2026: คำสั่งชุดเดียวกับ ART แต่เป็นงานปกติ (ดู docstring ในสคริปต์)
    "benign_admin_win": {
        "script": "benign_admin_win.ps1",
        "label": "session:0",
    },
    "benign_dev_win": {
        "script": "benign_dev_win.ps1",
        "label": "session:0",
    },
    # scenario มัลแวร์ - ART-driven ทั้งหมด (ดู CLAUDE.md)
    # เลข atomic test ยืนยันกับ ART จริงบน wintarget แล้ว 23 ส.ค. 2026
    "ransomware_win": {
        "script": "ransomware_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1083,T1005,T1074.001,T1486,T1070.004",
    },
    "miner_win": {
        "script": "miner_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1082,T1057,T1105,T1496,T1053.005",
    },
    "botnet_win": {
        "script": "botnet_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1016,T1049,T1018,T1071.001,T1132.001,T1105",
    },
    "trojan_win": {
        "script": "trojan_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1082,T1033,T1057,T1087.001,T1059.001,T1547.001,"
                  "T1053.005,T1112,T1005,T1074.001,T1027,T1036.003",
    },
    "exploit_win": {
        "script": "exploit_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1069.001,T1012,T1497.001,T1552.001,T1548.002,"
                  "T1134.001,T1134.002,T1055,T1218.011",
    },
    # scenario ใหม่ (16 ก.ย. 2026) เพิ่มความหลากหลาย + คู่กับ Zeek fusion
    # c2_dns_win : DNS C2/tunneling - ต้องเปิด host/dns_server.py (Administrator)
    "c2_dns_win": {
        "script": "c2_dns_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1071.004,T1048.003,T1132.001,T1016,T1018,T1049,"
                  "T1059.001,T1071.001,T1105",
    },
    # injection_win : อุดช่องว่าง CreateRemoteThread (EventID 8) ที่มีแค่ 4 แถว
    "injection_win": {
        "script": "injection_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1057,T1055",
    },
    # initial_access_win : execution chain ลึก (proxy-exec -> script host -> payload)
    "initial_access_win": {
        "script": "initial_access_win.ps1",
        "label": "lineage",
        "seed_dir": r"C:\lab_sandbox",
        "seed_cmd": "lab_sandbox",
        "attack": "T1204.002,T1218.011,T1218.005,T1059.001,T1059.003,"
                  "T1105,T1547.001,T1036.003",
    },
}


def run(cmd, capture=False, check=True, timeout=None):
    print(f"    $ {' '.join(cmd)}")
    if capture:
        r = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return r.stdout + (r.stderr or "")
    r = subprocess.run(cmd, cwd=LAB_DIR, check=check,
                       stdin=subprocess.DEVNULL, timeout=timeout)
    return r.returncode


# ---- vagrant wrappers ----
def snapshot_save():    run(["vagrant", "snapshot", "save", VM, CLEAN_SNAPSHOT, "--force"])
def snapshot_restore(): run(["vagrant", "snapshot", "restore", VM, CLEAN_SNAPSHOT, "--no-provision"], timeout=900)
def vm_up():            run(["vagrant", "up", VM], timeout=900)
def vm_halt():          run(["vagrant", "halt", VM], timeout=300)


def winrm(command, timeout=600):
    """รันคำสั่ง PowerShell ใน VM ผ่าน winrm"""
    try:
        return run(["vagrant", "winrm", VM, "-c", command], check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"    [!] winrm ค้างเกิน {timeout}s")
        return None


def winrm_ps1(vm_path, timeout=900):
    """รัน .ps1 ใน VM (ผ่าน powershell -File เลี่ยง & escaping)"""
    return winrm(f"powershell -ExecutionPolicy Bypass -File {vm_path}", timeout=timeout)


# ---------------------------------------------------------------- pipeline
def run_pipeline_win(raw_xml, scenario_name, spec):
    """parse(windows) -> enrich(windows) -> label"""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    stem = Path(raw_xml).stem
    events = DATASET_DIR / f"{stem}_events.csv"
    enriched = DATASET_DIR / f"{stem}_enriched.csv"
    labeled = DATASET_DIR / f"{stem}_labeled.csv"

    print("\n[pipeline] parse (windows)...")
    subprocess.run(["python", str(HOST_DIR / "parse_sysmon.py"),
                    str(raw_xml), "-o", str(events),
                    "--session", scenario_name, "--platform", "windows"], check=True)

    print("[pipeline] enrich (windows)...")
    subprocess.run(["python", str(HOST_DIR / "enrich_events.py"),
                    str(events), "-o", str(enriched),
                    "--platform", "windows"], check=True)

    print("[pipeline] label...")
    cmd = ["python", str(HOST_DIR / "label_events.py"), str(enriched), "-o", str(labeled)]
    label_spec = spec["label"]
    if label_spec.startswith("session:"):
        cmd += ["--mode", "session", "--label", label_spec.split(":", 1)[1]]
    else:
        cmd += ["--mode", "lineage"]
        if spec.get("seed_dir"):
            cmd += ["--seed-dir", spec["seed_dir"]]
        if spec.get("seed_cmd"):
            cmd += ["--seed-cmd", spec["seed_cmd"]]
    subprocess.run(cmd, check=True)
    print(f"[pipeline] เสร็จ -> {labeled}")
    return labeled


# ---------------------------------------------------------------- scenario
def run_scenario(name, duration_min=5, repeat=True):
    if name not in SCENARIOS:
        print(f"[!] ไม่รู้จัก scenario '{name}'  (มี: {', '.join(SCENARIOS)})")
        return
    spec = SCENARIOS[name]
    script = LAB_DIR / "scenarios_win" / spec["script"]

    started = datetime.now(timezone.utc)
    print(f"\n{'='*58}")
    print(f"  SCENARIO : {name}   ({spec['label']})   [Windows]")
    print(f"{'='*58}\n")

    print("[1/6] คืนสภาพ VM -> clean snapshot (powered-off)")
    snapshot_restore()

    # snapshot save ตอน VM halt (powered-off) -> restore แล้วต้อง full boot
    # (snapshot ตอน running ทำ network/winrm ไม่ setup หลัง restore -> fail)
    # up = boot + network + shared folder setup ใหม่ (เห็น "Enabling shared folders")
    print("[2/6] up VM (full boot -> network + shared folder setup)")
    vm_up()
    time.sleep(8)

    if not script.exists():
        print(f"    [!] ยังไม่มีสคริปต์ {script} - ข้าม")
        return

    # start time = ก่อนรัน scenario -> export filter เฉพาะ event ของ scenario (ตัด boot noise)
    scenario_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"[3/6] setup sandbox + รัน scenario: {name}")
    # copy _lib.ps1 + scenario เข้า C:\lab_sandbox (seed ของ lineage)
    setup = (
        "New-Item -ItemType Directory -Path C:\\lab_sandbox -Force | Out-Null; "
        "Copy-Item C:\\vagrant\\scenarios_win\\_lib.ps1 C:\\lab_sandbox\\ -Force; "
        f"Copy-Item C:\\vagrant\\scenarios_win\\{spec['script']} C:\\lab_sandbox\\ -Force"
    )
    winrm(f"powershell -Command \"{setup}\"", timeout=180)

    # timeout ของ winrm ต้องเผื่อกรณี atomic ค้างจนโดน $AtomicTimeout ตัดหลายตัวติดกัน
    # 23 ส.ค. 2026: duration 6 -> 660s ไม่พอ trojan_win โดนตัดกลางคันที่ stage สุดท้าย
    # ทำให้ไม่ได้รัน cleanup -> ใช้พื้นล่าง 2400s (ไม่ถ่วงรอบที่จบเร็ว เพราะรอจนคำสั่งคืนค่า)
    script_timeout = max(int(duration_min * 60 + 300), 2400)

    # วนซ้ำจนครบเวลา - เหมือน orchestrator.py ฝั่ง Linux
    #
    # 23 ส.ค. 2026: เดิมรันครั้งเดียว --duration จึงมีผลแค่กับ timeout ไม่ได้เพิ่มข้อมูล
    # ผลคือฝั่ง Windows เก็บได้น้อยกว่า Linux หลายเท่าโดยไม่มีใครสังเกต
    #   benign_win  528 แถว  vs  benign (Linux)  5,330 แถว
    #   Windows รวม 3,546    vs  Linux รวม      24,583
    # ทำให้สัดส่วน label สองแพลตฟอร์มต่างกัน 33.5 จุด -> platform กลายเป็น proxy ของ label
    # (ดู host/check_merge.py)
    deadline = time.time() + duration_min * 60
    loop = 0
    while True:
        loop += 1
        remain = int(deadline - time.time())
        print(f"    -- รอบที่ {loop} (เหลือ {max(remain,0)} วินาที) --")
        winrm_ps1(f"C:\\lab_sandbox\\{spec['script']}", timeout=script_timeout)
        if time.time() >= deadline or not repeat:
            break
    print(f"    รวม {loop} รอบ")

    print("[4/6] export Sysmon events -> XML")
    session_tag = f"{name}_{started.strftime('%H%M%S')}"
    winrm(f"powershell -ExecutionPolicy Bypass -File "
          f"C:\\vagrant\\provision\\windows\\export_sysmon_win.ps1 "
          f"-Session {session_tag} -StartUtc {scenario_start}", timeout=600)

    print("[5/6] ปิด VM")
    vm_halt()

    ended = datetime.now(timezone.utc)

    # หา XML ล่าสุด (export เขียนไป logs_win ผ่าน shared folder)
    LOGWIN_DIR.mkdir(parents=True, exist_ok=True)
    xmls = sorted(LOGWIN_DIR.glob(f"{session_tag}_*.xml"), key=lambda p: p.stat().st_mtime)
    raw_xml = xmls[-1] if xmls else None

    meta = {
        "scenario": name, "vm": VM, "platform": "windows",
        "start_utc": started.isoformat(), "end_utc": ended.isoformat(),
        "scenario_start_utc": scenario_start, "label_spec": spec["label"],
        "raw_xml": str(raw_xml) if raw_xml else None,
    }
    meta_file = LOGWIN_DIR / f"{session_tag}_meta.json"
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[6/6] metadata -> {meta_file}")

    if raw_xml:
        try:
            run_pipeline_win(raw_xml, name, spec)
        except subprocess.CalledProcessError as e:
            print(f"[!] pipeline ล้ม: {e}")
    else:
        print("[!] ไม่พบ XML - export ทำงานไหม? shared folder sync ไหม?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=list(SCENARIOS))
    ap.add_argument("--duration", type=float, default=5, help="นาที (วนซ้ำ scenario จนครบเวลา)")
    ap.add_argument("--no-repeat", action="store_true",
                    help="รัน scenario ครั้งเดียว ไม่วนซ้ำ (เดิมเป็นแบบนี้)")
    ap.add_argument("--save-snapshot", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        print("Scenarios (Windows):")
        for k, v in SCENARIOS.items():
            print(f"  {k:<18} {v['label']:<12} {v.get('attack','')}")
        return
    if args.save_snapshot:
        print(f"[*] บันทึก clean snapshot ของ {VM}")
        snapshot_save(); print("[+] เสร็จ"); return
    if not args.scenario:
        ap.error("ต้องระบุ --scenario หรือ --save-snapshot / --list")
    run_scenario(args.scenario, args.duration, repeat=not args.no_repeat)


if __name__ == "__main__":
    main()

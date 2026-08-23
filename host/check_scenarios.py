"""
check_scenarios.py - ตรวจ scenario ฝั่ง Windows แบบ static ก่อนเอาไปเก็บข้อมูลจริง

ตรวจ 6 อย่างที่เคยพลาดมาแล้วจริงในโปรเจคนี้:

  1. encoding      - .ps1 ต้องเป็น UTF-8 with BOM (PowerShell 5.1 อ่าน ANSI แล้วคอมเมนต์ไทยเละ)
  2. เลขว่าง       - `Atomic "T####"` ที่ไม่ระบุเลข = รันทุก test ของ technique นั้น (อันตราย)
  3. deny list     - technique ที่ห้ามรัน (T1490/T1485/T1561/T1529/T1491)
  4. cleanup       - technique ที่ทิ้ง artifact ต้องมี Atomic-Cleanup และเลขต้องตรงกับตอนเรียก
  5. เลข test จริง - cross-check กับ atomic_report_win.txt ที่ check_atomics.ps1 สร้าง
  6. ทะเบียน       - ทุก scenario ต้องอยู่ใน SCENARIOS ของ orchestrator_win

ใช้งาน:
    python host/check_scenarios.py
    python host/check_scenarios.py --report atomic_report_win.txt

exit code 0 = ผ่านหมด, 1 = มีปัญหา (เอาไปใส่ CI ได้)
"""
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
import glob
import os
import re

HOST_DIR = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HOST_DIR)
SCEN_DIR = os.path.join(LAB_DIR, "scenarios_win")

DENY_TECH = {"T1490", "T1485", "T1561", "T1529", "T1491"}

# technique ที่ทิ้ง artifact ไว้ในเครื่อง -> ต้องมี Atomic-Cleanup คู่กัน
# (ไม่ใช่แค่ persistence - T1105 โหลดไฟล์ลงเครื่อง, T1074.001 staging ฯลฯ)
NEEDS_CLEANUP = {
    "T1547.001": "Registry Run key",
    "T1053.005": "Scheduled Task",
    "T1112": "Modify Registry",
    "T1036.003": "ไฟล์ที่ปลอมชื่อ",
    "T1074.001": "ไฟล์ staging",
    "T1027": "obfuscated payload",
    "T1105": "ไฟล์ที่โหลดมา",
    "T1552.001": "ไฟล์ credential ล่อ",
    "T1548.002": "การตั้งค่า UAC",
    "T1134.001": "token artifact",
    "T1134.002": "token artifact",
    "T1055": "process ที่ inject",
    "T1218.011": "ไฟล์/registry ของ rundll32",
    "T1486": "ไฟล์ที่ถูกเข้ารหัส",
    "T1071.001": "artifact ของ web protocol test",
    "T1496": "artifact ของ resource hijacking",
}

RE_ATOMIC = re.compile(r'^\s*Atomic\s+"(T[\d.]+)"(?:\s+"([\d,]*)")?', re.M)
RE_CLEAN = re.compile(r'^\s*Atomic-Cleanup\s+"(T[\d.]+)"(?:\s+"([\d,]*)")?', re.M)


def read_ps1(path):
    raw = open(path, "rb").read()
    has_bom = raw.startswith(b"\xef\xbb\xbf")
    if has_bom:
        raw = raw[3:]
    return has_bom, raw.decode("utf-8", errors="replace")


def strip_comments(text):
    """ตัดบรรทัดคอมเมนต์ออก เพื่อไม่ให้ตัวอย่างในคอมเมนต์ถูกนับเป็นการเรียกจริง"""
    return "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))


def load_report(path):
    """อ่าน atomic_report_win.txt -> {tech: {index: (name, executor, risky)}}"""
    avail = {}
    if not os.path.exists(path):
        return None
    tech = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = re.match(r"^\[(T[\d.]+)\]", line)
            if m:
                tech = m.group(1)
                avail.setdefault(tech, {})
                continue
            if line.startswith("====") or line.strip().startswith("PASTE"):
                tech = None
            if tech is None:
                continue
            m = re.match(r"^\s{4,}(\d+)\.\s(.{1,60}?)\s*\((\S+?)\)(.*)$", line)
            if m:
                idx, name, ex, rest = int(m.group(1)), m.group(2).strip(), m.group(3), m.group(4)
                avail[tech][idx] = (name, ex, ("***" in rest) or ex == "manual")
    return avail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=os.path.join(LAB_DIR, "atomic_report_win.txt"))
    args = ap.parse_args()

    problems = []
    notes = []
    files = sorted(glob.glob(os.path.join(SCEN_DIR, "*_win.ps1"))
                   + glob.glob(os.path.join(SCEN_DIR, "benign.ps1")))

    print("=" * 70)
    print("  ตรวจ scenario ฝั่ง Windows")
    print("=" * 70)

    # ---- 6) ทะเบียนใน orchestrator_win ----
    _sys.path.insert(0, HOST_DIR)
    try:
        import orchestrator_win as ow
        registered = {v["script"] for v in ow.SCENARIOS.values()}
    except Exception as e:
        registered = None
        problems.append(f"อ่าน orchestrator_win.SCENARIOS ไม่ได้: {e}")

    report = load_report(args.report)
    if report is None:
        notes.append(f"ไม่พบ {os.path.basename(args.report)} - ข้ามการตรวจเลข test จริง"
                     " (สร้างด้วย scenarios_win/check_atomics.ps1 ใน VM)")

    print(f"\n  {'ไฟล์':<22} {'BOM':<5} {'Atomic':>7} {'Cleanup':>8}")
    print("  " + "-" * 50)

    total_nums = 0
    for path in files:
        name = os.path.basename(path)
        has_bom, text = read_ps1(path)
        body = strip_comments(text)
        calls = RE_ATOMIC.findall(body)
        cleans = RE_CLEAN.findall(body)
        print(f"  {name:<22} {'✓' if has_bom else '✗':<5} {len(calls):>7} {len(cleans):>8}")

        # 1) encoding
        if not has_bom:
            problems.append(f"{name}: ไม่มี UTF-8 BOM (คอมเมนต์ไทยจะเพี้ยนบน PowerShell 5.1)")

        # 6) ทะเบียน
        if registered is not None and name not in registered:
            problems.append(f"{name}: ไม่อยู่ใน SCENARIOS ของ orchestrator_win")

        called = {}
        for tech, nums in calls:
            # 2) เลขว่าง
            if not nums:
                problems.append(f"{name}: Atomic \"{tech}\" ไม่ระบุเลข = รันทุก test ของ technique นั้น")
                continue
            # 3) deny list
            if tech in DENY_TECH:
                problems.append(f"{name}: เรียก {tech} ซึ่งอยู่ใน deny list")
            nl = [int(x) for x in nums.split(",") if x]
            called[tech] = nl
            total_nums += len(nl)

            # 5) cross-check กับรายงาน
            if report is not None:
                if tech not in report:
                    notes.append(f"{name}: {tech} ไม่มีในรายงาน (รายงานอาจเก่ากว่า scenario)")
                else:
                    for n in nl:
                        if n not in report[tech]:
                            have = ",".join(str(i) for i in sorted(report[tech]))
                            problems.append(
                                f"{name}: {tech} test {n} ไม่ใช่ windows test (มีจริง: {have})")
                        elif report[tech][n][2]:
                            problems.append(
                                f"{name}: {tech} test {n} ติด flag อันตราย/manual"
                                f" — {report[tech][n][0]}")

        cleaned = {t: [int(x) for x in (n or "").split(",") if x] for t, n in cleans}

        # 4) cleanup ครบและเลขตรง
        for tech, nl in called.items():
            if tech not in NEEDS_CLEANUP:
                continue
            if tech not in cleaned:
                problems.append(f"{name}: {tech} ({NEEDS_CLEANUP[tech]}) ไม่มี Atomic-Cleanup")
            elif sorted(cleaned[tech]) != sorted(nl):
                problems.append(
                    f"{name}: {tech} cleanup เลขไม่ตรงกับตอนเรียก"
                    f" (เรียก {','.join(map(str,nl))} / ล้าง {','.join(map(str,cleaned[tech]))})")
        for tech in cleaned:
            if tech not in called:
                notes.append(f"{name}: cleanup {tech} ทั้งที่ไม่ได้เรียก Atomic ตัวนั้น")

    print(f"\n  เลข test รวม {total_nums} ตัว")

    if notes:
        print("\n" + "=" * 70)
        print("  หมายเหตุ (ไม่ถือว่าผิด)")
        print("=" * 70)
        for n in sorted(set(notes)):
            print(f"  - {n}")

    print("\n" + "=" * 70)
    if problems:
        print(f"  พบปัญหา {len(problems)} จุด")
        print("=" * 70)
        for p in problems:
            print(f"  [!] {p}")
        return 1
    print("  ผ่านทั้งหมด - ไม่พบ error")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    _sys.exit(main())

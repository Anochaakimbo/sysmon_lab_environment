"""
run_zeek.py - แปลง pcap -> Zeek logs -> CSV แถวละ flow

Zeek รันบน Windows ไม่ได้ ไฟล์นี้จึงเป็นตัวห่อ backend 3 แบบ (auto-detect ตามลำดับ):
    native  zeek อยู่ใน PATH แล้ว (WSL ที่ตั้ง interop / MSYS)
    wsl     wsl -e zeek           (ต้อง `wsl --install Ubuntu` + `apt install zeek`)
    docker  docker run zeek/zeek  (ต้องเปิด Docker Desktop ก่อน)

⚠️ ใช้ `zeek -C` เสมอ
   NIC ของ host ทำ checksum offload -> packet ที่ capture ได้มี checksum ผิด
   ถ้าไม่ใส่ -C Zeek จะทิ้ง packet เหล่านั้นเงียบๆ แล้วได้ conn.log ที่ว่างหรือขาด
   (ความล้มเหลวแบบเงียบชนิดเดียวกับ Defender บล็อก atomic test)

ใช้งาน:
    python host/run_zeek.py --session botnet_win_001
    python host/run_zeek.py --all               # ทำทุก pcap ที่ยังไม่มี CSV
    python host/run_zeek.py --all --force       # ทับของเดิม
    python host/run_zeek.py --check             # เช็คว่ามี backend ไหนใช้ได้บ้าง

ผลลัพธ์:
    host/zeek/<session>/*.log          Zeek logs ดิบ (conn/dns/http/ssl/files/...)
    host/dataset/<session>_zeek.csv    แถวละ flow พร้อม enrich จาก dns/http/ssl/files
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
import csv
import shutil
import subprocess
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parent
PCAP_DIR = HOST_DIR / "pcap"
ZEEK_DIR = HOST_DIR / "zeek"
DATASET_DIR = HOST_DIR / "dataset"

ZEEK_IMAGE = "zeek/zeek:latest"

# คอลัมน์ผลลัพธ์ - conn.log เป็นแกน แล้ว join log อื่นด้วย uid
CONN_COLS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
]
# log เสริม: uid -> คอลัมน์ที่ดึงมา (prefix ผลลัพธ์)
ENRICH = {
    "dns":   ("dns",   ["query", "qtype_name", "rcode_name", "answers"]),
    "http":  ("http",  ["method", "host", "uri", "user_agent", "status_code",
                        "request_body_len", "response_body_len"]),
    "ssl":   ("ssl",   ["server_name", "version", "cipher", "established"]),
    "files": ("files", ["mime_type", "filename", "total_bytes", "md5"]),
}

OUT_COLS = (["session"] + CONN_COLS +
            [p + "_" + c for p, cols in ENRICH.values() for c in cols])


# ------------------------------------------------------------------ backend
def _have(cmd):
    return shutil.which(cmd) is not None


def _run(cmd, timeout=900, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd,
                          stdin=subprocess.DEVNULL, encoding="utf-8",
                          errors="replace", timeout=timeout)


def detect_backend(prefer=None):
    """คืนชื่อ backend ที่ใช้ได้จริง (ทดสอบด้วย `zeek --version` ไม่ใช่แค่ดูว่ามีคำสั่ง)"""
    order = [prefer] if prefer else ["native", "wsl", "docker"]
    notes = []

    for b in order:
        if b == "native" and _have("zeek"):
            r = _run(["zeek", "--version"], timeout=60)
            if r.returncode == 0:
                return "native", (r.stdout or "").strip()
            notes.append("native: zeek --version exit {}".format(r.returncode))

        elif b == "wsl" and _have("wsl"):
            r = _run(["wsl", "-e", "zeek", "--version"], timeout=120)
            if r.returncode == 0:
                return "wsl", (r.stdout or "").strip()
            notes.append("wsl: " + ((r.stderr or r.stdout or "").strip()[:120]))

        elif b == "docker" and _have("docker"):
            r = _run(["docker", "run", "--rm", ZEEK_IMAGE, "zeek", "--version"],
                     timeout=600)
            if r.returncode == 0:
                return "docker", (r.stdout or "").strip()
            notes.append("docker: " + ((r.stderr or r.stdout or "").strip()[:120]))

    raise RuntimeError(
        "ไม่พบ Zeek ที่ใช้งานได้เลย\n" +
        ("\n".join("  - " + n for n in notes) + "\n" if notes else "") +
        "\nเลือกติดตั้งทางใดทางหนึ่ง:\n"
        "  [WSL]    wsl --install Ubuntu\n"
        "           wsl -e bash -c \"sudo apt update && sudo apt install -y zeek\"\n"
        "           (ถ้า apt ไม่มี zeek ให้ใช้ repo ของ OpenSUSE Build Service ตาม\n"
        "            https://docs.zeek.org/en/current/install.html#binary-packages)\n"
        "  [Docker] เปิด Docker Desktop แล้ว  docker pull " + ZEEK_IMAGE + "\n"
        "           และต้องแชร์ไดรฟ์ S: ใน Settings > Resources > File sharing"
    )


def _wslpath(p):
    r = _run(["wsl", "-e", "wslpath", "-a", str(p).replace("\\", "/")], timeout=60)
    if r.returncode != 0:
        raise RuntimeError("wslpath แปลง path ไม่ได้: {}".format(r.stderr))
    return (r.stdout or "").strip()


def run_zeek(pcap, outdir, backend, verbose=False):
    """รัน zeek -C -r <pcap> โดยให้ cwd = outdir (Zeek เขียน .log ลง cwd)"""
    outdir.mkdir(parents=True, exist_ok=True)
    for old in outdir.glob("*.log"):
        old.unlink()

    if backend == "native":
        cmd = ["zeek", "-C", "-r", str(pcap)]
        r = _run(cmd, cwd=str(outdir))
    elif backend == "wsl":
        cmd = ["wsl", "-e", "bash", "-lc",
               "cd {} && zeek -C -r {}".format(_wslpath(outdir), _wslpath(pcap))]
        r = _run(cmd)
    elif backend == "docker":
        pd = str(pcap.parent).replace("\\", "/")
        od = str(outdir).replace("\\", "/")
        cmd = ["docker", "run", "--rm",
               "-v", pd + ":/pcap:ro", "-v", od + ":/out", "-w", "/out",
               ZEEK_IMAGE, "zeek", "-C", "-r", "/pcap/" + pcap.name]
        r = _run(cmd)
    else:
        raise RuntimeError("backend ไม่รู้จัก: {}".format(backend))

    if verbose and (r.stdout or r.stderr):
        print("    zeek: " + ((r.stdout or "") + (r.stderr or "")).strip()[:500])

    logs = sorted(outdir.glob("*.log"))
    if r.returncode != 0 and not logs:
        raise RuntimeError(
            "zeek ล้มเหลว (exit {})\n  cmd: {}\n  {}".format(
                r.returncode, " ".join(cmd),
                ((r.stderr or r.stdout or "").strip())[:800])
        )
    return logs


# ------------------------------------------------------------------ parser
def read_zeek_log(path):
    """อ่าน Zeek TSV -> list[dict] (รองรับ #separator / #unset_field)"""
    rows = []
    fields, sep, unset, empty = None, "\t", "-", "(empty)"
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#"):
                if line.startswith("#separator"):
                    raw = line.split(" ", 1)[1].strip()
                    sep = raw.encode().decode("unicode_escape") if raw.startswith("\\x") else raw
                elif line.startswith("#unset_field"):
                    unset = line.split(sep, 1)[1] if sep in line else "-"
                elif line.startswith("#empty_field"):
                    empty = line.split(sep, 1)[1] if sep in line else "(empty)"
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                continue
            if not line or fields is None:
                continue
            vals = line.split(sep)
            row = {}
            for k, v in zip(fields, vals):
                row[k] = "" if v in (unset, empty) else v
            rows.append(row)
    return rows


def build_csv(session, zdir, out_csv):
    """conn.log เป็นแกน + join dns/http/ssl/files ด้วย uid"""
    conn_path = zdir / "conn.log"
    if not conn_path.exists():
        raise RuntimeError(
            "ไม่มี conn.log ใน {}\n".format(zdir) +
            "  แปลว่า Zeek ไม่เห็น traffic เลย ตรวจ:\n"
            "    - pcap มี packet จริงไหม (host/pcap/*_pcapmeta.json)\n"
            "    - ลืม -C หรือเปล่า (checksum offload ทำให้ packet ถูกทิ้งหมด)"
        )
    conns = read_zeek_log(conn_path)

    # uid -> ค่าที่ดึงจาก log เสริม (เอาแถวแรกของ uid นั้น)
    side = {}
    counts = {}
    for name, (prefix, cols) in ENRICH.items():
        p = zdir / (name + ".log")
        counts[name] = 0
        if not p.exists():
            continue
        for row in read_zeek_log(p):
            counts[name] += 1
            uid = row.get("uid")
            if not uid:
                continue
            bucket = side.setdefault(uid, {})
            for c in cols:
                key = prefix + "_" + c
                if key not in bucket and row.get(c):
                    bucket[key] = row[c]

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLS, extrasaction="ignore")
        w.writeheader()
        for c in conns:
            row = {"session": session}
            for k in CONN_COLS:
                row[k] = c.get(k, "")
            row.update(side.get(c.get("uid", ""), {}))
            w.writerow(row)

    counts["conn"] = len(conns)
    return counts


def process(session, backend, force=False, verbose=False):
    pcap = PCAP_DIR / (session + ".pcapng")
    if not pcap.exists():
        alt = PCAP_DIR / (session + ".pcap")
        if alt.exists():
            pcap = alt
        else:
            raise RuntimeError("ไม่พบ pcap ของ session '{}' ใน {}".format(session, PCAP_DIR))

    out_csv = DATASET_DIR / (session + "_zeek.csv")
    if out_csv.exists() and not force:
        print("  [ข้าม] {} มีแล้ว (ใช้ --force เพื่อทับ)".format(out_csv.name))
        return None

    zdir = ZEEK_DIR / session
    print("  [zeek] {}  ({:,} bytes)".format(pcap.name, pcap.stat().st_size))
    logs = run_zeek(pcap, zdir, backend, verbose=verbose)
    print("  [zeek] ได้ {} log: {}".format(
        len(logs), ", ".join(p.stem for p in logs) or "(ไม่มี)"))

    counts = build_csv(session, zdir, out_csv)
    parts = ["conn={}".format(counts.get("conn", 0))]
    parts += ["{}={}".format(k, v) for k, v in counts.items() if k != "conn"]
    print("  [csv ] {} -> {}".format(", ".join(parts), out_csv.name))

    if counts.get("conn", 0) == 0:
        print("  [!]   conn.log ว่าง - ไม่มี flow ให้ fuse กับ Sysmon เลย")
    return counts


def main():
    ap = argparse.ArgumentParser(description="pcap -> Zeek -> CSV")
    ap.add_argument("--session", help="ชื่อ session (ไม่ต้องใส่ .pcapng)")
    ap.add_argument("--all", action="store_true", help="ทำทุก pcap ที่มี")
    ap.add_argument("--force", action="store_true", help="ทับ CSV เดิม")
    ap.add_argument("--backend", choices=["native", "wsl", "docker"],
                    help="บังคับ backend (ปกติ auto-detect)")
    ap.add_argument("--check", action="store_true", help="เช็ค backend แล้วออก")
    ap.add_argument("--list", action="store_true", help="แสดง pcap ที่มี")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.list:
        pcaps = sorted(list(PCAP_DIR.glob("*.pcapng")) + list(PCAP_DIR.glob("*.pcap")))
        if not pcaps:
            print("ไม่มี pcap ใน {} - รัน host/pcap_capture.py ก่อน".format(PCAP_DIR))
            return 1
        for p in pcaps:
            done = (DATASET_DIR / (p.stem + "_zeek.csv")).exists()
            print("  {:<50} {:>12,} bytes  {}".format(
                p.stem, p.stat().st_size, "[มี CSV แล้ว]" if done else ""))
        return 0

    backend, ver = detect_backend(args.backend)
    print("[zeek] backend = {}  ({})".format(backend, ver.splitlines()[0] if ver else ""))
    if args.check:
        return 0

    if args.all:
        pcaps = sorted(list(PCAP_DIR.glob("*.pcapng")) + list(PCAP_DIR.glob("*.pcap")))
        sessions = [p.stem for p in pcaps]
    elif args.session:
        sessions = [args.session]
    else:
        ap.error("ต้องระบุ --session หรือ --all (หรือ --list / --check)")

    if not sessions:
        print("ไม่มี pcap ให้ทำ")
        return 1

    ok = fail = 0
    for s in sessions:
        print("\n== {} ==".format(s))
        try:
            process(s, backend, force=args.force, verbose=args.verbose)
            ok += 1
        except RuntimeError as e:
            print("  [!] {}".format(e))
            fail += 1

    print("\nสรุป: สำเร็จ {} / ล้มเหลว {}".format(ok, fail))
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())

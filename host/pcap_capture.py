"""
pcap_capture.py - เก็บ network capture คู่ขนานกับ Sysmon (ฝั่ง host)

ทำไมต้องเก็บบน host ไม่ใช่ใน VM:
  - Zeek รันบน Windows ไม่ได้ และเราไม่อยากลง agent เพิ่มใน VM
    (ทุกอย่างที่ลงใน guest จะโผล่เป็น noise ใน Sysmon เอง)
  - capture บน vmnet adapter ของ host เห็น traffic ของ guest ทั้งหมด
    โดยที่ guest ไม่รู้ตัว = ไม่ปนเปื้อน host telemetry
  - ได้ .pcapng เป็น "raw source of truth" ตัวที่ 3 ต่อจาก logs/ และ logs_win/
    เปลี่ยนสคริปต์วิเคราะห์แล้วรันซ้ำได้โดยไม่ต้องเก็บ VM ใหม่

adapter ที่เก็บ (ดู `dumpcap -D`):
  VMnet1  192.168.56.1    host-only  <- beacon ไป c2_server.py / mining_pool.py
  VMnet8  192.168.205.1   NAT        <- T1105 โหลดไฟล์ออกอินเทอร์เน็ต

ใช้งาน:
    python host/pcap_capture.py --session botnet_win_001    # รันค้าง Ctrl-C เพื่อหยุด
    python host/pcap_capture.py --list                      # ดู adapter ที่เจอ
    python host/pcap_capture.py --session x --duration 600  # หยุดเองตามเวลา

เรียกจากโค้ดอื่น (dashboard/orchestrator):
    cap = PcapCapture("botnet_win_001"); cap.start(); ...; cap.stop()
"""

# บังคับ utf-8 ก่อนพิมพ์อะไรก็ตาม - console Windows เป็น cp1252 print ไทยแล้วตาย
# (บทเรียนเดียวกับ c2_server.py / mining_pool.py ที่เคยล้มเงียบจนพอร์ตไม่ขึ้น)
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
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parent
PCAP_DIR = HOST_DIR / "pcap"

# adapter ที่ต้องการเก็บ - match แบบ substring กับชื่อที่ dumpcap -D พิมพ์ออกมา
# ใช้ชื่อไม่ใช่เลข index เพราะ index เลื่อนได้เมื่อมี adapter มาเพิ่ม/หาย
WANT_IFACES = ["VMnet1", "VMnet8"]

_WIRESHARK_DIRS = [
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
]


def _find_tool(name):
    """หา dumpcap.exe / capinfos.exe - PATH ก่อน แล้วค่อยไล่ path มาตรฐาน"""
    found = shutil.which(name)
    if found:
        return found
    for d in _WIRESHARK_DIRS:
        p = Path(d) / (name + ".exe")
        if p.exists():
            return str(p)
    return None


def list_interfaces():
    """คืน [(index, description)] จาก `dumpcap -D`"""
    dumpcap = _find_tool("dumpcap")
    if not dumpcap:
        raise RuntimeError(
            "ไม่พบ dumpcap.exe\n"
            "  ติดตั้ง Wireshark ก่อน: https://www.wireshark.org/download.html\n"
            "  ตอนติดตั้งต้องติ๊ก Npcap ด้วย ไม่งั้นจับ packet ไม่ได้"
        )
    out = subprocess.run([dumpcap, "-D"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=60)
    ifaces = []
    for line in (out.stdout or "").splitlines():
        m = re.match(r"\s*(\d+)\.\s+(\S+)\s*(?:\((.*)\))?\s*$", line)
        if m:
            ifaces.append((int(m.group(1)), m.group(3) or m.group(2)))
    if not ifaces:
        raise RuntimeError(
            "dumpcap -D ไม่คืน adapter เลย\n"
            "  stdout: {!r}\n  stderr: {!r}\n".format(out.stdout, out.stderr) +
            "  มักแปลว่า Npcap ไม่ได้ติดตั้ง หรือต้องรันเป็น Administrator"
        )
    return ifaces


def resolve_targets(want=None):
    """map ชื่อ adapter ที่ต้องการ -> index จริง

    throw ถ้าไม่เจอสักตัว - ห้ามเงียบ เพราะ capture ว่างจะไม่มีอะไรบอก
    จนกว่าจะถึงขั้น fuse แล้วพบว่า match rate = 0
    """
    want = want or WANT_IFACES
    ifaces = list_interfaces()
    picked, missing = [], []
    for w in want:
        hit = next(((i, d) for i, d in ifaces if w.lower() in d.lower()), None)
        if hit:
            picked.append(hit)
        else:
            missing.append(w)
    if missing:
        have = "\n".join("    {}. {}".format(i, d) for i, d in ifaces)
        raise RuntimeError(
            "ไม่พบ adapter: {}\n".format(", ".join(missing)) +
            "  adapter ที่มีอยู่:\n" + have + "\n" +
            "  VMware ตั้ง VMnet ตามเครื่อง - ตรวจด้วย ipconfig แล้วแก้ WANT_IFACES"
        )
    return picked


def count_packets(pcap_path):
    """นับ packet ในไฟล์ - คืน None ถ้าไม่มี capinfos"""
    capinfos = _find_tool("capinfos")
    if not capinfos:
        return None
    try:
        out = subprocess.run([capinfos, "-c", "-M", str(pcap_path)],
                             capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=120)
        m = re.search(r"Number of packets\s*[:=]\s*(\d+)", out.stdout or "")
        return int(m.group(1)) if m else None
    except (subprocess.SubprocessError, ValueError):
        return None


class PcapCapture:
    """เก็บ pcap 1 ไฟล์ต่อ 1 session (ครอบทุก adapter ที่ระบุ)"""

    def __init__(self, session, ifaces=None, outdir=None):
        self.session = session
        self.want = ifaces or WANT_IFACES
        self.outdir = Path(outdir) if outdir else PCAP_DIR
        self.proc = None
        self.targets = None
        self.started_at = None
        self.pcap_path = self.outdir / (session + ".pcapng")
        self.meta_path = self.outdir / (session + "_pcapmeta.json")

    def start(self):
        self.outdir.mkdir(parents=True, exist_ok=True)
        dumpcap = _find_tool("dumpcap")
        if not dumpcap:
            raise RuntimeError("ไม่พบ dumpcap.exe - ติดตั้ง Wireshark + Npcap ก่อน")
        self.targets = resolve_targets(self.want)

        cmd = [dumpcap]
        for idx, _desc in self.targets:
            cmd += ["-i", str(idx)]
        # -q เงียบ  /  pcapng รองรับหลาย interface ในไฟล์เดียว (dumpcap >= 2.x)
        cmd += ["-q", "-w", str(self.pcap_path)]

        names = ", ".join("{}:{}".format(i, d) for i, d in self.targets)
        print("[pcap] เริ่มเก็บ  session={}".format(self.session))
        print("[pcap] adapter  {}".format(names))
        print("[pcap] ไฟล์      {}".format(self.pcap_path))
        self.started_at = datetime.now(timezone.utc)
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8",
                                     errors="replace")
        # dumpcap ที่เปิดไฟล์ไม่ได้/ไม่มีสิทธิ์จะตายภายในเสี้ยววินาที
        # ถ้าไม่เช็คตรงนี้ scenario จะวิ่งจนจบแล้วค่อยรู้ว่าไม่มี pcap
        time.sleep(2.0)
        if self.proc.poll() is not None:
            out = self.proc.stdout.read() if self.proc.stdout else ""
            raise RuntimeError(
                "dumpcap ตายทันทีหลังสตาร์ต (exit {})\n".format(self.proc.returncode) +
                "  " + (out or "").strip() + "\n" +
                "  สาเหตุที่พบบ่อย: Npcap ไม่ได้ติดตั้ง / ต้องรันเป็น Administrator"
            )
        return self

    def stop(self):
        """หยุด capture แล้วตรวจว่าได้ packet จริง"""
        if not self.proc:
            return None
        # ให้ dumpcap flush buffer สุดท้ายลงดิสก์ก่อน
        time.sleep(1.5)
        self.proc.terminate()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)
        stopped_at = datetime.now(timezone.utc)

        size = self.pcap_path.stat().st_size if self.pcap_path.exists() else 0
        pkts = count_packets(self.pcap_path) if size else 0
        meta = {
            "session": self.session,
            "pcap": str(self.pcap_path),
            "interfaces": [{"index": i, "desc": d} for i, d in (self.targets or [])],
            "started_utc": self.started_at.isoformat() if self.started_at else None,
            "stopped_utc": stopped_at.isoformat(),
            "bytes": size,
            "packets": pkts,
        }
        self.meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False),
                                  encoding="utf-8")

        shown = pkts if pkts is not None else "?"
        print("[pcap] หยุดแล้ว  {:,} bytes  {} packets  -> {}".format(
            size, shown, self.pcap_path))
        # เตือนดังๆ - pcap ว่างคือความล้มเหลวแบบเงียบที่จะไปโผล่ตอน fuse
        if not size or pkts == 0:
            print("[pcap] !!  ไม่ได้ packet เลย! ตรวจ:")
            print("         - VM บูตอยู่และมี traffic จริงไหม")
            print("         - เก็บถูก adapter ไหม (ipconfig เทียบ WANT_IFACES)")
            print("         - รัน Python เป็น Administrator หรือยัง (Npcap ต้องการ)")
        return meta

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


def main():
    ap = argparse.ArgumentParser(description="เก็บ pcap คู่ขนานกับ Sysmon")
    ap.add_argument("--session", help="ชื่อ session (ใช้ตั้งชื่อไฟล์)")
    ap.add_argument("--duration", type=float, default=0,
                    help="วินาที (0 = รันค้างจนกด Ctrl-C)")
    ap.add_argument("--iface", action="append",
                    help="ชื่อ adapter (ระบุซ้ำได้) default: VMnet1 + VMnet8")
    ap.add_argument("--list", action="store_true", help="แสดง adapter แล้วออก")
    args = ap.parse_args()

    if args.list:
        for i, d in list_interfaces():
            mark = "  <-- เก็บ" if any(w.lower() in d.lower() for w in WANT_IFACES) else ""
            print("  {:>2}. {}{}".format(i, d, mark))
        return 0

    if not args.session:
        ap.error("ต้องระบุ --session (หรือใช้ --list)")

    cap = PcapCapture(args.session, ifaces=args.iface)
    cap.start()
    try:
        if args.duration > 0:
            print("[pcap] เก็บ {:.0f} วินาที...".format(args.duration))
            time.sleep(args.duration)
        else:
            print("[pcap] กำลังเก็บ... กด Ctrl-C เพื่อหยุด")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[pcap] ได้รับ Ctrl-C")
    finally:
        cap.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

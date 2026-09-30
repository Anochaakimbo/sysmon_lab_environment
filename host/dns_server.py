"""
dns_server.py - DNS server จำลองในแล็บ (รันบน Windows host)

ใช้คู่กับ scenarios_win/c2_dns_win.ps1 เพื่อให้ VM มีปลายทาง DNS จริงให้ query
โดยไม่ต้องออกอินเทอร์เน็ต และไม่ต้องแตะ DNS จริงของใคร

ทำไมต้องมี:
    DNS tunneling / DNS-based C2 คือช่องทางที่ firewall แทบไม่เคยปิด
    เปเปอร์อ้างอิงไม่มี telemetry ชนิดนี้เลย (NetworkConnect 20 แถวทั้ง dataset)
    และเป็นเคสที่ Zeek (dns.log) กับ Sysmon (ev3 + ev22) เสริมกันชัดที่สุด:
        Zeek   เห็นชื่อ query ยาวผิดปกติ + entropy สูง  แต่ไม่รู้ว่า process ไหน
        Sysmon รู้ว่า process ไหน                        แต่ไม่เห็นเนื้อ query
    -> host/fuse_network.py รวมสองอย่างเข้าด้วยกัน

พอร์ต:
    53/udp   ตอบทุก A query ด้วย 192.168.56.1 และทุก TXT query ด้วยข้อความสั้น
             (ตอบให้ครบทุก query เพื่อไม่ให้ resolver ใน VM ค้าง retry)

⚠️ ต้องรันเป็น Administrator (พอร์ต < 1024)
⚠️ ถ้าเครื่องมี DNS server อื่นยึด :53 อยู่ (เช่น Docker Desktop, ICS) จะ bind ไม่ได้
   สคริปต์จะบอกตรงๆ ไม่ใช่ตายเงียบ

ใช้งาน:
    python host/dns_server.py
    python host/dns_server.py --port 5353     # ทดสอบโดยไม่ต้องเป็น admin
"""
import os
import sys

# บังคับ utf-8 ก่อนพิมพ์อะไรก็ตาม - console Windows เป็น cp1252 print ไทยแล้วตาย
# (บทเรียนเดียวกับที่ c2_server.py เคยล้มจนพอร์ตไม่ขึ้นแล้ว beacon ไม่ติดแบบเงียบ)
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import argparse
import socket
import struct
import threading
from collections import Counter
from datetime import datetime

LAB_IP = "192.168.56.1"

QTYPE = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}

STATS = Counter()
_lock = threading.Lock()


def parse_question(data):
    """แกะชื่อโดเมน + qtype จาก DNS query. คืน (qname, qtype, end_offset)"""
    if len(data) < 12:
        return None, 0, 0
    off = 12
    labels = []
    # กัน pointer loop / packet พิการ
    for _ in range(64):
        if off >= len(data):
            return None, 0, 0
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:                       # compression pointer - ไม่ควรมีใน question
            return None, 0, 0
        off += 1
        labels.append(data[off:off + ln].decode("utf-8", errors="replace"))
        off += ln
    if off + 4 > len(data):
        return None, 0, 0
    qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
    return ".".join(labels), qtype, off + 4


def build_response(data, qend, qtype):
    """สร้าง response ที่ตอบกลับได้จริง - A -> LAB_IP, TXT -> ข้อความสั้น, อื่นๆ -> NOERROR ว่าง"""
    tid = data[:2]
    question = data[12:qend]
    # QR=1 AA=1 RD copy จาก request
    rd = data[2] & 0x01
    flags = struct.pack("!H", 0x8400 | (0x0100 if rd else 0))

    if qtype == 1:                                   # A
        rdata = socket.inet_aton(LAB_IP)
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, len(rdata)) + rdata)
        ancount = 1
    elif qtype == 16:                                # TXT
        txt = b"lab-c2-ok"
        rdata = bytes([len(txt)]) + txt
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata)
        ancount = 1
    else:
        answer = b""
        ancount = 0

    header = tid + flags + struct.pack("!HHHH", 1, ancount, 0, 0)
    return header + question + answer


def serve(port, quiet=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except PermissionError:
        print("[dns] !! bind :{} ไม่ได้ - ต้องรัน PowerShell เป็น Administrator".format(port))
        return 1
    except OSError as e:
        print("[dns] !! bind :{} ไม่ได้ - {}".format(port, e))
        print("[dns]    มีโปรแกรมอื่นยึดพอร์ตอยู่? ตรวจด้วย:")
        print("[dns]      netstat -ano -p UDP | findstr :{}".format(port))
        print("[dns]    ตัวที่ยึด :53 บ่อยๆ คือ Docker Desktop และ Internet Connection Sharing")
        return 1

    print("[dns] DNS server ในแล็บพร้อม  0.0.0.0:{}/udp".format(port))
    print("[dns] ตอบ A -> {} , TXT -> 'lab-c2-ok' , อื่นๆ -> NOERROR ว่าง".format(LAB_IP))
    print("[dns] ตั้งใน VM:  netsh interface ip set dns \"Ethernet1\" static {}".format(LAB_IP))
    print("[dns] กด Ctrl-C เพื่อหยุด\n")

    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            break
        except OSError:
            continue

        qname, qtype, qend = parse_question(data)
        if not qname:
            continue

        with _lock:
            STATS["total"] += 1
            STATS[QTYPE.get(qtype, str(qtype))] += 1
            n = STATS["total"]

        try:
            s.sendto(build_response(data, qend, qtype), addr)
        except OSError:
            pass

        if not quiet:
            ts = datetime.now().strftime("%H:%M:%S")
            label = qname.split(".")[0]
            # ชื่อ label ยาว = สัญญาณ tunneling - ทำเครื่องหมายไว้ให้เห็นสดๆ
            mark = "  <-- label ยาว {} ตัว".format(len(label)) if len(label) > 30 else ""
            print("[dns] {} {:<15} {:<5} {}{}".format(
                ts, addr[0], QTYPE.get(qtype, qtype), qname[:80], mark))
            if n % 50 == 0:
                print("[dns] --- รับแล้ว {} query ---".format(n))
    return 0


def main():
    ap = argparse.ArgumentParser(description="DNS server จำลองในแล็บ")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--quiet", action="store_true", help="ไม่พิมพ์ทุก query")
    args = ap.parse_args()
    try:
        return serve(args.port, args.quiet)
    except KeyboardInterrupt:
        with _lock:
            total = STATS["total"]
            breakdown = ", ".join("{}={}".format(k, v) for k, v in STATS.items()
                                  if k != "total")
        print("\n[dns] หยุดแล้ว - รับ {} query  ({})".format(total, breakdown or "-"))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

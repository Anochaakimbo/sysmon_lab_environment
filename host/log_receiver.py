"""
Log Receiver - รันบน Windows host
รับ syslog จาก VM ผ่าน TCP แล้วเขียนลงไฟล์แยกตาม session

ใช้งาน:
    python log_receiver.py                    # session ชื่อ default
    python log_receiver.py --session ransom_01
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
import socket
import threading
from datetime import datetime
from pathlib import Path

LOG_DIR = Path("logs")


def handle_client(conn, addr, outfile, lock):
    print(f"[+] VM เชื่อมต่อ: {addr[0]}")
    buffer = b""
    count = 0
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                # เก็บเฉพาะบรรทัดที่มาจาก sysmon
                if "sysmon" not in text.lower():
                    continue
                ts = datetime.now().isoformat()
                with lock:
                    with open(outfile, "a", encoding="utf-8") as f:
                        f.write(f"{ts}\t{addr[0]}\t{text}\n")
                count += 1
                if count % 50 == 0:
                    print(f"    ...รับแล้ว {count} events จาก {addr[0]}")
    except ConnectionResetError:
        pass
    finally:
        conn.close()
        print(f"[-] {addr[0]} ตัดการเชื่อมต่อ (รวม {count} events)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--session", default="default",
                    help="ชื่อ session ใช้ตั้งชื่อไฟล์ log")
    args = ap.parse_args()

    LOG_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = LOG_DIR / f"{args.session}_{stamp}.log"
    lock = threading.Lock()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(10)

    print(f"[*] กำลังฟังที่ {args.host}:{args.port}")
    print(f"[*] เขียนลง: {outfile.resolve()}")
    print("[*] กด Ctrl+C เพื่อหยุด\n")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client,
                                 args=(conn, addr, outfile, lock),
                                 daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(f"\n[*] หยุดแล้ว  log อยู่ที่: {outfile.resolve()}")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
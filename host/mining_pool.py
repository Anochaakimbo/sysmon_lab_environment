"""
mining_pool.py - Stratum pool จำลองขั้นต่ำ สำหรับให้ XMRig ตัวจริงขุดได้

ทำไมต้องมี: c2_server.py พอร์ต 3333 เป็น echo server เฉยๆ (ตอบ "OK\\n" แล้วปิด)
XMRig จะ login ไม่ผ่าน แล้ววนแต่ retry -> ได้แค่พฤติกรรม network ไม่ได้ CPU hashing
ซึ่งเป็นลายเซ็นหลักของ cryptojacking

ไฟล์นี้พูด JSON-RPC ของ Stratum พอให้ XMRig:
  1. login สำเร็จ -> ได้ job -> เริ่มแฮชจริงด้วย RandomX
  2. เจอ share แล้ว submit กลับมา -> ตอบ OK -> ได้ traffic beacon สม่ำเสมอ
  3. ดัน job ใหม่เป็นระยะ -> เหมือน pool จริง

ไม่ได้ขุดเงินจริง - blob เป็นข้อมูลสุ่ม ไม่เชื่อมกับบล็อกเชนใดๆ

ใช้งาน (แทน c2_server.py ตอนรัน scenario miner_real):
    python mining_pool.py
    python mining_pool.py --port 3333 --difficulty 256
"""
import argparse
import json
import os
import socket
import threading
from datetime import datetime

LOCK = threading.Lock()
STATS = {"login": 0, "submit": 0, "conn": 0}


def log(msg):
    with LOCK:
        print(f"  [pool] {datetime.now():%H:%M:%S} {msg}", flush=True)


def make_job(difficulty):
    """สร้าง job ปลอม - blob/seed เป็น hex สุ่ม ความยาวตามที่ RandomX คาดหวัง"""
    target = format(int(0xFFFFFFFF / max(1, difficulty)), "08x")
    # target ส่งแบบ little-endian hex (xmrig อ่านกลับด้าน)
    target_le = "".join(reversed([target[i:i+2] for i in range(0, 8, 2)]))
    return {
        "blob": os.urandom(76).hex(),      # RandomX hashing blob
        "job_id": os.urandom(8).hex(),
        "target": target_le,
        "algo": "rx/0",
        "height": 3000000,
        "seed_hash": os.urandom(32).hex(),
    }


def handle(conn, addr, difficulty):
    STATS["conn"] += 1
    log(f"เชื่อมต่อจาก {addr[0]}:{addr[1]}")
    session = os.urandom(8).hex()
    buf = b""
    try:
        conn.settimeout(300)
        while True:
            data = conn.recv(8192)
            if not data:
                break
            buf += data
            # JSON-RPC ของ stratum คั่นด้วย newline
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    log(f"อ่าน JSON ไม่ออก: {line[:60]!r}")
                    continue

                method = req.get("method", "")
                rid = req.get("id", 1)

                if method == "login":
                    STATS["login"] += 1
                    agent = (req.get("params") or {}).get("agent", "?")
                    log(f"login: {agent}")
                    resp = {"id": rid, "jsonrpc": "2.0", "error": None,
                            "result": {"id": session, "job": make_job(difficulty),
                                       "status": "OK"}}
                elif method == "submit":
                    STATS["submit"] += 1
                    if STATS["submit"] % 5 == 0:
                        log(f"รับ share แล้ว {STATS['submit']} ครั้ง")
                    resp = {"id": rid, "jsonrpc": "2.0", "error": None,
                            "result": {"status": "OK"}}
                    # ดัน job ใหม่ทุก 10 share ให้เหมือน pool จริง
                    if STATS["submit"] % 10 == 0:
                        push = {"jsonrpc": "2.0", "method": "job",
                                "params": make_job(difficulty)}
                        conn.sendall((json.dumps(push) + "\n").encode())
                elif method == "keepalived":
                    resp = {"id": rid, "jsonrpc": "2.0", "error": None,
                            "result": {"status": "KEEPALIVED"}}
                else:
                    resp = {"id": rid, "jsonrpc": "2.0", "error": None,
                            "result": {"status": "OK"}}

                conn.sendall((json.dumps(resp) + "\n").encode())
    except (socket.timeout, ConnectionResetError, OSError):
        pass
    finally:
        log(f"ปิดการเชื่อมต่อ {addr[0]}  (login {STATS['login']}, share {STATS['submit']})")
        try:
            conn.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3333)
    ap.add_argument("--difficulty", type=int, default=256,
                    help="ต่ำ = เจอ share บ่อย = traffic ถี่ (default 256)")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen(8)
    print(f"[*] Stratum pool จำลอง {args.host}:{args.port}  difficulty={args.difficulty}")
    print("[*] รอ XMRig เชื่อมต่อ... (Ctrl+C เพื่อหยุด)\n")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr, args.difficulty),
                             daemon=True).start()
    except KeyboardInterrupt:
        print(f"\n[*] สรุป: เชื่อมต่อ {STATS['conn']} ครั้ง, login {STATS['login']}, "
              f"share {STATS['submit']}")


if __name__ == "__main__":
    main()

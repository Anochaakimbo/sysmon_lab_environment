"""
c2_server.py - เซิร์ฟเวอร์ C2/mining-pool จำลอง (รันบน Windows host)

ใช้คู่กับ botnet.sh และ miner.sh เพื่อให้ VM มีปลายทางเชื่อมต่อจริง
(สร้าง NetworkConnect events ที่สมบูรณ์) โดยไม่ต้องต่ออินเทอร์เน็ต

ใช้งาน:
    python c2_server.py               # HTTP 8080 + TCP 3333, 4444
"""
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime


class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [http] {datetime.now():%H:%M:%S} {self.address_string()} {fmt % args}")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        print(f"  [http] รับข้อมูล {n} bytes จาก {self.address_string()}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"RECEIVED")


def tcp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"[*] TCP listener บนพอร์ต {port}")
    while True:
        try:
            conn, addr = s.accept()
            data = conn.recv(4096)
            print(f"  [tcp:{port}] {addr[0]} -> {data[:60]!r}")
            conn.sendall(b"OK\n")
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    for p in (3333, 4444):
        threading.Thread(target=tcp_listener, args=(p,), daemon=True).start()

    print("[*] HTTP C2 บนพอร์ต 8080")
    print("[*] กด Ctrl+C เพื่อหยุด\n")
    try:
        HTTPServer(("0.0.0.0", 8080), C2Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] หยุดแล้ว")
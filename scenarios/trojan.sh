#!/usr/bin/env bash
# trojan.sh - จำลองพฤติกรรม trojan / backdoor
#
# ATT&CK:
#   T1082     3,4,5,6,8,12,25,26  System Information Discovery
#   T1033     2                   System Owner/User Discovery
#   T1057     1                   Process Discovery
#   T1059.004 1,2,3,4,5           Unix Shell (มี 17 ตัว - เริ่มจาก 5 ตัวก่อน)
#   T1053.003 1,2,3,4             Scheduled Task - Cron
#   T1543.002 1,2,3               Systemd Service
#   T1546.004 1,2,3,4             Event Triggered - Shell Config Modification
#   T1027     1                   Obfuscated Files
#   T1005     2                   Data from Local System
#
# หมายเหตุ: T1059.004 มี 17 tests  ถ้าอยาก event เยอะขึ้นเปลี่ยนเป็น
#   atomic T1059.004 1,2,3,6,7,8,9,10   (ใช้เวลานานขึ้น ต้องเพิ่ม --duration)
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "trojan"
setup_sandbox

STAGE="$SANDBOX/trojan_stage"
mkdir -p "$STAGE"

# --- Stage 1: recon ระบบและผู้ใช้ ---
# ตัดจาก 8 tests เหลือ 3: test 6,8,12,25,26 วน xargs/find ยิง grep/gawk/tr
# หลายพันตัว -> Sysmon for Linux ตามสายเลือดไม่ทัน ParentProcessGuid กลายเป็น
# null 100% ทำให้ lineage labeling พังทั้งรอบ (วัดแล้ว: ParentImage ว่าง 68%)
atomic T1082 3,4,5
atomic T1033 2
atomic T1057 1

# --- Stage 2: รัน shell command หลายรูปแบบ ---
atomic T1059.004 1,2,3

# --- Stage 3: เก็บข้อมูลจากเครื่อง ---
atomic T1005 2

# --- Stage 4: persistence 3 ช่องทาง ---
atomic T1053.003 1,2,3,4        # cron
atomic T1543.002 1,2,3          # systemd service
atomic T1546.004 1,2,3,4        # shell config (.bashrc ฯลฯ)

# --- Stage 5: obfuscation ---
atomic T1027 1

# --- Stage 6: dropper จำลอง ---
echo "[trojan] วาง payload จำลอง"
cat > "$STAGE/.hidden_payload.sh" <<'PAYLOAD'
#!/bin/bash
# LAB SIMULATION - benign placeholder
for i in $(seq 1 5); do
    date >> /tmp/lab_sandbox/trojan_stage/beacon.log
    id   >> /tmp/lab_sandbox/trojan_stage/beacon.log
    sleep 2
done
PAYLOAD
chmod +x "$STAGE/.hidden_payload.sh"
base64 "$STAGE/.hidden_payload.sh" > "$STAGE/payload.b64"
"$STAGE/.hidden_payload.sh"

# --- ล้าง persistence ที่ atomic test ทิ้งไว้ ---
# ต้องล้างให้ครบ ไม่ใช่แค่ crontab: orchestrator วนรอบโดยไม่ revert
# ถ้า profile/.bashrc ที่ T1546.004 แก้ยังค้าง รอบถัดไปจะเจอ process storm
crontab -r 2>/dev/null || true
atomic_cleanup T1546.004 1,2,3,4
atomic_cleanup T1543.002 1,2,3
atomic_cleanup T1053.003 1,2,3,4

# ตาข่ายรับ เผื่อ cleanup ของ ART ล้างไม่หมด
rm -f /etc/profile.d/*atomic* /etc/profile.d/*T1546* 2>/dev/null || true
rm -f /etc/init.d/T1543.002 /etc/systemd/system/art-systemd-service.service 2>/dev/null || true
rm -f /etc/cron.d/persistevil 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

done_banner "trojan"
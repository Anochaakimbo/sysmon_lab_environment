#!/usr/bin/env bash
# benign.sh - กิจกรรมปกติของผู้ใช้/ระบบ
# สำคัญมาก: ต้องรันบน "ทุก VM" เพื่อไม่ให้ hostname ทำนาย label ได้
# และต้องสร้าง process ใหม่เยอะๆ (ไม่ใช่ปล่อย idle) เพื่อกัน enrichment leakage
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "benign"
setup_sandbox

WORK="/tmp/benign_work"
mkdir -p "$WORK"

for round in 1 2 3 4 5; do
    echo "[benign] รอบ $round"

    # --- งานไฟล์ทั่วไป ---
    for i in $(seq 1 5); do
        echo "report data $round-$i $(date)" > "$WORK/doc_$i.txt"
        cp "$WORK/doc_$i.txt" "$WORK/doc_$i.bak"
    done
    tar -czf "$WORK/backup_$round.tar.gz" -C "$WORK" . 2>/dev/null
    rm -f "$WORK"/doc_*.bak

    # --- สำรวจระบบแบบผู้ดูแลปกติ ---
    ls -la /etc > /dev/null
    ps aux > /dev/null
    df -h > /dev/null
    free -m > /dev/null
    uptime > /dev/null
    whoami > /dev/null
    id > /dev/null

    # --- ประมวลผลข้อความ ---
    cat /etc/passwd | grep -c bash > /dev/null
    awk '{print $1}' /etc/hostname > /dev/null
    sort /etc/services 2>/dev/null | head -50 > /dev/null
    wc -l /var/log/syslog > /dev/null

    # --- network ปกติ ---
    ping -c 2 192.168.56.1 > /dev/null 2>&1
    getent hosts localhost > /dev/null

    # --- จัดการแพ็กเกจ/บริการ (อ่านอย่างเดียว) ---
    dpkg -l 2>/dev/null | head -20 > /dev/null
    systemctl list-units --type=service --state=running --no-pager > /dev/null 2>&1

    sleep 4
done

rm -rf "$WORK"
done_banner "benign"
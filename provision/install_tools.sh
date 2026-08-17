#!/usr/bin/env bash
# install_tools.sh - ติดตั้งเครื่องมือที่ Atomic Red Team tests เรียกใช้
#
# ถ้าไม่มีเครื่องมือพวกนี้ test จะรันผ่าน (exit 0) แต่ "ไม่เกิด process"
# ทำให้เสีย event ที่ควรได้ไปเปล่าๆ
set -euo pipefail

echo "[*] ติดตั้งเครื่องมือสำหรับ atomic tests..."
apt-get update -qq

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    net-tools \
    iproute2 \
    curl \
    wget \
    gnupg \
    p7zip-full \
    ccrypt \
    sqlite3 \
    bc \
    jq \
    xxd \
    netcat-openbsd \
    cron \
    at \
    lsof \
    psmisc \
    procps \
    file \
    zip unzip \
    openssl \
    2>/dev/null || echo "[!] บางแพ็กเกจติดตั้งไม่ได้ (ข้ามไป)"

# เปิด cron service (T1053.003 ต้องใช้)
systemctl enable --now cron 2>/dev/null || true

echo "[*] ตรวจสอบ..."
for c in netstat arp ss ip curl wget gpg 7z ccrypt sqlite3 bc jq nc crontab lsof; do
    if command -v "$c" > /dev/null 2>&1; then
        echo "    OK   $c"
    else
        echo "    MISS $c"
    fi
done

echo "[+] เสร็จ"
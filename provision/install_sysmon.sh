#!/usr/bin/env bash
# ติดตั้ง Sysmon for Linux + ตั้ง rsyslog ให้ forward log กลับ Windows host
# ตัวแปร HOST_IP / LOG_PORT ส่งมาจาก Vagrantfile
set -euo pipefail

HOST_IP="${HOST_IP:-192.168.56.1}"
LOG_PORT="${LOG_PORT:-5514}"

echo "[*] จะส่ง log ไปที่ ${HOST_IP}:${LOG_PORT}"

# ---------- 1. Microsoft repo ----------
echo "[*] เพิ่ม Microsoft package repository..."
UBUNTU_VER=$(lsb_release -rs)
wget -q "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VER}/packages-microsoft-prod.deb" \
     -O /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
apt-get update -qq

# ---------- 2. ติดตั้ง Sysmon ----------
# ต้องลง sysinternalsebpf ก่อน แล้วค่อย sysmonforlinux
echo "[*] ติดตั้ง sysinternalsebpf..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sysinternalsebpf

echo "[*] ติดตั้ง sysmonforlinux..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sysmonforlinux

# ---------- 3. วาง config แล้ว register service ----------
echo "[*] ติดตั้ง Sysmon config..."
cp /vagrant/provision/sysmon-config.xml /opt/sysmon-config.xml
sysmon -accepteula -i /opt/sysmon-config.xml

# ---------- 4. rsyslog forward ----------
echo "[*] ตั้งค่า rsyslog forwarding..."
cat > /etc/rsyslog.d/10-sysmon-forward.conf <<EOF
# ขยาย message size (event ของ Sysmon ใหญ่เกิน default 8KB ได้)
\$MaxMessageSize 128k

# ส่ง log ทั้งหมดไปหา host  (@@ = TCP)
*.* @@${HOST_IP}:${LOG_PORT}

# กันคิวเต็มตอน host ยังไม่เปิด listener
\$ActionQueueType LinkedList
\$ActionQueueFileName sysmonfwd
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
EOF

systemctl restart rsyslog

# ---------- 5. ตรวจสอบ ----------
echo "[*] ตรวจสอบสถานะ..."
systemctl is-active sysmon  && echo "    sysmon : OK"
systemctl is-active rsyslog && echo "    rsyslog: OK"

echo "[+] เสร็จแล้ว! สร้าง activity ทดสอบ..."
ls -la /tmp > /dev/null
touch /tmp/vagrant-provision-test && rm /tmp/vagrant-provision-test
#!/usr/bin/env bash
# ติดตั้ง Sysmon for Linux + ตั้ง rsyslog ให้ forward กลับ host
# v2: ปิด rate limiting  (v1 ทำให้ event หายตอน burst หนัก เช่น FileCreate)
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
echo "[*] ติดตั้ง sysinternalsebpf..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sysinternalsebpf
echo "[*] ติดตั้ง sysmonforlinux..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sysmonforlinux

# ---------- 3. config ----------
echo "[*] ติดตั้ง Sysmon config..."
cp /vagrant/provision/sysmon-config.xml /opt/sysmon-config.xml
sysmon -accepteula -i /opt/sysmon-config.xml

# ---------- 4. journald: ปิด rate limit ----------
# สำคัญ: Sysmon เขียนผ่าน journald ก่อนถึง rsyslog
# ถ้าไม่ปิด limit ตรงนี้ event จะหายตั้งแต่ต้นทาง
echo "[*] ปิด rate limiting ของ journald..."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-nolimit.conf <<'JCONF'
[Journal]
RateLimitIntervalSec=0
RateLimitBurst=0
SystemMaxUse=2G
JCONF
systemctl restart systemd-journald

# ---------- 5. rsyslog: forward + ปิด rate limit ----------
echo "[*] ตั้งค่า rsyslog forwarding..."
cat > /etc/rsyslog.d/10-sysmon-forward.conf <<RCONF
# ขยาย message size (event ของ Sysmon ใหญ่เกิน default)
\$MaxMessageSize 256k

# ปิด rate limiting ทุกทาง - ห้าม drop event
\$SystemLogRateLimitInterval 0
\$SystemLogRateLimitBurst 0
\$IMUXSockRateLimitInterval 0
\$IMUXSockRateLimitBurst 0

# ส่ง log ทั้งหมดไปหา host (@@ = TCP)
*.* @@${HOST_IP}:${LOG_PORT}

# คิวใหญ่ กัน log หายตอน burst
\$ActionQueueType LinkedList
\$ActionQueueFileName sysmonfwd
\$ActionQueueMaxDiskSpace 1g
\$ActionQueueSize 200000
\$ActionQueueHighWaterMark 150000
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
RCONF

# ปิด rate limit ของ imjournal ด้วย (ตัวหลักที่ทิ้ง event)
if grep -q "imjournal" /etc/rsyslog.conf; then
    sed -i 's/^\$imjournalRatelimitInterval.*//' /etc/rsyslog.conf
    cat > /etc/rsyslog.d/09-imjournal-nolimit.conf <<'ICONF'
$imjournalRatelimitInterval 0
$imjournalRatelimitBurst 0
ICONF
fi

systemctl restart rsyslog

# ---------- 6. ตรวจสอบ ----------
echo "[*] ตรวจสอบสถานะ..."
systemctl is-active sysmon  && echo "    sysmon : OK"
systemctl is-active rsyslog && echo "    rsyslog: OK"

echo "[*] ตรวจ event type ที่ config เปิดอยู่:"
sysmon -c 2>/dev/null | grep -oE '(ProcessCreate|NetworkConnect|ProcessTerminate|RawAccessRead|ProcessAccess|FileCreate|FileDelete)' | sort -u | sed 's/^/    /'

echo "[+] เสร็จแล้ว! สร้าง activity ทดสอบ..."
ls -la /tmp > /dev/null
touch /tmp/vagrant-provision-test && rm /tmp/vagrant-provision-test
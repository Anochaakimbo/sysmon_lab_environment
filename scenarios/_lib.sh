#!/usr/bin/env bash
# _lib.sh - ฟังก์ชันร่วมของทุก scenario
# ทุก scenario ต้อง source ไฟล์นี้

SANDBOX="/tmp/lab_sandbox"
LAUNCHER="$SANDBOX/run_atomic.sh"

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

# atomic <TECHNIQUE> [TEST_NUMBERS]
atomic() {
    "$LAUNCHER" "$@"
    sleep 3
}

banner() {
    echo "============================================"
    echo "  SCENARIO: $1"
    echo "  sandbox : $SANDBOX"
    echo "  เริ่ม    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================"
}

done_banner() {
    echo "--------------------------------------------"
    echo "  จบ scenario: $1  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo "--------------------------------------------"
}
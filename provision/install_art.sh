#!/usr/bin/env bash
# ติดตั้ง PowerShell Core + Invoke-AtomicRedTeam + atomics folder
# รันครั้งเดียวตอน provision (ต้องมีเน็ตผ่าน NAT)
set -euo pipefail

echo "[*] ติดตั้ง PowerShell Core..."
# Microsoft repo ถูกเพิ่มไว้แล้วโดย install_sysmon.sh
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq powershell || {
    echo "[!] ติดตั้ง powershell ไม่ผ่าน - ลองผ่าน snap"
    snap install powershell --classic
}

echo "[*] ติดตั้ง Invoke-AtomicRedTeam + atomics..."
pwsh -NoProfile -Command '
  $ErrorActionPreference = "Stop"
  Install-Module -Name powershell-yaml -Scope AllUsers -Force -AllowClobber
  IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing)
  Install-AtomicRedTeam -getAtomics -InstallPath "/opt/AtomicRedTeam" -Force
'

echo "[*] เตรียม sandbox directory..."
mkdir -p /tmp/lab_sandbox
chmod 755 /tmp/lab_sandbox

# ---------- launcher ที่ scenario ทุกตัวเรียกใช้ ----------
# สำคัญ: ทุก atomic test จะถูก spawn จาก launcher นี้
# ทำให้ lineage labeling ตามรอยได้ครบ (seed = /tmp/lab_sandbox/)
cat > /tmp/lab_sandbox/run_atomic.sh <<'LAUNCHER'
#!/usr/bin/env bash
# run_atomic.sh <TECHNIQUE> [TEST_NUMBERS]
# ตัวกลางเรียก Invoke-AtomicTest - เป็น seed ของ lineage labeling
TECH="$1"
NUMS="${2:-}"
ARG_NUMS=""
[ -n "$NUMS" ] && ARG_NUMS="-TestNumbers $NUMS"

echo "  [atomic] $TECH $NUMS"
pwsh -NoProfile -Command "
  Import-Module '/opt/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1' -Force
  \$PSDefaultParameterValues = @{'Invoke-AtomicTest:PathToAtomicsFolder'='/opt/AtomicRedTeam/atomics'}
  Invoke-AtomicTest $TECH $ARG_NUMS -GetPrereqs -ErrorAction SilentlyContinue
  Invoke-AtomicTest $TECH $ARG_NUMS -ExecutionLogPath /tmp/lab_sandbox/art_exec.csv -ErrorAction SilentlyContinue
" 2>&1 | tail -5
LAUNCHER
chmod +x /tmp/lab_sandbox/run_atomic.sh

# ให้ sandbox กลับมาเสมอหลัง revert snapshot
cp -r /tmp/lab_sandbox /opt/lab_sandbox_template

echo "[+] Atomic Red Team พร้อมใช้งาน"
pwsh -NoProfile -Command "
  Import-Module '/opt/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1' -Force
  Write-Host '    atomics:' (Get-ChildItem /opt/AtomicRedTeam/atomics -Directory).Count 'techniques'
" || echo "[!] ตรวจสอบการติดตั้งด้วยตนเอง"
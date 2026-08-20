# install_sysmon_win.ps1 - ติดตั้ง Sysmon (Windows) + research config
# รันตอน vagrant provision (ต้องมีเน็ตผ่าน NAT)
#
# ต่างจาก Linux: Windows ไม่มี syslog/rsyslog
#   Sysmon เขียน event -> Windows Event Log (Microsoft-Windows-Sysmon/Operational)
#   การส่ง log กลับ host ใช้วิธี batch export EVTX หลัง scenario จบ
#   (ดู provision/windows/export_sysmon_win.ps1 ที่ orchestrator เรียก)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # เร่ง Invoke-WebRequest

Write-Host "[*] ดาวน์โหลด Sysmon (Sysinternals)..."
$zip = "C:\sysmon.zip"
$dir = "C:\sysmon"
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip
Expand-Archive $zip $dir -Force

Write-Host "[*] ติดตั้ง Sysmon config (research)..."
$cfg = "C:\sysmon\config.xml"
Copy-Item "C:\vagrant\provision\windows\sysmon-config-win.xml" $cfg -Force

# ถ้ามี Sysmon ติดตั้งอยู่แล้ว -> update config, ไม่งั้น -i ติดตั้งใหม่
$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc) {
    & "$dir\Sysmon64.exe" -c $cfg
} else {
    & "$dir\Sysmon64.exe" -accepteula -i $cfg
}

Write-Host "[*] ตรวจสอบ..."
Start-Sleep -Seconds 3
$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "[+] Sysmon64 ทำงาน (Status: $($svc.Status))"
    # นับ event type ที่ config เปิด
    & "$dir\Sysmon64.exe" -c | Select-String -Pattern "ProcessCreate|NetworkConnect|FileCreate|RegistryEvent|ImageLoad|CreateRemoteThread" | Select-Object -First 8
} else {
    Write-Host "[!] Sysmon ไม่ทำงาน - ตรวจสอบด้วยตนเอง"
    exit 1
}

# เปิดสิทธิ์อ่าน Event Log ให้ export ได้ (เผื่อ non-admin)
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:256000000  # ขยาย log ให้ใหญ่ กัน event ล้น

Write-Host "[+] Sysmon Windows พร้อมเก็บ dataset"

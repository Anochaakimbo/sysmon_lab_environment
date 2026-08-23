# _diag_defender.ps1 - ตรวจว่า preflight ของ Setup-Sandbox ยิงจริงเมื่อ Defender เปิดอยู่
# เครื่องมือ debug อย่างเดียว ไม่ใช่ scenario เก็บข้อมูล
#
# รัน: vagrant winrm wintarget -c "powershell -ExecutionPolicy Bypass -File C:\vagrant\scenarios_win\_diag_defender.ps1"

Copy-Item C:\vagrant\scenarios_win\_lib.ps1 C:\lab_sandbox\ -Force
Set-Location C:\lab_sandbox
. .\_lib.ps1

$st = Get-MpComputerStatus -ErrorAction SilentlyContinue
Write-Host "สถานะ Defender ตอนนี้:"
Write-Host "  RealTimeProtectionEnabled = $($st.RealTimeProtectionEnabled)"
Write-Host "  IsTamperProtected         = $($st.IsTamperProtected)"
Write-Host ""

try {
    Setup-Sandbox
    Write-Host ""
    Write-Host "[ผล] Setup-Sandbox ผ่าน - Defender ไม่ได้ขวาง scenario จะเก็บข้อมูลได้ครบ"
} catch {
    Write-Host ""
    Write-Host "[ผล] preflight ยิงแล้ว - scenario จะไม่เดินต่อไปเก็บข้อมูลขยะ"
    Write-Host "--------------------------------------------------------------"
    Write-Host $_.Exception.Message
    Write-Host "--------------------------------------------------------------"
}

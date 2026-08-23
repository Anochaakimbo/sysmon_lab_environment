# disable_defender_win.ps1 - ปิด Windows Defender ใน VM (จำเป็นสำหรับ malware lab)
# รันตอน provision - Defender จะลบ real malware (xmrig/msfvenom payload/exploit)
# ตอน download/run ถ้าไม่ปิด
#
# ⚠️ ปิดเฉพาะใน VM (isolated, revert ได้) ไม่กระทบ host
# host ต้อง exclude project path เอง (Add-MpPreference -ExclusionPath, admin)
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] ปิด Windows Defender real-time protection..."
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend

Write-Host "[*] exclude sandbox paths..."
Add-MpPreference -ExclusionPath "C:\lab_sandbox"
Add-MpPreference -ExclusionPath "C:\vagrant"
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
Add-MpPreference -ExclusionExtension "exe"
Add-MpPreference -ExclusionExtension "ps1"

# ปิดผ่าน registry เผื่อ Set-MpPreference ถูก revert (Tamper Protection)
$reg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
New-Item -Path $reg -Force | Out-Null
Set-ItemProperty -Path $reg -Name "DisableAntiSpyware" -Value 1 -Type DWord
New-Item -Path "$reg\Real-Time Protection" -Force | Out-Null
Set-ItemProperty -Path "$reg\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord

Write-Host "[*] ตรวจสอบ..."
$s = Get-MpComputerStatus
Write-Host "    RealTimeProtection : $($s.RealTimeProtectionEnabled)   (False = ปิดสำเร็จ)"
Write-Host "    TamperProtection   : $($s.IsTamperProtected)"
Write-Host "    BehaviorMonitor    : $($s.BehaviorMonitorEnabled)"

if ($s.RealTimeProtectionEnabled) {
    # เตือนดังๆ ห้ามผ่านไปเงียบ - ปิดไม่ลงแปลว่า dataset จะขาด event ทั้งชนิด
    #
    # วัดจริง 23 ส.ค. 2026: Tamper Protection ย้อน Set-MpPreference -Disable* ทุกตัว
    # ผลคือ Defender บล็อก command line ของ T1059.001-5/-7 และ T1074.001
    # (test ที่โหลดไฟล์) -> trojan_win เก็บ NetworkConnect ที่เป็น malicious ได้ 0 แถว
    # ทั้งที่ atomic รายงานว่า "Done executing test" ครบทุกตัว
    #
    # exclusion ช่วยไม่ได้: Add-MpPreference -ExclusionPath กันแค่การสแกน "ไฟล์"
    # แต่ตัวที่บล็อกคือ AMSI/command-line scanning ซึ่งไม่ดู path
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host " [!] ปิด Defender ไม่สำเร็จ - Tamper Protection = $($s.IsTamperProtected)" -ForegroundColor Red
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host " Tamper Protection ย้อน Set-MpPreference ทุกตัวที่สคริปต์นี้ตั้ง" -ForegroundColor Yellow
    Write-Host " ปิดผ่านสคริปต์/registry ไม่ได้ ต้องทำมือครั้งเดียวบนหน้าจอ VM:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Windows Security > Virus & threat protection > Manage settings" -ForegroundColor Yellow
    Write-Host "   > ปิด Tamper Protection" -ForegroundColor Yellow
    Write-Host ""
    Write-Host " แล้วบนโฮสต์:  vagrant provision wintarget" -ForegroundColor Yellow
    Write-Host "               vagrant halt wintarget" -ForegroundColor Yellow
    Write-Host "               vagrant snapshot save wintarget clean --force" -ForegroundColor Yellow
    Write-Host ""
    Write-Host " ถ้ายังไม่ปิด: atomic test ที่โหลดไฟล์จะถูกบล็อกเงียบ" -ForegroundColor Yellow
    Write-Host " dataset จะไม่มี NetworkConnect ฝั่ง malicious เลย" -ForegroundColor Yellow
    Write-Host "==============================================================" -ForegroundColor Red
} else {
    Write-Host "[+] Defender ปิดแล้ว - scenario จะไม่ถูกบล็อก"
}

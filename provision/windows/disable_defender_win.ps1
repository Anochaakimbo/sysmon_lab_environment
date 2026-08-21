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
Write-Host "    RealTimeProtection: $($s.RealTimeProtectionEnabled)  (False = ปิดสำเร็จ)"
Write-Host "[+] Defender config เสร็จ - malware scenario จะไม่ถูกลบ"
Write-Host "    หมายเหตุ: ถ้ายัง True ให้ปิด Tamper Protection ด้วยมือใน Windows Security"

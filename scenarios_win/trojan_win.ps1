# trojan_win.ps1 - trojan / backdoor behaviour (Windows) ผ่าน Atomic Red Team
# คู่ขนานกับ scenarios/trojan.sh ฝั่ง Linux
#
# ฝั่ง Windows ART ครอบคลุมกว้างกว่า Linux มาก จึงใช้ atomic test ล้วน
# ไม่ต้องเขียน payload เอง -> map ATT&CK ได้ตรง อ้างอิงในธีสิสง่าย
#
# ATT&CK: T1082/T1033/T1057/T1087.001 Discovery, T1059.001 PowerShell,
#         T1547.001 Registry Run Keys, T1053.005 Scheduled Task,
#         T1112 Modify Registry, T1027 Obfuscation, T1005 Collection,
#         T1036.003 Masquerading
#
# ⚠️ ใส่เลข test จาก check_atomics.ps1 เสมอ
#    ถ้าเว้นว่าง Atomic() จะรัน "ทุก test" ของ technique นั้น ซึ่งอันตราย
. "$PSScriptRoot\_lib.ps1"
Banner "trojan_win"
Setup-Sandbox

$stage = "C:\lab_sandbox\trojan_stage"
New-Item -ItemType Directory -Path $stage -Force | Out-Null

# ---------- Stage 1: reconnaissance ----------
Write-Host "[trojan] recon"
Atomic "T1082" "1,7,9,11,27,35"           # System Information Discovery
Atomic "T1033" "1,4,5,6"             # System Owner/User Discovery
Atomic "T1057" "2,3,4,5,6"             # Process Discovery
Atomic "T1087.001" "8,9,10"         # Account Discovery - Local Account

# ---------- Stage 2: execution ----------
Write-Host "[trojan] execution"
Atomic "T1059.001" "5,7,8"       # PowerShell execution (เลี่ยง 1=Mimikatz, 2/3=BloodHound)

# ---------- Stage 3: persistence (2 ช่องทาง) ----------
Write-Host "[trojan] persistence"
Atomic "T1547.001" "1,2,8,9,11"  # Registry Run Keys (เลี่ยง 14/15/17 ที่แก้ Winlogon/BootExecute)
Atomic "T1053.005" "2,4,7,9"     # Scheduled Task
Atomic "T1112" "1,6,7,40,41"     # Modify Registry (มี 90 test เลือกตัวที่ไม่ปิด cmd/regedit/Defender)

# ---------- Stage 4: collection + staging ----------
Write-Host "[trojan] collection"
Atomic "T1005" "1"               # Data from Local System
Atomic "T1074.001" "1,3"         # Local Data Staging

# ---------- Stage 5: defense evasion ----------
Write-Host "[trojan] evasion"
Atomic "T1027" "2,3,7,11"        # Obfuscated Files or Information
Atomic "T1036.003" "1,3,5,7"     # Masquerading - Rename System Utilities

# ---------- Stage 6: file activity ใน sandbox (FileCreate/Delete telemetry) ----------
Write-Host "[trojan] sandbox file activity"
1..25 | ForEach-Object {
    $f = Join-Path $stage "staged_$_.dat"
    "collected data chunk $_ $(Get-Date -Format o)" | Out-File $f
}
Compress-Archive -Path "$stage\*.dat" -DestinationPath "$stage\collected.zip" -Force
Remove-Item "$stage\*.dat" -Force

# ---------- Cleanup: ล้าง persistence ที่ ART ทิ้งไว้ ----------
# จำเป็นมาก ไม่งั้น artifact ค้างข้ามรอบ ทำให้ session ถัดไปปนเปื้อน
Write-Host "[trojan] cleanup"
Atomic-Cleanup "T1547.001" "1,2,8,9,11"
Atomic-Cleanup "T1053.005" "2,4,7,9"
Atomic-Cleanup "T1112" "1,6,7,40,41"
Atomic-Cleanup "T1036.003" "1,3,5,7"
Atomic-Cleanup "T1074.001" "1,3"    # staging ทิ้งไฟล์ไว้
Atomic-Cleanup "T1027" "2,3,7,11"   # obfuscated payload ทิ้งไฟล์ไว้

Done-Banner "trojan_win"
# benign.ps1 - กิจกรรมปกติของผู้ใช้/ระบบ (Windows)  label = 0
# สำคัญ: สร้าง process ใหม่เยอะๆ (ไม่ปล่อย idle) กัน enrichment leakage
# เหมือน scenarios/benign.sh ฝั่ง Linux
. "$PSScriptRoot\_lib.ps1"
Banner "benign"
Setup-Sandbox

$work = "C:\lab_sandbox\benign_work"
New-Item -ItemType Directory -Path $work -Force | Out-Null

Write-Host "[benign] กิจกรรมไฟล์ + process ปกติ"
for ($i = 1; $i -le 30; $i++) {
    # สร้าง/อ่าน/ลบไฟล์ (FileCreate, FileDelete)
    $f = Join-Path $work "doc_$i.txt"
    "benign content $i $(Get-Random)" | Out-File $f
    Get-Content $f | Out-Null
    Get-ChildItem $work | Out-Null

    # process ใหม่หลากหลาย (ProcessCreate) - ให้มี CommandLine ไม่ว่าง
    cmd /c "echo hello $i" | Out-Null
    whoami | Out-Null
    hostname | Out-Null
    ipconfig /all | Out-Null
    tasklist | Select-Object -First 5 | Out-Null

    Remove-Item $f -Force
    Start-Sleep -Milliseconds 300
}

# กิจกรรม network ปกติ (NetworkConnect) - ต่อ host C2 (จะถูก label benign เพราะ session mode)
Write-Host "[benign] network ปกติ"
Test-NetConnection -ComputerName "192.168.56.1" -Port 8080 -WarningAction SilentlyContinue | Out-Null

Done-Banner "benign"

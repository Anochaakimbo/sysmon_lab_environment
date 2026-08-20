# export_sysmon_win.ps1 - ดึง Sysmon event ในช่วงเวลาที่กำหนด -> XML ไป host
# แทนท่อ log realtime ของ Linux (rsyslog TCP) ด้วย batch export หลัง scenario
#
# orchestrator เรียกหลัง scenario จบ ด้วย start/end time:
#   powershell export_sysmon_win.ps1 -Session <name> -StartUtc <iso> -OutDir C:\vagrant\host\logs_win
#
# ผลลัพธ์: <OutDir>\<session>.xml (Sysmon event XML) -> host parse ด้วย parse_sysmon.py --platform windows
param(
    [string]$Session = "win_session",
    [string]$StartUtc = "",           # ISO เช่น 2026-08-21T10:00:00Z (ว่าง = 30 นาทีล่าสุด)
    [string]$OutDir = "C:\vagrant\host\logs_win"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# กรอง event ตั้งแต่ StartUtc (ถ้าระบุ) ไม่งั้นเอา 30 นาทีล่าสุด
if ($StartUtc) {
    $start = [datetime]::Parse($StartUtc).ToUniversalTime()
} else {
    $start = (Get-Date).ToUniversalTime().AddMinutes(-30)
}

Write-Host "[export] Sysmon events ตั้งแต่ $($start.ToString('o'))"
$filter = @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    StartTime = $start
}
$events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "[!] ไม่มี event ในช่วงเวลานี้"
    exit 0
}

# เขียนเป็น XML (raw event XML ของ Sysmon - เหมือน syslog XML ฝั่ง Linux)
$stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$out = Join-Path $OutDir "$($Session)_$stamp.xml"
$sw = [System.IO.StreamWriter]::new($out, $false, [System.Text.Encoding]::UTF8)
try {
    foreach ($e in $events) {
        # ToXml() ให้ <Event>...</Event> เต็ม - parse_sysmon.py จับ pattern เดียวกับ Linux ได้
        $sw.WriteLine($e.ToXml())
    }
} finally {
    $sw.Close()
}
Write-Host "[+] เขียนแล้ว: $out ($($events.Count) events)"

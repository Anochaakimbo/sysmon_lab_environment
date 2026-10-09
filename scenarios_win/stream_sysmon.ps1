# stream_sysmon.ps1 - ส่ง Sysmon event ของ Windows VM ไป host แบบ live (ไม่ใช่ scenario)
#
# ปกติฝั่ง Windows export EVTX ตอนจบ run -> live_detector.py ใช้ได้แค่ --replay
# สคริปต์นี้ส่ง event ใหม่ทีละบรรทัด (XML 1 บรรทัด) ไป log_receiver.py ที่ TCP 5514
# รูปแบบเดียวกับไฟล์ export -> parse_sysmon.parse_line(platform="windows") อ่านได้เลย
#
# ต้องรันเป็น SYSTEM ผ่าน scheduled task (WinRM ฆ่า process ลูกตอนปิด session):
#   schtasks /create /tn LabSysmonStream /sc once /st 00:00 /ru SYSTEM /f /tr "powershell -ExecutionPolicy Bypass -File C:\vagrant\scenarios_win\stream_sysmon.ps1"
#   schtasks /run /tn LabSysmonStream
# หยุด: schtasks /end /tn LabSysmonStream ; schtasks /delete /tn LabSysmonStream /f
#
# replay_detect.harness_mask ตัด process ของสคริปต์นี้ออกจาก detection แล้ว (stream_sysmon.ps1 / LabSysmonStream)
param([string]$HostIp = "192.168.56.1", [int]$Port = 5514, [int]$PollMs = 1000)

$log = "Microsoft-Windows-Sysmon/Operational"
$errLog = "C:\lab_stream_error.txt"
# เริ่มจาก event ล่าสุด ณ ตอนสตาร์ท (ไม่ส่งของเก่าย้อนหลัง)
$last = (Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop).RecordId

while ($true) {
    try {
        $client = New-Object Net.Sockets.TcpClient($HostIp, $Port)
        $w = New-Object IO.StreamWriter($client.GetStream(), [Text.Encoding]::UTF8)
        $w.AutoFlush = $true
        while ($true) {
            $ev = @(Get-WinEvent -LogName $log -FilterXPath "*[System[EventRecordID>$last]]" -ErrorAction SilentlyContinue |
                    Sort-Object RecordId)
            foreach ($e in $ev) {
                $w.WriteLine(($e.ToXml() -replace "`r?`n", " "))
                $last = $e.RecordId
            }
            Start-Sleep -Milliseconds $PollMs
        }
    }
    catch {
        # host ยังไม่เปิด log_receiver / เน็ตหลุด -> จดไว้ แล้วต่อใหม่ (ไม่เงียบ)
        "$(Get-Date -Format o) $($_.Exception.Message)" | Out-File -Append $errLog
        Start-Sleep -Seconds 3
    }
    finally {
        if ($client) { $client.Close() }
    }
}

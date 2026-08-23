# _diag_network.ps1 - วินิจฉัยว่าทำไม NetworkConnect ของ scenario ไม่ถูกบันทึก
# ไม่ใช่ scenario เก็บข้อมูล - เป็นเครื่องมือ debug อย่างเดียว
#
# รัน: vagrant winrm wintarget -c "powershell -ExecutionPolicy Bypass -File C:\vagrant\scenarios_win\_diag_network.ps1"

$url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.xml"

function Show-NetEvents {
    param([datetime]$Since, [string]$Label)
    Start-Sleep -Seconds 6
    $ev = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Sysmon/Operational'
        Id        = 3
        StartTime = $Since
    } -ErrorAction SilentlyContinue
    Write-Host "  -> Sysmon NetworkConnect ที่จับได้: $(@($ev).Count)"
    foreach ($e in @($ev)) {
        $x = [xml]$e.ToXml()
        $d = @{}
        $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        Write-Host ("     {0,-46} -> {1}:{2}" -f
            (Split-Path $d.Image -Leaf), $d.DestinationIp, $d.DestinationPort)
    }
}

Write-Host "=============================================================="
Write-Host " 1) powershell โหลดไฟล์ผ่าน XmlDocument.Load (แบบ T1059.001-7)"
Write-Host "=============================================================="
$t = (Get-Date).AddSeconds(-2)
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile `
    "`$Xml = (New-Object System.Xml.XmlDocument); `$Xml.Load('$url'); 'loaded ' + `$Xml.OuterXml.Length + ' chars'"
Show-NetEvents -Since $t

Write-Host ""
Write-Host "=============================================================="
Write-Host " 2) powershell เดียวกัน แต่ต่อ IP ในแล็บ (ไม่ผ่าน proxy/เน็ตนอก)"
Write-Host "=============================================================="
$t = (Get-Date).AddSeconds(-2)
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile `
    "try { `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('192.168.56.1', 8080); `$c.Close(); 'connected' } catch { 'connect fail: ' + `$_.Exception.Message }"
Show-NetEvents -Since $t

Write-Host ""
Write-Host "=============================================================="
Write-Host " 3) Sysmon config ที่ใช้อยู่จริง - NetworkConnect เปิดไหม"
Write-Host "=============================================================="
& "C:\Sysmon\Sysmon64.exe" -c 2>$null |
    Select-String -Pattern "NetworkConnect" -Context 0, 3

Write-Host ""
Write-Host "=============================================================="
Write-Host " 4) นับ NetworkConnect ทั้งหมดใน log ย้อนหลัง 10 นาที แยกตาม process"
Write-Host "=============================================================="
$ev = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 3
    StartTime = (Get-Date).AddMinutes(-10)
} -ErrorAction SilentlyContinue
@($ev) | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    Split-Path $d.Image -Leaf
} | Group-Object | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("   {0,-34} {1}" -f $_.Name, $_.Count) }

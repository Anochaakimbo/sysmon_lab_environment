# miner_win.ps1 - cryptominer behaviour (Windows) ผ่าน Atomic Red Team
# แทนที่ miner_real_win.ps1 (เวอร์ชันโหลด XMRig จริง)
#
# ไม่โหลด/รัน mining binary — ใช้ atomic test T1496 ทำ resource hijacking
# ส่วน CPU load กับการเชื่อม pool ในแล็บเป็น operation ปกติ (คำนวณเลข + TCP socket)
# ได้ telemetry แบบเดียวกัน: ProcessCreate CPU สูง + NetworkConnect ไป pool
#
# ATT&CK: T1082 System Info Discovery, T1057 Process Discovery,
#         T1496 Resource Hijacking, T1105 Ingress Tool Transfer,
#         T1053.005 Scheduled Task persistence
#
# ต้องรัน host/c2_server.py ก่อน (pool จำลองพอร์ต 3333, HTTP 8080)
# ⚠️ เลข test ทุกบรรทัดต้องมาจาก check_atomics.ps1 ที่รันใน VM จริง
#    ห้ามเว้นว่าง - Atomic() ที่ไม่ระบุเลขจะรัน "ทุก test" ของ technique นั้น
. "$PSScriptRoot\_lib.ps1"
Banner "miner_win"
Setup-Sandbox

$poolHost = if ($env:POOL_HOST) { $env:POOL_HOST } else { "192.168.56.1" }
$poolPort = 3333
$mine = "C:\lab_sandbox\miner"
New-Item -ItemType Directory -Path $mine -Force | Out-Null

# ---------- Stage 1: recon สเปกเครื่อง (miner ทุกตัวทำก่อนเริ่ม) ----------
Write-Host "[miner] recon"
Atomic "T1082" "1,7,9,11,27,35"             # System Information Discovery
Atomic "T1057" "2,3,4,5,6"             # Process Discovery

Get-CimInstance Win32_Processor      | Select-Object Name,NumberOfCores,MaxClockSpeed |
    Out-File "$mine\cpu.txt"
Get-CimInstance Win32_ComputerSystem | Out-File "$mine\sys.txt"
Get-CimInstance Win32_VideoController| Select-Object Name,AdapterRAM |
    Out-File "$mine\gpu.txt"
wmic cpu get name,numberofcores      | Out-File "$mine\wmic_cpu.txt" 2>$null

# หา miner คู่แข่ง (พฤติกรรมเด่นของ miner จริง)
Get-Process | Where-Object { $_.ProcessName -match 'xmrig|minerd|cpuminer|nicehash' } |
    Out-File "$mine\competitors.txt"
tasklist /v | Out-File "$mine\tasklist.txt"

# ---------- Stage 2: ingress tool transfer ----------
Write-Host "[miner] tool transfer"
Atomic "T1105" "7,9,10,15,16,25"             # Ingress Tool Transfer (ต้องมีเน็ต/NAT)

# ---------- Stage 3: resource hijacking (ART) ----------
Write-Host "[miner] resource hijacking via ART"
Atomic "T1496" "2"               # มี windows test เดียวคือเลข 2 (เดิมใส่ "1,2" = error)

# ---------- Stage 4: CPU load 90 วินาที ----------
# คำนวณเลขล้วน ไม่ใช่ mining binary - ได้ CPU pattern + ProcessCreate เหมือนกัน
Write-Host "[miner] CPU load (90s)"
$jobs = @()
1..2 | ForEach-Object {
    $jobs += Start-Job -ScriptBlock {
        $end = (Get-Date).AddSeconds(90)
        $x = 0.0
        while ((Get-Date) -lt $end) {
            for ($i = 1; $i -le 200000; $i++) { $x = [Math]::Sqrt($i) * [Math]::Sin($i) }
        }
    }
}

# ---------- Stage 5: เชื่อม pool จำลองในแล็บ ----------
Write-Host "[miner] connect pool ${poolHost}:${poolPort}"
$ok = 0; $fail = 0
for ($i = 1; $i -le 20; $i++) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($poolHost, $poolPort)
        $msg = [Text.Encoding]::ASCII.GetBytes(
            "{`"method`":`"login`",`"worker`":`"lab_$env:COMPUTERNAME`_$i`"}`n")
        $tcp.GetStream().Write($msg, 0, $msg.Length)
        $tcp.Close()
        $ok++
    } catch { $fail++ }

    try {
        Invoke-WebRequest -Uri "http://${poolHost}:8080/submit?share=$i" `
            -TimeoutSec 2 -UseBasicParsing | Out-Null
    } catch { }
    Start-Sleep -Seconds 3
}
Write-Host "[miner] pool connect ok=$ok fail=$fail"
if ($ok -eq 0) { Write-Host "[!] เชื่อม pool ไม่ได้เลย - c2_server.py เปิดอยู่ไหม?" }

$jobs | Wait-Job -Timeout 120 | Out-Null
$jobs | Remove-Job -Force -ErrorAction SilentlyContinue

# ---------- Stage 6: persistence ----------
Write-Host "[miner] persistence"
Atomic "T1053.005" "2,4,7,9"     # Scheduled Task

# ---------- Cleanup ----------
Write-Host "[miner] cleanup"
Atomic-Cleanup "T1053.005" "2,4,7,9"
Atomic-Cleanup "T1496" "2"
Atomic-Cleanup "T1105" "7,9,10,15,16,25"      # T1105 โหลดไฟล์ทิ้งไว้ ต้องล้าง

Done-Banner "miner_win"
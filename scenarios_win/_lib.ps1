# _lib.ps1 - ฟังก์ชันร่วมของทุก scenario ฝั่ง Windows
# ทุก scenario dot-source ไฟล์นี้:  . "$PSScriptRoot\_lib.ps1"
#
# เทียบเท่า scenarios/_lib.sh ฝั่ง Linux แต่เป็น PowerShell

$SANDBOX = "C:\lab_sandbox"
# 360s: T1036.003 (4 test คัดลอก binary + spawn) โดน 240s ตัดกลางคัน 23 ส.ค. 2026
$AtomicTimeout = if ($env:ATOMIC_TIMEOUT) { [int]$env:ATOMIC_TIMEOUT } else { 360 }

# Install-AtomicRedTeam -InstallPath C:\AtomicRedTeam ไม่ได้วาง module ลง PSModulePath
# ทำให้ `Import-Module Invoke-AtomicRedTeam` ตามชื่อหาไม่เจอ -> ต้อง import ตาม path เต็ม
# (23 ส.ค. 2026: จุดนี้ทำให้ trojan_win รันแล้วไม่มี atomic test ทำงานเลยสักตัว แต่ exit 0)
$ARTRoot   = if ($env:ART_ROOT) { $env:ART_ROOT } else { "C:\AtomicRedTeam" }
$ARTModule = Join-Path $ARTRoot "invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
$ARTAtomics = Join-Path $ARTRoot "atomics"

function Setup-Sandbox {
    if (-not (Test-Path $SANDBOX)) {
        New-Item -ItemType Directory -Path $SANDBOX -Force | Out-Null
    }
    if (-not (Test-Path $ARTModule)) {
        throw "ไม่พบ ART module ที่ $ARTModule - ติดตั้ง ART หรือยัง? (provision/windows/install_art_win.ps1)"
    }
    Import-Module $ARTModule -Force
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
        throw "import $ARTModule แล้วแต่ยังไม่มี Invoke-AtomicTest - module เสียหาย"
    }
    $global:PSDefaultParameterValues = @{
        "Invoke-AtomicTest:PathToAtomicsFolder" = $ARTAtomics
    }
    Write-Host "  [setup] ART module พร้อม: $ARTModule"
}

# Atomic <TECHNIQUE> [TestNumbers]
# กันค้าง: job + timeout (PowerShell ไม่มี setsid แต่ job แยก runspace ได้)
# spawn จาก $SANDBOX เพื่อให้ lineage labeling จับได้ (seed)
function Atomic {
    param([string]$Technique, [string]$TestNumbers = "")
    Write-Host "  [atomic] $Technique $TestNumbers"
    $job = Start-Job -ScriptBlock {
        param($tech, $nums, $sandbox, $mod, $atomics)
        Set-Location $sandbox
        Import-Module $mod -Force
        $PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder" = $atomics}
        $p = @{}
        if ($nums) { $p["TestNumbers"] = $nums.Split(",") }
        Invoke-AtomicTest $tech @p -GetPrereqs -ErrorAction SilentlyContinue
        Invoke-AtomicTest $tech @p -ErrorAction SilentlyContinue
    } -ArgumentList $Technique, $TestNumbers, $SANDBOX, $ARTModule, $ARTAtomics

    if (Wait-Job $job -Timeout $AtomicTimeout) {
        Receive-Job $job | Select-Object -Last 5
    } else {
        Write-Host "  [!] atomic $Technique ค้างเกิน ${AtomicTimeout}s - ตัดทิ้ง"
        Stop-Job $job
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

# Atomic-Cleanup <TECHNIQUE> [TestNumbers] - ล้าง artifact (จำเป็นเพราะรันซ้ำโดยไม่ revert)
function Atomic-Cleanup {
    param([string]$Technique, [string]$TestNumbers = "")
    Write-Host "  [cleanup] $Technique $TestNumbers"
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
        Import-Module $ARTModule -Force
    }
    $p = @{}
    if ($TestNumbers) { $p["TestNumbers"] = $TestNumbers.Split(",") }
    Invoke-AtomicTest $Technique @p -Cleanup -ErrorAction SilentlyContinue
}

function Banner { param([string]$Name)
    Write-Host "============================================"
    Write-Host "  SCENARIO: $Name  (Windows)"
    Write-Host "  sandbox : $SANDBOX"
    Write-Host "  เริ่ม    : $((Get-Date).ToUniversalTime().ToString('o'))"
    Write-Host "============================================"
}
function Done-Banner { param([string]$Name)
    Write-Host "--------------------------------------------"
    Write-Host "  จบ scenario: $Name  ($((Get-Date).ToUniversalTime().ToString('o')))"
    Write-Host "--------------------------------------------"
}

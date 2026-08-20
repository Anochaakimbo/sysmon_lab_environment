# _lib.ps1 - ฟังก์ชันร่วมของทุก scenario ฝั่ง Windows
# ทุก scenario dot-source ไฟล์นี้:  . "$PSScriptRoot\_lib.ps1"
#
# เทียบเท่า scenarios/_lib.sh ฝั่ง Linux แต่เป็น PowerShell

$SANDBOX = "C:\lab_sandbox"
$AtomicTimeout = if ($env:ATOMIC_TIMEOUT) { [int]$env:ATOMIC_TIMEOUT } else { 240 }

function Setup-Sandbox {
    if (-not (Test-Path $SANDBOX)) {
        New-Item -ItemType Directory -Path $SANDBOX -Force | Out-Null
    }
    Import-Module Invoke-AtomicRedTeam -Force -ErrorAction SilentlyContinue
    $global:PSDefaultParameterValues = @{
        "Invoke-AtomicTest:PathToAtomicsFolder" = "C:\AtomicRedTeam\atomics"
    }
}

# Atomic <TECHNIQUE> [TestNumbers]
# กันค้าง: job + timeout (PowerShell ไม่มี setsid แต่ job แยก runspace ได้)
# spawn จาก $SANDBOX เพื่อให้ lineage labeling จับได้ (seed)
function Atomic {
    param([string]$Technique, [string]$TestNumbers = "")
    Write-Host "  [atomic] $Technique $TestNumbers"
    $job = Start-Job -ScriptBlock {
        param($tech, $nums, $sandbox)
        Set-Location $sandbox
        Import-Module Invoke-AtomicRedTeam -Force
        $PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder" = "C:\AtomicRedTeam\atomics"}
        $p = @{}
        if ($nums) { $p["TestNumbers"] = $nums.Split(",") }
        Invoke-AtomicTest $tech @p -GetPrereqs -ErrorAction SilentlyContinue
        Invoke-AtomicTest $tech @p -ErrorAction SilentlyContinue
    } -ArgumentList $Technique, $TestNumbers, $SANDBOX

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

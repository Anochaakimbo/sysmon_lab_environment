# install_art_win.ps1 - ติดตั้ง Invoke-AtomicRedTeam (Windows)
# Windows มี PowerShell อยู่แล้ว -> ติดตั้งง่ายกว่า Linux
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "[*] ตั้ง TLS 1.2 + execution policy..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Host "[*] ติดตั้ง Invoke-AtomicRedTeam + atomics..."
Install-Module -Name powershell-yaml -Scope AllUsers -Force
IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -InstallPath "C:\AtomicRedTeam" -Force

# sandbox ให้ scenario spawn จากที่เดียว (seed ของ lineage labeling - เหมือน /tmp/lab_sandbox ฝั่ง Linux)
$sandbox = "C:\lab_sandbox"
New-Item -ItemType Directory -Path $sandbox -Force | Out-Null

Write-Host "[+] Atomic Red Team (Windows) พร้อมใช้งาน"
Write-Host "    atomics: $((Get-ChildItem C:\AtomicRedTeam\atomics -Directory).Count) techniques"

# check_atomics.ps1 (v1) - list atomic tests that ACTUALLY support Windows
#
# เทียบเท่า scenarios/check_atomics.sh ฝั่ง Linux (v2)
# อ่าน supported_platforms จาก YAML โดยตรง ไม่ใช่ grep คำว่า "windows" ในชื่อ test
# (บทเรียนจากฝั่ง Linux: checker v1 grep ชื่อ test แล้วรายงานผิด)
#
# ไม่ต้องพึ่ง powershell-yaml module - parse เองตาม indentation ของ ART yaml
# ซึ่ง format สม่ำเสมอทั้ง repo
#
# เอาต์พุตเป็น ASCII ล้วน redirect ลงไฟล์แล้วไม่เพี้ยน
#
# วิธีใช้ (ใน Windows VM):
#   powershell -ExecutionPolicy Bypass -File .\check_atomics.ps1 > C:\atomic_report_win.txt
#   powershell -File .\check_atomics.ps1 -Technique T1486,T1490   # เช็คเฉพาะบางตัว
#   powershell -File .\check_atomics.ps1 -PasteOnly               # เอาแค่บรรทัดพร้อมวาง

[CmdletBinding()]
param(
    [string]   $AtomicsPath = $(if ($env:ATOMICS) { $env:ATOMICS } else { 'C:\AtomicRedTeam\atomics' }),
    [string[]] $Technique,
    [switch]   $PasteOnly
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $AtomicsPath)) {
    Write-Host "[!] atomics folder not found: $AtomicsPath"
    Write-Host '    ระบุด้วย -AtomicsPath หรือ $env:ATOMICS'
    exit 1
}

# ---------------------------------------------------------------------------
# technique ที่แต่ละ scenario ใช้ (ต้องตรงกับ scenarios_win/*.ps1)
# ---------------------------------------------------------------------------
$SCENARIOS = [ordered]@{
    'ransomware_win' = @('T1083','T1005','T1074.001','T1486','T1070.004','T1490')
    'miner_win'      = @('T1082','T1057','T1105','T1496','T1053.005')
    'botnet_win'     = @('T1016','T1049','T1018','T1071.001','T1132.001','T1105')
    'trojan_win'     = @('T1082','T1033','T1057','T1087.001','T1059.001','T1547.001',
                         'T1053.005','T1112','T1005','T1074.001','T1027','T1036.003')
    'exploit_win'    = @('T1069.001','T1012','T1497.001','T1552.001','T1548.002',
                         'T1134','T1055','T1218.011')
}

# technique ที่ห้ามรันทั้งก้อน (ดู CLAUDE.md ส่วน deny list)
$DENY_TECH = @{
    'T1490' = 'Inhibit System Recovery - ลบ shadow copy'
    'T1485' = 'Data Destruction'
    'T1561' = 'Disk Wipe'
    'T1529' = 'System Shutdown/Reboot - ตัด log กลางคัน'
    'T1491' = 'Defacement'
}

# ---------------------------------------------------------------------------
# keyword สแกนใน command ของแต่ละ test
#   DESTRUCTIVE = พังเครื่อง / พังนอก sandbox
#   LOGKILL     = ทำลาย telemetry ที่กำลังเก็บ (ร้ายกว่าสำหรับงานนี้)
#   REBOOT      = ตัด log กลางคัน
# ---------------------------------------------------------------------------
$RISK = @(
    @{ Tag = 'LOGKILL';     Pattern = 'wevtutil\s+cl|Clear-EventLog|Remove-EventLog' }
    @{ Tag = 'LOGKILL';     Pattern = 'Stop-Service[^\r\n]*[Ss]ysmon|sc\.exe\s+stop[^\r\n]*[Ss]ysmon|[Ss]ysmon[^\r\n]*\s-u\b' }
    @{ Tag = 'LOGKILL';     Pattern = 'fsutil\s+usn\s+deletejournal' }
    @{ Tag = 'DESTRUCTIVE'; Pattern = 'vssadmin[^\r\n]*delete\s+shadows|shadowcopy[^\r\n]*[Dd]elete|Win32_Shadowcopy[^\r\n]*[Dd]elete' }
    @{ Tag = 'DESTRUCTIVE'; Pattern = 'wbadmin\s+delete|bcdedit[^\r\n]*recoveryenabled|bcdedit[^\r\n]*bootstatuspolicy' }
    @{ Tag = 'DESTRUCTIVE'; Pattern = 'cipher\s+/w|format\s+[a-zA-Z]:|diskpart|Clear-Disk|Initialize-Disk' }
    @{ Tag = 'DESTRUCTIVE'; Pattern = 'del\s+/[fsq][^\r\n]*\bc:\\\*|Remove-Item[^\r\n]*[Cc]:\\\*|rd\s+/s\s+/q\s+c:\\' }
    @{ Tag = 'REBOOT';      Pattern = 'shutdown\s+/[rs]\b|Restart-Computer|Stop-Computer' }
)

# ---------------------------------------------------------------------------
# parser: อ่าน ART yaml ตาม indentation
#   ^- name:              = เริ่ม test ใหม่ (index +1)
#   ^  <key>:             = key ระดับ test
#   ^  - x / ^    - x     = สมาชิก list ของ key ก่อนหน้า
#   ^    <key>:           = key ย่อยของ executor
# ---------------------------------------------------------------------------
function Get-AtomicTests {
    param([string]$YamlPath)

    $tests   = @()
    $cur     = $null
    $section = ''
    $inTests = $false
    $idx     = 0

    foreach ($raw in (Get-Content -LiteralPath $YamlPath -Encoding UTF8)) {
        $line = $raw -replace "`t", '    '

        if (-not $inTests) {
            if ($line -match '^atomic_tests:\s*$') { $inTests = $true }
            continue
        }

        # ---- test ใหม่ ----
        if ($line -match '^-\s+name:\s*(.*)$') {
            if ($cur) { $tests += $cur }
            $idx++
            $cur = [pscustomobject]@{
                Index     = $idx
                Name      = $matches[1].Trim().Trim('"').Trim("'")
                Platforms = New-Object System.Collections.ArrayList
                Executor  = '?'
                Elevation = $false
                HasDeps   = $false
                Raw       = New-Object System.Text.StringBuilder
            }
            $section = ''
            continue
        }
        if (-not $cur) { continue }

        [void]$cur.Raw.AppendLine($line)

        # ---- สมาชิก list (ต้องเช็คก่อน key ไม่งั้น "  - windows" หลุด) ----
        if ($line -match '^\s{2,4}-\s+(\S+)\s*$') {
            if ($section -eq 'platforms') { [void]$cur.Platforms.Add($matches[1].ToLower()) }
            continue
        }

        # ---- key ระดับ test (2 space) ----
        if ($line -match '^  ([a-z_]+):\s*(.*)$') {
            switch ($matches[1]) {
                'supported_platforms' { $section = 'platforms' }
                'executor'            { $section = 'executor' }
                'dependencies'        { $section = 'deps'; $cur.HasDeps = $true }
                default               { $section = '' }
            }
            continue
        }

        # ---- key ย่อยของ executor (4 space) ----
        if ($section -eq 'executor' -and $line -match '^    ([a-z_]+):\s*(.*)$') {
            $k = $matches[1]
            $v = $matches[2].Trim()
            if ($k -eq 'name' -and $v) { $cur.Executor = $v }
            if ($k -eq 'elevation_required') { $cur.Elevation = ($v -match '^(true|yes)$') }
            continue
        }
    }
    if ($cur) { $tests += $cur }
    return $tests
}

function Get-RiskTags {
    param([string]$Text)
    $tags = @()
    foreach ($r in $RISK) {
        if ($Text -match $r.Pattern) { $tags += $r.Tag }
    }
    return @($tags | Select-Object -Unique)
}

# ---------------------------------------------------------------------------
# รวบรวม technique ที่จะตรวจ
# ---------------------------------------------------------------------------
if ($Technique) {
    $wanted = $Technique
} else {
    $wanted = @()
    foreach ($k in $SCENARIOS.Keys) { $wanted += $SCENARIOS[$k] }
    $wanted = @($wanted | Select-Object -Unique | Sort-Object)
}

$result = @{}

foreach ($tech in $wanted) {
    $yaml = Join-Path $AtomicsPath "$tech\$tech.yaml"
    if (-not (Test-Path $yaml)) {
        $result[$tech] = @{ Missing = $true; Tests = @(); Safe = @(); Error = $null }
        continue
    }
    try {
        $all = Get-AtomicTests $yaml
    } catch {
        $result[$tech] = @{ Missing = $true; Tests = @(); Safe = @(); Error = $_.Exception.Message }
        continue
    }

    $win = @()
    foreach ($t in $all) {
        if ($t.Platforms -notcontains 'windows') { continue }
        $tags = @(Get-RiskTags $t.Raw.ToString())
        if ($DENY_TECH.ContainsKey($tech)) { $tags += 'DENY-TECH' }
        $win += [pscustomobject]@{
            Index     = $t.Index
            Name      = $t.Name
            Executor  = $t.Executor
            Elevation = $t.Elevation
            HasDeps   = $t.HasDeps
            Tags      = @($tags | Select-Object -Unique)
        }
    }

    # test ที่รันอัตโนมัติได้จริง: ไม่ใช่ manual + ไม่ติด risk tag
    $safe = @($win | Where-Object { $_.Executor -ne 'manual' -and $_.Tags.Count -eq 0 })

    $result[$tech] = @{ Missing = $false; Tests = $win; Safe = $safe; Error = $null }
}

# ---------------------------------------------------------------------------
# รายงานละเอียด
# ---------------------------------------------------------------------------
if (-not $PasteOnly) {
    Write-Host ('=' * 78)
    Write-Host '  ATOMIC TESTS WITH WINDOWS SUPPORT'
    Write-Host "  atomics : $AtomicsPath"
    Write-Host '  legend  : [admin]=elevation_required  [prereq]=has dependencies'
    Write-Host '            *** DENY-TECH / DESTRUCTIVE / LOGKILL / REBOOT = DO NOT RUN ***'
    Write-Host ('=' * 78)

    foreach ($tech in $wanted) {
        $r = $result[$tech]
        if ($r.Missing) {
            $err = if ($r.Error) { " ($($r.Error))" } else { '' }
            Write-Host ''
            Write-Host "[$tech]  -- no yaml found --$err"
            continue
        }
        $note = if ($DENY_TECH.ContainsKey($tech)) { "   << DENY LIST: $($DENY_TECH[$tech]) >>" } else { '' }
        Write-Host ''
        Write-Host "[$tech]  $($r.Tests.Count) windows test(s)$note"
        if ($r.Tests.Count -eq 0) {
            Write-Host '    -- NO windows test --'
            continue
        }
        foreach ($t in $r.Tests) {
            $flags = ''
            if ($t.Elevation) { $flags += ' [admin]' }
            if ($t.HasDeps)   { $flags += ' [prereq]' }
            $risk = if ($t.Tags.Count) { '  *** ' + ($t.Tags -join ',') + ' ***' } else { '' }
            $nm = $t.Name
            if ($nm.Length -gt 52) { $nm = $nm.Substring(0, 52) }
            Write-Host ('    {0,3}. {1,-52} ({2}){3}{4}' -f $t.Index, $nm, $t.Executor, $flags, $risk)
        }
    }
}

# ---------------------------------------------------------------------------
# บรรทัดพร้อมวางลง scenarios_win/*.ps1 แยกตามไฟล์
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 78)
Write-Host '  PASTE THESE INTO scenarios_win/*.ps1'
Write-Host '  (manual executor + risky test ถูกตัดออกแล้ว)'
Write-Host ('=' * 78)

foreach ($scn in $SCENARIOS.Keys) {
    Write-Host ''
    Write-Host "---- $scn.ps1 ----"
    foreach ($tech in $SCENARIOS[$scn]) {
        $r = $result[$tech]
        if (-not $r -or $r.Missing) {
            Write-Host "    # Atomic `"$tech`"   <- no yaml, ลบบรรทัดนี้"
            continue
        }
        if ($DENY_TECH.ContainsKey($tech)) {
            Write-Host "    # Atomic `"$tech`"   <- DENY LIST ($($DENY_TECH[$tech])) ห้ามเปิด"
            continue
        }
        $nums = @($r.Safe | ForEach-Object { $_.Index })
        if ($nums.Count -eq 0) {
            Write-Host "    # Atomic `"$tech`"   <- ไม่มี windows test ที่รันได้ ลบบรรทัดนี้"
        } else {
            Write-Host ('    Atomic "{0}" "{1}"' -f $tech, ($nums -join ','))
        }
    }
}

# ---------------------------------------------------------------------------
# สรุปตัวที่ถูกตัดออก พร้อมเหตุผล (ห้ามเงียบ)
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 78)
Write-Host '  EXCLUDED TESTS AND WHY'
Write-Host ('=' * 78)
$anyExcluded = $false
foreach ($tech in $wanted) {
    $r = $result[$tech]
    if ($r.Missing) { continue }
    $bad = @($r.Tests | Where-Object { $_.Executor -eq 'manual' -or $_.Tags.Count -gt 0 })
    if ($bad.Count -eq 0) { continue }
    $anyExcluded = $true
    Write-Host ''
    Write-Host "[$tech]"
    foreach ($t in $bad) {
        $why = if ($t.Tags.Count) { ($t.Tags -join ',') } else { 'manual executor (รันเองไม่ได้)' }
        $nm = $t.Name
        if ($nm.Length -gt 46) { $nm = $nm.Substring(0, 46) }
        Write-Host ('    {0,3}. {1,-46}  -> {2}' -f $t.Index, $nm, $why)
    }
}
if (-not $anyExcluded) { Write-Host ''; Write-Host '  (none)' }

Write-Host ''
Write-Host ('=' * 78)
Write-Host '  SUMMARY'
Write-Host ('=' * 78)
foreach ($tech in $wanted) {
    $r = $result[$tech]
    if ($r.Missing) { Write-Host ('  {0,-12} no yaml' -f $tech); continue }
    Write-Host ('  {0,-12} windows={1,-3} runnable={2}' -f $tech, $r.Tests.Count, $r.Safe.Count)
}

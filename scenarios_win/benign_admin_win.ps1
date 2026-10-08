# benign_admin_win.ps1 - งานผู้ดูแลระบบปกติ (Windows)  label = 0
#
# ทำไมต้องมี: benign.ps1 เดิมวนคำสั่งสั้นชุดเดียว (whoami/hostname/ipconfig/tasklist)
# replay 8 ต.ค. 2026: กัน benign run ออกจาก train -> RF flag benign 71%
# แอดมินจริงใช้คำสั่งชุดเดียวกับ ART ทุกวัน -> ต้องมีใน benign
#
# ทุกคำสั่ง spawn เป็น process ลูก (cmd / powershell -Command / exe) เหมือนที่ ART ทำ
# ไม่งั้นจะไม่มี ProcessCreate ให้เทียบ
# เขียนเฉพาะ C:\lab_sandbox\benign_admin, HKCU\Software\LabBenign, task "LabBenign_Backup"
# และลบทิ้งทั้งหมดใน finally
. "$PSScriptRoot\_lib.ps1"

Banner "benign_admin"
Setup-Sandbox

$work = "C:\lab_sandbox\benign_admin"
$rep  = Join-Path $work "reports"
New-Item -ItemType Directory -Path $rep -Force | Out-Null
$task = "LabBenign_Backup"
$regk = "HKCU\Software\LabBenign"

function Run([string]$exe, [string]$argv, [string]$out) {
    # รันเป็น process ลูกแล้วต่อท้ายผลลงรายงาน
    cmd /c "$exe $argv >> `"$out`" 2>&1" | Out-Null
}
function PSRun([string]$cmd) {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd | Out-Null
}

try {
    for ($round = 1; $round -le 4; $round++) {
        Write-Host "[benign_admin] รอบ $round"
        $r = Join-Path $rep "health_$round.txt"

        # ---- ตรวจสุขภาพเครื่อง (T1082/T1057/T1033 ใช้คำสั่งเดียวกัน) ----
        Run "systeminfo" "" $r
        Run "hostname" "" $r
        Run "whoami" "/all" $r
        Run "tasklist" "/v /fo csv" $r
        Run "wmic" "os get Caption,Version,LastBootUpTime /format:list" $r
        Run "wmic" "logicaldisk get DeviceID,FreeSpace,Size" $r
        Run "driverquery" "/fo csv" $r
        PSRun "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,WS | Format-Table -AutoSize | Out-File -Append '$r'"

        # ---- บัญชีผู้ใช้ (T1087.001 ใช้คำสั่งเดียวกัน) ----
        Run "net" "user" $r
        Run "net" "localgroup administrators" $r
        PSRun "Get-LocalUser | Select-Object Name,Enabled,LastLogon | Out-File -Append '$r'"

        # ---- เครือข่าย (T1016/T1049) ----
        Run "ipconfig" "/all" $r
        Run "netstat" "-ano" $r
        Run "arp" "-a" $r
        Run "route" "print" $r
        Run "nslookup" "localhost" $r
        PSRun "Test-NetConnection -ComputerName 192.168.56.1 -Port 8080 -WarningAction SilentlyContinue | Out-File -Append '$r'"
        PSRun "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 http://192.168.56.1:8080/ | Out-Null } catch {}"

        # ---- service / registry / task / log (อ่านอย่างเดียว) ----
        Run "sc" "query type= service state= running" $r
        Run "reg" "query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" $r
        Run "reg" "query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" $r
        Run "schtasks" "/query /fo LIST" $r
        Run "wevtutil" "qe System /c:10 /rd:true /f:text" $r
        PSRun "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 20 Name,StartType | Out-File -Append '$r'"
        PSRun "Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object -First 20 TaskName,TaskPath | Out-File -Append '$r'"

        # ---- งานแอดมินที่เขียนจริง (persistence-like แต่ benign) ----
        # scheduled task สำรองข้อมูล: สร้าง -> query -> ลบ (T1053.005 ใช้ schtasks เหมือนกัน)
        Run "schtasks" "/create /tn $task /tr `"cmd /c echo backup`" /sc daily /st 02:30 /f" $r
        Run "schtasks" "/query /tn $task /v /fo LIST" $r
        Run "schtasks" "/delete /tn $task /f" $r
        # ค่าตั้งค่าของเครื่องมือภายใน (T1112 ใช้ reg add เหมือนกัน)
        Run "reg" "add $regk /v LastHealthCheck /t REG_SZ /d `"round $round`" /f" $r
        Run "reg" "add $regk /v ReportDir /t REG_SZ /d `"$rep`" /f" $r
        Run "reg" "query $regk" $r

        # ---- แพ็กรายงาน + ล้างของเก่า (T1074.001 / T1070.004 ใช้คำสั่งเดียวกัน) ----
        PSRun "Compress-Archive -Path '$rep\*' -DestinationPath '$work\reports_$round.zip' -Force"
        Run "certutil" "-hashfile `"$work\reports_$round.zip`" SHA256" $r
        Run "robocopy" "`"$rep`" `"$work\backup_$round`" /E /NJH /NJS /NP" $r
        cmd /c "del /q `"$work\backup_$round\*.txt`" & rmdir /s /q `"$work\backup_$round`"" | Out-Null

        # คำสั่งยาวแบบสคริปต์แอดมิน (ไม่ให้ "คำสั่งยาว = ART" เป็นทางลัด)
        PSRun "Get-ChildItem -Path C:\Windows\Temp,`$env:TEMP -File -ErrorAction SilentlyContinue | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Measure-Object -Property Length -Sum | Select-Object Count,Sum | Out-File -Append '$r'"
        PSRun "Get-CimInstance Win32_LogicalDisk | ForEach-Object { '{0} {1:N1}GB free of {2:N1}GB' -f `$_.DeviceID, (`$_.FreeSpace/1GB), (`$_.Size/1GB) } | Out-File -Append '$r'"

        Start-Sleep -Seconds 5
    }
}
finally {
    cmd /c "schtasks /delete /tn $task /f >nul 2>&1" | Out-Null
    cmd /c "reg delete $regk /f >nul 2>&1" | Out-Null
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

Done-Banner "benign_admin"

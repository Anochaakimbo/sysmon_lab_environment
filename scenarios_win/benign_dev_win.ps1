# benign_dev_win.ps1 - งานนักพัฒนาปกติ (Windows)  label = 0
#
# เขียนโค้ด / compile C# ด้วย csc ของ .NET Framework / encode-decode ไฟล์ / zip
# โหลดไฟล์จากเซิร์ฟเวอร์ในแล็บ หลายคำสั่งหน้าตาเหมือน ART (certutil -decode,
# powershell -Command ยาวๆ, Invoke-WebRequest) แต่เป็นงานปกติ
# ทำทั้งหมดใน C:\lab_sandbox\benign_dev และไม่ออกเน็ตนอกแล็บ
. "$PSScriptRoot\_lib.ps1"

Banner "benign_dev"
Setup-Sandbox

$work = "C:\lab_sandbox\benign_dev\project"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$git = Get-Command git.exe -ErrorAction SilentlyContinue
$py  = Get-Command python.exe -ErrorAction SilentlyContinue |
       Where-Object { $_.Source -notmatch 'WindowsApps' }   # ข้าม stub ของ Store

function PSRun([string]$cmd) {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd | Out-Null
}

try {
    Push-Location $work
    if ($git) { & git init -q . 2>$null | Out-Null }

    for ($round = 1; $round -le 4; $round++) {
        Write-Host "[benign_dev] รอบ $round"

        # ---- เขียนโค้ด + config ----
@"
using System;
using System.Linq;
class App {
    static void Main() {
        var items = Enumerable.Range(0, 50).Select(i => i * $round).ToArray();
        Console.WriteLine("round $round sum=" + items.Sum());
    }
}
"@ | Out-File -Encoding ascii "App.cs"
        "name=demo`r`nversion=0.$round`r`nport=8080" | Out-File -Encoding ascii "app.config.txt"
        "@echo off`r`n`"$csc`" /nologo /out:App.exe App.cs`r`nApp.exe > out.txt" | Out-File -Encoding ascii "build.cmd"

        # ---- build / run ----
        if (Test-Path $csc) {
            cmd /c "build.cmd > build.log 2>&1" | Out-Null
        }
        if ($py) {
            & $py.Source -c "import json,hashlib; d={'round':$round}; print(hashlib.sha256(json.dumps(d).encode()).hexdigest())" | Out-Null
        }
        PSRun "Get-ChildItem -Path '$work' -Recurse -Include *.cs,*.cmd,*.txt | Select-String -Pattern 'TODO|FIXME|round' | Measure-Object | Out-Null"

        # ---- encode / decode + checksum (certutil เป็น LOLBin ที่ ART ใช้ แต่ dev ก็ใช้) ----
        cmd /c "certutil -f -encode app.config.txt app.config.b64 >nul" | Out-Null
        cmd /c "certutil -f -decode app.config.b64 app.config.check >nul" | Out-Null
        cmd /c "fc /b app.config.txt app.config.check >nul && del app.config.check" | Out-Null
        cmd /c "certutil -hashfile App.cs SHA256 > SHA256SUMS.txt" | Out-Null
        PSRun "[Convert]::ToBase64String([IO.File]::ReadAllBytes('$work\App.cs')) | Set-Content '$work\App.cs.b64'"

        # ---- ค้นโค้ด / เครื่องมือ ----
        cmd /c "findstr /s /i /n `"Console`" *.cs > nul" | Out-Null
        cmd /c "dir /s /b *.cs *.cmd > filelist.txt" | Out-Null
        cmd /c "where powershell cmd csc 2>nul" | Out-Null
        cmd /c "set | findstr /i `"^PATH= ^USERPROFILE=`"" | Out-Null

        # ---- โหลด artifact จากเซิร์ฟเวอร์ในแล็บ (T1105 ใช้คำสั่งเดียวกัน) ----
        PSRun "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri http://192.168.56.1:8080/ -OutFile '$work\artifact_$round.html' } catch {}"
        cmd /c "curl.exe -s -m 5 -o artifact_$round.curl http://192.168.56.1:8080/" | Out-Null

        # ---- version control ----
        if ($git) {
            & git add -A 2>$null | Out-Null
            & git -c user.name=dev -c user.email=dev@lab.local commit -qm "round ${round}: update build" 2>$null | Out-Null
            & git log --oneline -n 3 2>$null | Out-Null
        }

        # ---- แพ็กส่ง + ล้าง build เก่า ----
        PSRun "Compress-Archive -Path '$work\*.cs','$work\*.txt','$work\*.cmd' -DestinationPath '$work\..\release_$round.zip' -Force"
        PSRun "Expand-Archive -Path '$work\..\release_$round.zip' -DestinationPath '$work\..\verify_$round' -Force; Remove-Item '$work\..\verify_$round' -Recurse -Force"
        cmd /c "del /q App.exe out.txt build.log artifact_* 2>nul" | Out-Null

        # คำสั่งยาวแบบ one-liner ของนักพัฒนา
        PSRun "Get-ChildItem '$work' -File | ForEach-Object { '{0,-24} {1,8} {2}' -f `$_.Name, `$_.Length, (Get-FileHash `$_.FullName -Algorithm SHA1).Hash.Substring(0,12) } | Sort-Object | Out-Null"

        Start-Sleep -Seconds 5
    }
}
finally {
    Pop-Location
    Remove-Item "C:\lab_sandbox\benign_dev" -Recurse -Force -ErrorAction SilentlyContinue
}

Done-Banner "benign_dev"

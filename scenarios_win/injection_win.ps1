# injection_win.ps1 - process injection / code injection (Windows)
#
# ทำไมต้องมี scenario นี้:
#   CLAUDE.md ระบุว่า CreateRemoteThread (EventID 8) เป็น "ช่องว่างจริงของเรา"
#   เปเปอร์อ้างอิงมี 4,441 แถว (6.3%) เรามีแค่ 4 แถว
#   เพราะ ART test ที่ทำ process injection สำเร็จมีกระจายอยู่หลาย technique
#   -> รวมมันไว้ scenario เดียวเพื่อดัน event 8 โดยเฉพาะ
#
# ATT&CK:
#   T1055      Process Injection            (Section View / Go RemoteThread / CreateThread)
#   T1055.001  DLL Injection
#   T1055.002  Portable Executable Injection
#   T1055.012  Process Hollowing
#   T1620      Reflective Code Loading
#   T1106      Native API
#   T1057      Process Discovery            (หา process เป้าหมายก่อน inject)
#
# ⚠️ scenario นี้ทำ process injection จริงในหน่วยความจำ - ต้อง revert snapshot
#    ทุกรอบ (orchestrator ทำให้แล้ว) และต้องปิด Defender (Setup-Sandbox เช็คให้)
#
# ⚠️ เลข atomic test ทุกบรรทัดมาจาก atomic_report_win.txt ที่รันบน wintarget จริง
#    ตัวที่มี [prereq] (โหลดเครื่องมือจากเน็ต) ถูกคัดออกแล้ว
#    ยังไม่ยืนยันเลขของ T1055.001/.002/.012/T1620/T1106 บน VM -> ถูกคอมเมนต์ไว้
#    ให้ปลดคอมเมนต์หลังรัน check_atomics.ps1 -Technique T1055.001,... บน wintarget
. "$PSScriptRoot\_lib.ps1"
Banner "injection_win"
Setup-Sandbox

# ---------- Stage 1: หา process เป้าหมาย ----------
Write-Host "[inject] process discovery"
Atomic "T1057" "2,3,4,5,6"          # Process Discovery (tasklist/Get-Process/wmi)

# เปิด process เป้าหมายที่ inject ได้ (notepad = คลาสสิก) ให้ค้างไว้
# spawn จาก sandbox เพื่อให้ lineage จับ - kill ตอน cleanup
Write-Host "[inject] เปิด target process"
$targets = @()
for ($i = 0; $i -lt 2; $i++) {
    try {
        $p = Start-Process notepad -PassThru -WindowStyle Minimized -ErrorAction Stop
        $targets += $p
    } catch { }
}
Start-Sleep -Seconds 2

# ---------- Stage 2: process injection (ตัวหลัก - ดัน EventID 8) ----------
# เลขจาก atomic_report_win.txt (T1055 runnable=13):
#   3  Section View Injection
#   4  Dirty Vanity process Injection
#   6  Go UuidFromStringA
#   7  Go EtwpCreateEtwThread
#   8  Go RtlCreateUserThread    <- remote thread
#   9  Go CreateRemoteThread     <- remote thread (ตรงชื่อ EventID 8)
#   10 Go CreateRemoteThread     <- remote thread
#   11 Go CreateThread
#   12 Go CreateThread
# ตัด 1,2,5,13 = [prereq] (VBA shellcode / mimikatz / UUID custom)
Write-Host "[inject] process injection (เน้น remote thread -> EventID 8)"
Atomic "T1055" "3,4,6,7,8,9,10,11,12"

# ---------- Stage 3: subtechnique เพิ่มเติม ----------
# ⚠️ ยังไม่ยืนยันเลขบน VM - ปลดคอมเมนต์หลัง check_atomics.ps1 -Technique T1055.001
# Write-Host "[inject] DLL / PE injection / hollowing"
# Atomic "T1055.001" "<เลขจาก checker>"    # DLL Injection
# Atomic "T1055.002" "<เลขจาก checker>"    # PE Injection
# Atomic "T1055.012" "<เลขจาก checker>"    # Process Hollowing
# Atomic "T1620"     "<เลขจาก checker>"    # Reflective Code Loading
# Atomic "T1106"     "<เลขจาก checker>"    # Native API

# ---------- Cleanup ----------
Write-Host "[inject] cleanup"
Atomic-Cleanup "T1055" "3,4,6,7,8,9,10,11,12"

# ปิด target process ที่เปิดค้างไว้ (ทั้งที่ inject สำเร็จและไม่สำเร็จ)
Write-Host "[inject] ปิด target process"
foreach ($p in $targets) {
    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { }
}
Get-Process notepad -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

Done-Banner "injection_win"

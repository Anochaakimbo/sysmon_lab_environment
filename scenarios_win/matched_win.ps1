# matched_win.ps1 - ชุด technique เดียวกับ scenarios/matched.sh (Atomic Red Team ล้วน)
#
# ทำไมมี: ทดสอบว่าโมเดลที่เทรนจาก OS หนึ่งใช้กับอีก OS ได้ไหม (host/cross_platform_eval.py)
# ใช้ technique + ลำดับเดียวกับฝั่ง Linux ไม่มี payload ที่เขียนเอง
#
# ATT&CK (เลข test ยืนยันบน wintarget แล้ว 23 ส.ค. 2026 - ดูตารางใน CLAUDE.md):
#   discovery   T1082 1,7,9  T1057 2,3  T1033 1,4  T1016 1,2  T1049 1,2  T1083 1,2
#   collection  T1005 1  T1074.001 1,3
#   persistence T1053.005 2,4
#   evasion     T1027 2,3
#   credential  T1552.001 4,5
#   C2          T1105 7,9,10  T1071.001 1  T1132.001 3
#   impact      T1486 5,10  T1496 2
#   cleanup     T1070.004 4,5
# ⚠️ ห้ามเว้นเลข test - Atomic() ที่ไม่ระบุเลขจะรันทุก test ของ technique นั้น
. "$PSScriptRoot\_lib.ps1"
Banner "matched_win"
Setup-Sandbox

# --- discovery ---
Atomic "T1082" "1,7,9"
Atomic "T1057" "2,3"
Atomic "T1033" "1,4"
Atomic "T1016" "1,2"
Atomic "T1049" "1,2"
Atomic "T1083" "1,2"

# --- collection ---
Atomic "T1005" "1"
Atomic "T1074.001" "1,3"

# --- persistence ---
Atomic "T1053.005" "2,4"

# --- defense evasion ---
Atomic "T1027" "2,3"

# --- credential access ---
Atomic "T1552.001" "4,5"

# --- command and control / ingress ---
Atomic "T1105" "7,9,10"
Atomic "T1071.001" "1"
Atomic "T1132.001" "3"

# --- impact ---
Atomic "T1486" "5,10"
Atomic "T1496" "2"

# --- indicator removal ---
Atomic "T1070.004" "4,5"

# --- cleanup: orchestrator วนซ้ำโดยไม่ revert ระหว่างรอบ ---
Write-Host "[matched] cleanup"
Atomic-Cleanup "T1053.005" "2,4"
Atomic-Cleanup "T1005" "1"
Atomic-Cleanup "T1074.001" "1,3"
Atomic-Cleanup "T1027" "2,3"
Atomic-Cleanup "T1552.001" "4,5"
Atomic-Cleanup "T1105" "7,9,10"
Atomic-Cleanup "T1071.001" "1"
Atomic-Cleanup "T1486" "5,10"
Atomic-Cleanup "T1496" "2"

Done-Banner "matched_win"

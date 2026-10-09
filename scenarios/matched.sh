#!/usr/bin/env bash
# matched.sh - ชุด technique เดียวกับ scenarios_win/matched_win.ps1 (Atomic Red Team ล้วน)
#
# ทำไมมี: ทดสอบว่าโมเดลที่เทรนจาก OS หนึ่งใช้กับอีก OS ได้ไหม (host/cross_platform_eval.py)
# scenario เดิมของ Linux ปนสคริปต์ที่เขียนเอง ส่วน Windows เป็น ART ล้วน -> ผลข้าม OS
# แยกไม่ออกว่าต่างเพราะ OS หรือเพราะการโจมตีต่างกัน ชุดนี้ใช้ technique + ลำดับเดียวกันทั้งสองฝั่ง
# ไม่มี payload ที่เขียนเอง
#
# ATT&CK (เลข test ยืนยันบน target1 แล้ว - ดูตารางใน CLAUDE.md):
#   discovery   T1082 3,4,5  T1057 1  T1033 2  T1016 3  T1049 4,5  T1083 3,4
#   collection  T1005 2  T1074.001 2
#   persistence T1053.003 1,2
#   evasion     T1027 1
#   credential  T1552.001 1,3
#   C2          T1105 1,2,3  T1071.001 3  T1132.001 1,2
#   impact      T1486 1,2  T1496 1
#   cleanup     T1070.004 1,2,3   (⚠️ ห้าม test 8 = ล้างเครื่อง)
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
banner "matched"
setup_sandbox

# --- discovery ---
atomic T1082 3,4,5
atomic T1057 1
atomic T1033 2
atomic T1016 3
atomic T1049 4,5
atomic T1083 3,4

# --- collection ---
atomic T1005 2
atomic T1074.001 2

# --- persistence ---
atomic T1053.003 1,2

# --- defense evasion ---
atomic T1027 1

# --- credential access ---
atomic T1552.001 1,3

# --- command and control / ingress ---
atomic T1105 1,2,3
atomic T1071.001 3
atomic T1132.001 1,2

# --- impact ---
atomic T1486 1,2
atomic T1496 1

# --- indicator removal ---
atomic T1070.004 1,2,3

# --- cleanup: orchestrator วนซ้ำโดยไม่ revert ระหว่างรอบ ---
atomic_cleanup T1053.003 1,2
atomic_cleanup T1005 2
atomic_cleanup T1074.001 2
atomic_cleanup T1027 1
atomic_cleanup T1552.001 1,3
atomic_cleanup T1105 1,2,3
atomic_cleanup T1486 1,2
atomic_cleanup T1496 1

done_banner "matched"
